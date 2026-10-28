//! Screens and interaction: first-run setup, the lock screen, and the vault.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use arboard::SetExtWindows;
use eframe::egui::{self, Align, Color32, Frame, Key, Layout, Margin, Pos2, Rect, RichText, Sense, Stroke, Vec2};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KdfParams, SALT_LEN, SecretKey};
use crate::generator::{self, GenOptions};
use crate::theme::{self, BRASS, DANGER, MUTED, OK, RULE, TEXT};
use crate::vault::{Entry, Field, UnlockedVault, VaultFile, unix_now};
use crate::{CLIPBOARD_CLEAR_SECONDS, IDLE_CLOSE_SECONDS, MIN_MASTER_PASSWORD_LEN, hello, window};

const MASK: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

// ---------------------------------------------------------------------------
// Background work
// ---------------------------------------------------------------------------

/// Results of slow work (Argon2, Windows Hello prompts) done off the UI thread.
enum Job {
    HelloSupport(bool),
    Opened { result: Result<UnlockedVault, String>, is_new: bool },
    HelloEnabled { name: String, challenge: Vec<u8>, result: Result<Zeroizing<Vec<u8>>, String> },
    PasswordKeys(Result<(SecretKey, Vec<u8>, SecretKey), String>),
}

#[derive(Clone, Copy, PartialEq)]
enum Busy {
    Opening,
    HelloSetup,
    PasswordChange,
}

struct Toast {
    text: String,
    color: Color32,
    until: Instant,
}

/// Copies secrets to the clipboard (kept out of Windows clipboard history and
/// cloud sync) and clears them again after a delay, if they are still there.
#[derive(Default)]
struct ClipboardGuard {
    pending: Option<([u8; 32], Instant)>,
}

fn digest(text: &str) -> [u8; 32] {
    let d = Sha256::digest(text.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

impl ClipboardGuard {
    fn copy(&mut self, text: &str) -> Result<(), String> {
        let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
        cb.set().exclude_from_history().exclude_from_cloud().text(text.to_owned()).map_err(|e| e.to_string())?;
        self.pending = Some((digest(text), Instant::now()));
        Ok(())
    }

    fn tick(&mut self) {
        if let Some((_, at)) = self.pending
            && at.elapsed() >= Duration::from_secs(CLIPBOARD_CLEAR_SECONDS)
        {
            self.clear_if_ours();
        }
    }

    fn clear_if_ours(&mut self) {
        let Some((hash, _)) = self.pending.take() else { return };
        if let Ok(mut cb) = arboard::Clipboard::new()
            && let Ok(mut current) = cb.get_text()
        {
            if digest(&current) == hash {
                let _ = cb.clear();
            }
            current.zeroize();
        }
    }
}

/// Everything except the current screen, so screens can borrow it freely.
struct Shared {
    path: PathBuf,
    tx: Sender<Job>,
    busy: Option<Busy>,
    busy_since: Instant,
    hello_supported: Option<bool>,
    clipboard: ClipboardGuard,
    toast: Option<Toast>,
}

impl Shared {
    fn toast(&mut self, text: impl Into<String>, color: Color32) {
        self.toast = Some(Toast { text: text.into(), color, until: Instant::now() + Duration::from_secs(5) });
    }

    fn start(&mut self, ctx: &egui::Context, busy: Busy, work: impl FnOnce() -> Job + Send + 'static) {
        self.busy = Some(busy);
        self.busy_since = Instant::now();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let _ = tx.send(work());
            ctx.request_repaint();
        });
    }

    fn copy(&mut self, what: &str, value: &str) {
        match self.clipboard.copy(value) {
            Ok(()) => self.toast(format!("{what} copied. The clipboard clears in {CLIPBOARD_CLEAR_SECONDS} seconds."), OK),
            Err(e) => self.toast(format!("Could not copy: {e}"), DANGER),
        }
    }
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SetupScreen {
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
    error: Option<String>,
}

#[derive(Default)]
struct LockScreen {
    password: Zeroizing<String>,
    error: Option<String>,
    has_hello: bool,
    focused: bool,
}

enum Dialog {
    None,
    Delete(String),
    Generator { field: usize, opts: GenOptions, preview: Zeroizing<String> },
    Settings,
}

struct Draft {
    entry: Entry,
    is_new: bool,
    revealed: HashSet<usize>,
    error: Option<String>,
}

#[derive(Default)]
struct SettingsForm {
    current: Zeroizing<String>,
    new: Zeroizing<String>,
    confirm: Zeroizing<String>,
    message: Option<(String, bool)>,
}

struct Session {
    vault: UnlockedVault,
    selected: Option<String>,
    search: String,
    revealed: HashSet<usize>,
    draft: Option<Draft>,
    dialog: Dialog,
    offer_hello: bool,
    settings: SettingsForm,
}

enum Screen {
    Setup(SetupScreen),
    Locked(LockScreen),
    Unlocked(Box<Session>),
}

enum Next {
    Stay,
    Lock,
}

pub struct App {
    screen: Screen,
    s: Shared,
    rx: Receiver<Job>,
    last_activity: Instant,
    title_bar_done: bool,
}

impl App {
    pub fn new(ctx: &egui::Context, path: PathBuf) -> App {
        let (tx, rx) = channel();
        let mut s = Shared {
            path,
            tx,
            busy: None,
            busy_since: Instant::now(),
            hello_supported: None,
            clipboard: ClipboardGuard::default(),
            toast: None,
        };
        let screen = Self::start_screen(&s.path);
        {
            let tx = s.tx.clone();
            let ctx = ctx.clone();
            thread::spawn(move || {
                let _ = tx.send(Job::HelloSupport(hello::is_available()));
                ctx.request_repaint();
            });
        }
        s.toast = None;
        App { screen, s, rx, last_activity: Instant::now(), title_bar_done: false }
    }

    fn start_screen(path: &std::path::Path) -> Screen {
        if !path.exists() {
            return Screen::Setup(SetupScreen::default());
        }
        let mut lock = LockScreen::default();
        match VaultFile::load(path) {
            Ok(file) => lock.has_hello = file.hello_slot.is_some(),
            Err(e) => lock.error = Some(e.to_string()),
        }
        Screen::Locked(lock)
    }

    fn poll_jobs(&mut self) {
        while let Ok(job) = self.rx.try_recv() {
            match job {
                Job::HelloSupport(ok) => self.s.hello_supported = Some(ok),
                Job::Opened { result, is_new } => {
                    self.s.busy = None;
                    match result {
                        Ok(vault) => {
                            let offer_hello = is_new && self.s.hello_supported == Some(true);
                            self.screen = Screen::Unlocked(Box::new(Session {
                                vault,
                                selected: None,
                                search: String::new(),
                                revealed: HashSet::new(),
                                draft: None,
                                dialog: Dialog::None,
                                offer_hello,
                                settings: SettingsForm::default(),
                            }));
                            if is_new {
                                self.s.toast("Your vault is ready.", OK);
                            }
                        }
                        Err(e) => match &mut self.screen {
                            Screen::Locked(l) => {
                                l.error = Some(e);
                                l.focused = false;
                            }
                            Screen::Setup(st) => st.error = Some(e),
                            Screen::Unlocked(_) => {}
                        },
                    }
                }
                Job::HelloEnabled { name, challenge, result } => {
                    self.s.busy = None;
                    if let Screen::Unlocked(session) = &mut self.screen {
                        match result {
                            Ok(signature) => match session.vault.enable_hello(name, challenge, &signature) {
                                Ok(()) => {
                                    session.offer_hello = false;
                                    self.s.toast("Windows Hello is set up. Use it next time you unlock.", OK);
                                }
                                Err(e) => self.s.toast(e.to_string(), DANGER),
                            },
                            Err(e) => self.s.toast(e, DANGER),
                        }
                    }
                }
                Job::PasswordKeys(result) => {
                    self.s.busy = None;
                    if let Screen::Unlocked(session) = &mut self.screen {
                        let form = &mut session.settings;
                        match result {
                            Ok((current_kek, new_salt, new_kek)) => {
                                if !session.vault.password_key_matches(&current_kek) {
                                    form.message = Some(("Your current master password is not correct.".into(), false));
                                } else {
                                    match session.vault.set_password_key(new_salt, KdfParams::STRONG, &new_kek) {
                                        Ok(()) => {
                                            *form = SettingsForm::default();
                                            form.message = Some(("Master password changed.".into(), true));
                                        }
                                        Err(e) => form.message = Some((e.to_string(), false)),
                                    }
                                }
                            }
                            Err(e) => form.message = Some((e, false)),
                        }
                    }
                }
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_jobs();
        self.s.clipboard.tick();
        // A Windows Hello prompt is the user being active somewhere else.
        if self.s.busy.is_some() {
            self.last_activity = Instant::now();
        }
        if self.last_activity.elapsed() >= Duration::from_secs(IDLE_CLOSE_SECONDS) {
            self.s.clipboard.clear_if_ours();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(if self.s.busy.is_some() { 16 } else { 1000 }));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if ui.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        if !self.title_bar_done {
            self.title_bar_done = window::apply_dark_title_bar();
        }
        let ctx = ui.ctx().clone();

        footer(ui, &mut self.s, self.last_activity);

        let next = match &mut self.screen {
            Screen::Setup(st) => {
                setup_ui(ui, &ctx, st, &mut self.s);
                Next::Stay
            }
            Screen::Locked(l) => {
                lock_ui(ui, &ctx, l, &mut self.s);
                Next::Stay
            }
            Screen::Unlocked(session) => session_ui(ui, &ctx, session, &mut self.s),
        };
        if let Next::Lock = next {
            self.s.clipboard.clear_if_ours();
            self.screen = Self::start_screen(&self.s.path);
            self.s.toast("Vault locked.", MUTED);
        }
    }

    fn on_exit(&mut self) {
        self.s.clipboard.clear_if_ours();
    }
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

fn footer(ui: &mut egui::Ui, s: &mut Shared, last_activity: Instant) {
    egui::Panel::bottom("footer")
        .resizable(false)
        .show_separator_line(true)
        .frame(Frame::new().fill(theme::PANEL).inner_margin(Margin::symmetric(16, 8)))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(t) = &s.toast {
                    if Instant::now() < t.until {
                        ui.label(RichText::new(&t.text).size(theme::SIZE_SMALL).color(t.color));
                    } else {
                        s.toast = None;
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let left = IDLE_CLOSE_SECONDS.saturating_sub(last_activity.elapsed().as_secs());
                    let text = format!("Closes in {}:{:02} if idle", left / 60, left % 60);
                    let color = if left <= 60 { BRASS } else { MUTED };
                    ui.label(RichText::new(text).size(theme::SIZE_SMALL).color(color));
                });
            });
        });
}

/// A left-aligned column of fixed width, centred in the window.
fn centered_column(ui: &mut egui::Ui, width: f32, height: f32, add: impl FnOnce(&mut egui::Ui)) {
    let avail = ui.available_rect_before_wrap();
    let x = avail.center().x - width / 2.0;
    let y = (avail.center().y - height / 2.0).max(avail.top() + 24.0);
    let rect = Rect::from_min_size(Pos2::new(x.max(avail.left() + 16.0), y), Vec2::new(width.min(avail.width() - 32.0), height));
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect).layout(Layout::top_down(Align::Min)), add);
}

fn dial(ui: &mut egui::Ui, s: &Shared, radius: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(radius * 2.0 + 12.0), Sense::hover());
    let turn = if s.busy == Some(Busy::Opening) {
        // Eased, continuous turning while the vault opens.
        let t = s.busy_since.elapsed().as_secs_f32();
        t * 0.35 + (t * 2.2).sin() * 0.04
    } else {
        0.0
    };
    theme::paint_dial(ui.painter(), rect.center(), radius, turn);
}

fn password_field(ui: &mut egui::Ui, value: &mut String, label: egui::Id) -> egui::Response {
    ui.add(egui::TextEdit::singleline(value).password(true).desired_width(f32::INFINITY).margin(Margin::symmetric(10, 8)).font(theme::body(15.0)))
        .labelled_by(label)
}

fn text_field(ui: &mut egui::Ui, value: &mut String, hint: &str, width: f32) -> egui::Response {
    ui.add(egui::TextEdit::singleline(value).hint_text(hint).desired_width(width).margin(Margin::symmetric(10, 7)))
}

fn submitted(ui: &egui::Ui, r: &egui::Response) -> bool {
    r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

/// Rough strength estimate for the setup screen: 0 (weak) to 3 (strong).
fn strength(pw: &str) -> usize {
    let len = pw.chars().count();
    let classes = [
        pw.chars().any(|c| c.is_lowercase()),
        pw.chars().any(|c| c.is_uppercase()),
        pw.chars().any(|c| c.is_ascii_digit()),
        pw.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    match (len, classes) {
        (l, _) if l < MIN_MASTER_PASSWORD_LEN => 0,
        (l, c) if l >= 20 || (l >= 14 && c >= 3) => 3,
        (l, c) if l >= 12 || c >= 3 => 2,
        _ => 1,
    }
}

fn strength_meter(ui: &mut egui::Ui, pw: &str) {
    let score = strength(pw);
    let (labels, colors) = (["Too short", "Fair", "Good", "Strong"], [DANGER, BRASS, BRASS, OK]);
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 4.0), Sense::hover());
    let gap = 4.0;
    let seg = (width - gap * 3.0) / 4.0;
    for i in 0..4 {
        let r = Rect::from_min_size(Pos2::new(rect.left() + i as f32 * (seg + gap), rect.top()), Vec2::new(seg, 4.0));
        let filled = !pw.is_empty() && i <= score;
        ui.painter().rect_filled(r, 2, if filled { colors[score] } else { theme::RAISED });
    }
    let text = if pw.is_empty() { format!("Use at least {MIN_MASTER_PASSWORD_LEN} characters.") } else { labels[score].to_owned() };
    ui.label(theme::muted(text));
}

// ---------------------------------------------------------------------------
// First run
// ---------------------------------------------------------------------------

fn setup_ui(ui: &mut egui::Ui, ctx: &egui::Context, st: &mut SetupScreen, s: &mut Shared) {
    egui::CentralPanel::default().frame(Frame::new().fill(theme::BG)).show(ui, |ui| {
        centered_column(ui, 380.0, 540.0, |ui| {
            dial(ui, s, 52.0);
            ui.add_space(14.0);
            ui.label(RichText::new("Create your vault").font(theme::strong(theme::SIZE_DISPLAY)).color(TEXT));
            ui.add_space(2.0);
            ui.label(
                RichText::new("Choose a master password. It encrypts everything you store here, on this PC only. Nobody can reset it, so keep it somewhere safe.")
                    .size(theme::SIZE_BODY)
                    .color(MUTED),
            );
            ui.add_space(18.0);

            let busy = s.busy.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                let lid = ui.label(theme::label("Master password")).id;
                password_field(ui, &mut st.password, lid);
                ui.add_space(2.0);
                strength_meter(ui, &st.password);
                ui.add_space(6.0);
                let lid = ui.label(theme::label("Type it again")).id;
                let r = password_field(ui, &mut st.confirm, lid);
                ui.add_space(14.0);

                let label = if busy { "Creating vault\u{2026}" } else { "Create vault" };
                let clicked = ui.add_sized([ui.available_width(), 38.0], theme::primary(label)).clicked();
                if clicked || submitted(ui, &r) {
                    if st.password.chars().count() < MIN_MASTER_PASSWORD_LEN {
                        st.error = Some(format!("Use at least {MIN_MASTER_PASSWORD_LEN} characters for your master password."));
                    } else if *st.password != *st.confirm {
                        st.error = Some("The two passwords do not match.".into());
                    } else {
                        st.error = None;
                        let pw = Zeroizing::new(st.password.to_string());
                        st.password.zeroize();
                        st.confirm.zeroize();
                        let path = s.path.clone();
                        s.start(ctx, Busy::Opening, move || Job::Opened {
                            result: UnlockedVault::create(&path, &pw, KdfParams::STRONG).map_err(|e| e.to_string()),
                            is_new: true,
                        });
                    }
                }
            });
            if let Some(e) = &st.error {
                ui.add_space(8.0);
                ui.label(RichText::new(e).size(theme::SIZE_SMALL + 0.5).color(DANGER));
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Lock screen
// ---------------------------------------------------------------------------

fn lock_ui(ui: &mut egui::Ui, ctx: &egui::Context, l: &mut LockScreen, s: &mut Shared) {
    egui::CentralPanel::default().frame(Frame::new().fill(theme::BG)).show(ui, |ui| {
        centered_column(ui, 360.0, 470.0, |ui| {
            dial(ui, s, 52.0);
            ui.add_space(14.0);
            ui.label(RichText::new("LocalVault is locked").font(theme::strong(theme::SIZE_DISPLAY)).color(TEXT));
            ui.add_space(2.0);
            let prompt = if l.has_hello {
                "Unlock with Windows Hello or your master password."
            } else {
                "Enter your master password to unlock."
            };
            ui.label(RichText::new(prompt).size(theme::SIZE_BODY).color(MUTED));
            ui.add_space(18.0);

            let busy = s.busy.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                let lid = ui.label(theme::label("Master password")).id;
                let r = password_field(ui, &mut l.password, lid);
                if !l.focused && !busy {
                    r.request_focus();
                    l.focused = true;
                }
                ui.add_space(12.0);
                let label = if busy { "Unlocking\u{2026}" } else { "Unlock" };
                let clicked = ui.add_sized([ui.available_width(), 38.0], theme::primary(label)).clicked();
                if (clicked || submitted(ui, &r)) && !l.password.is_empty() {
                    l.error = None;
                    let pw = Zeroizing::new(l.password.to_string());
                    l.password.zeroize();
                    let path = s.path.clone();
                    s.start(ctx, Busy::Opening, move || Job::Opened {
                        result: UnlockedVault::unlock_with_password(&path, &pw).map_err(|e| e.to_string()),
                        is_new: false,
                    });
                }

                if l.has_hello {
                    ui.add_space(4.0);
                    if ui.add_sized([ui.available_width(), 38.0], theme::secondary("Unlock with Windows Hello")).clicked() {
                        l.error = None;
                        let path = s.path.clone();
                        s.start(ctx, Busy::Opening, move || {
                            let result = (|| {
                                let file = VaultFile::load(&path).map_err(|e| e.to_string())?;
                                let slot = file.hello_slot.clone().ok_or_else(|| "Windows Hello is not set up for this vault.".to_string())?;
                                let signature = hello::sign(&slot.credential_name, &slot.challenge).map_err(|e| e.to_string())?;
                                UnlockedVault::unlock_with_hello_signature(&path, file, &signature).map_err(|e| e.to_string())
                            })();
                            Job::Opened { result, is_new: false }
                        });
                    }
                }
            });
            if busy {
                ui.add_space(8.0);
                ui.label(theme::muted("Opening the vault\u{2026}"));
            }
            if let Some(e) = &l.error {
                ui.add_space(8.0);
                ui.label(RichText::new(e).size(theme::SIZE_SMALL + 0.5).color(DANGER));
            }
        });
    });
}

// ---------------------------------------------------------------------------
// Unlocked vault
// ---------------------------------------------------------------------------

fn session_ui(ui: &mut egui::Ui, ctx: &egui::Context, session: &mut Session, s: &mut Shared) -> Next {
    let mut next = Next::Stay;

    egui::Panel::left("entries")
        .resizable(false)
        .exact_size(292.0)
        .show_separator_line(true)
        .frame(Frame::new().fill(theme::PANEL).inner_margin(Margin { left: 14, right: 14, top: 16, bottom: 12 }))
        .show(ui, |ui| {
            egui::Panel::bottom("entries_footer")
                .resizable(false)
                .show_separator_line(false)
                .frame(Frame::new().inner_margin(Margin { left: 0, right: 0, top: 10, bottom: 0 }))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let half = (ui.available_width() - 8.0) / 2.0;
                        if ui.add_sized([half, 32.0], theme::secondary("Settings")).clicked() {
                            session.settings = SettingsForm::default();
                            session.dialog = Dialog::Settings;
                        }
                        if ui.add_sized([half, 32.0], theme::secondary("Lock")).clicked() {
                            next = Next::Lock;
                        }
                    });
                });
            entry_list(ui, session);
        });

    egui::CentralPanel::default().frame(Frame::new().fill(theme::BG).inner_margin(Margin { left: 40, right: 32, top: 28, bottom: 20 })).show(ui, |ui| {
        if session.offer_hello && session.vault.hello_slot().is_none() {
            hello_offer(ui, ctx, session, s);
            ui.add_space(20.0);
        }
        if session.draft.is_some() {
            edit_view(ui, session, s);
        } else if session.vault.data.entries.is_empty() {
            empty_view(ui, session);
        } else if let Some(idx) = session.selected.as_ref().and_then(|id| session.vault.data.entries.iter().position(|e| &e.id == id)) {
            detail_view(ui, session, s, idx);
        } else {
            ui.add_space(4.0);
            ui.label(RichText::new("Select an entry to see its details.").size(theme::SIZE_BODY).color(MUTED));
        }
    });

    dialogs(ui, ctx, session, s);
    if ui.input(|i| i.modifiers.ctrl && i.key_pressed(Key::L)) {
        next = Next::Lock;
    }
    next
}

fn entry_list(ui: &mut egui::Ui, session: &mut Session) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("LocalVault").font(theme::strong(16.0)).color(TEXT));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let n = session.vault.data.entries.len();
            ui.label(theme::muted(if n == 1 { "1 entry".to_owned() } else { format!("{n} entries") }));
        });
    });
    ui.add_space(8.0);
    text_field(ui, &mut session.search, "Search", f32::INFINITY);
    ui.add_space(4.0);
    let editing = session.draft.is_some();
    if ui.add_enabled(!editing, egui::Button::new(RichText::new("New entry").font(theme::strong(theme::SIZE_BODY)).color(theme::ON_BRASS)).fill(BRASS).stroke(Stroke::NONE).corner_radius(theme::RADIUS).min_size(Vec2::new(ui.available_width(), 34.0))).clicked() {
        start_new_entry(session);
    }
    ui.add_space(10.0);

    let query = session.search.trim().to_lowercase();
    let mut rows: Vec<(usize, String)> = session
        .vault
        .data
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            query.is_empty()
                || e.title.to_lowercase().contains(&query)
                || e.website.to_lowercase().contains(&query)
                || e.subtitle().to_lowercase().contains(&query)
        })
        .map(|(i, e)| (i, e.title.to_lowercase()))
        .collect();
    rows.sort_by(|a, b| a.1.cmp(&b.1));

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        if rows.is_empty() && !query.is_empty() {
            ui.add_space(6.0);
            ui.label(theme::muted("No entries match your search."));
        }
        for (i, _) in rows {
            let entry = &session.vault.data.entries[i];
            let selected = session.selected.as_deref() == Some(entry.id.as_str());
            let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 50.0), Sense::click());
            let name = if entry.title.is_empty() { "Untitled".to_owned() } else { entry.title.clone() };
            resp.widget_info(|| egui::WidgetInfo::selected(egui::Role::Button, true, selected, &name));
            let painter = ui.painter_at(rect);
            if selected {
                painter.rect_filled(rect, theme::RADIUS, theme::RAISED);
                painter.rect_filled(Rect::from_min_size(rect.min + Vec2::new(0.0, 10.0), Vec2::new(3.0, rect.height() - 20.0)), 2, BRASS);
            } else if resp.hovered() {
                painter.rect_filled(rect, theme::RADIUS, theme::RAISED.gamma_multiply(0.6));
            }
            let title = if entry.title.is_empty() { "Untitled" } else { entry.title.as_str() };
            painter.text(rect.left_top() + Vec2::new(14.0, 8.0), egui::Align2::LEFT_TOP, title, theme::body(theme::SIZE_BODY), TEXT);
            let sub = entry.subtitle();
            if !sub.is_empty() {
                painter.text(rect.left_top() + Vec2::new(14.0, 28.0), egui::Align2::LEFT_TOP, sub, theme::body(theme::SIZE_SMALL), MUTED);
            }
            if resp.clicked() && !editing {
                session.selected = Some(entry.id.clone());
                session.revealed.clear();
            }
        }
    });
}

fn start_new_entry(session: &mut Session) {
    if let Ok(entry) = Entry::new_login() {
        session.draft = Some(Draft { entry, is_new: true, revealed: HashSet::new(), error: None });
    }
}

fn hello_offer(ui: &mut egui::Ui, ctx: &egui::Context, session: &mut Session, s: &mut Shared) {
    Frame::new()
        .fill(theme::PANEL)
        .stroke(Stroke::new(1.0, theme::BRASS_DIM))
        .corner_radius(8)
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_max_width(ui.available_width().min(640.0));
            ui.label(RichText::new("Unlock with Windows Hello").font(theme::strong(15.5)).color(TEXT));
            ui.label(
                RichText::new("Use your face, fingerprint or PIN instead of typing your master password. Your master password keeps working as a backup.")
                    .size(theme::SIZE_BODY)
                    .color(MUTED),
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let busy = s.busy == Some(Busy::HelloSetup);
                if ui.add_enabled(!busy, theme::primary(if busy { "Waiting for Windows Hello\u{2026}" } else { "Set up Windows Hello" })).clicked() {
                    begin_hello_setup(ctx, session, s);
                }
                if ui.add_enabled(!busy, theme::secondary("Not now")).clicked() {
                    session.offer_hello = false;
                }
            });
        });
}

fn begin_hello_setup(ctx: &egui::Context, session: &mut Session, s: &mut Shared) {
    let name = format!("LocalVault-{}", session.vault.vault_id_hex());
    let challenge = match crypto::random_bytes::<32>() {
        Ok(c) => c.to_vec(),
        Err(e) => {
            s.toast(e.to_string(), DANGER);
            return;
        }
    };
    s.toast("Windows will ask you to confirm twice.", MUTED);
    s.start(ctx, Busy::HelloSetup, move || {
        let result = hello::create_and_sign(&name, &challenge).map_err(|e| e.to_string());
        Job::HelloEnabled { name, challenge, result }
    });
}

fn empty_view(ui: &mut egui::Ui, session: &mut Session) {
    ui.set_max_width(ui.available_width().min(520.0));
    ui.add_space(8.0);
    ui.label(RichText::new("Your vault is empty").font(theme::strong(theme::SIZE_TITLE)).color(TEXT));
    ui.add_space(2.0);
    ui.label(
        RichText::new("Add your first login. Each entry starts with a username and a password, and you can add more fields such as a PIN or a security answer.")
            .size(theme::SIZE_BODY)
            .color(MUTED),
    );
    ui.add_space(14.0);
    if ui.add(theme::primary("New entry")).clicked() {
        start_new_entry(session);
    }
}

fn format_date(secs: u64) -> String {
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!("{d} {} {y}", MONTHS[(m - 1) as usize])
}

fn rule(ui: &mut egui::Ui) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(w, 1.0), Sense::hover());
    ui.painter().rect_filled(rect, 0, RULE);
}

fn detail_view(ui: &mut egui::Ui, session: &mut Session, s: &mut Shared, idx: usize) {
    ui.set_max_width(ui.available_width().min(680.0));
    let entry = &session.vault.data.entries[idx];
    let mut edit = false;
    let mut delete = false;

    ui.horizontal(|ui| {
        let title = if entry.title.is_empty() { "Untitled" } else { entry.title.as_str() };
        ui.add(egui::Label::new(RichText::new(title).font(theme::strong(theme::SIZE_TITLE + 3.0)).color(TEXT)).truncate());
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            delete = ui.add(theme::secondary("Delete")).clicked();
            edit = ui.add(theme::secondary("Edit")).clicked();
        });
    });
    if !entry.website.is_empty() {
        let url = if entry.website.contains("://") { entry.website.clone() } else { format!("https://{}", entry.website) };
        ui.hyperlink_to(RichText::new(&entry.website).size(theme::SIZE_BODY).color(BRASS), url);
    }
    ui.add_space(16.0);
    rule(ui);

    let mut copy: Option<(String, String)> = None;
    for (i, field) in entry.fields.iter().enumerate() {
        ui.add_space(10.0);
        ui.label(theme::label(if field.name.is_empty() { "Field" } else { field.name.as_str() }));
        ui.horizontal(|ui| {
            let revealed = session.revealed.contains(&i);
            let shown = if field.value.is_empty() {
                RichText::new("Empty").size(theme::SIZE_BODY).color(MUTED.gamma_multiply(0.7))
            } else if field.secret && !revealed {
                RichText::new(MASK).size(theme::SIZE_BODY).color(TEXT)
            } else if field.secret {
                RichText::new(&field.value).font(theme::mono(15.5)).color(TEXT)
            } else {
                RichText::new(&field.value).size(theme::SIZE_BODY + 0.5).color(TEXT)
            };
            ui.add(egui::Label::new(shown).truncate());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !field.value.is_empty() {
                    if ui.add(theme::quiet("Copy")).clicked() {
                        copy = Some((if field.name.is_empty() { "Value".into() } else { field.name.clone() }, field.value.clone()));
                    }
                    if field.secret && ui.add(theme::quiet(if revealed { "Hide" } else { "Show" })).clicked() {
                        if revealed {
                            session.revealed.remove(&i);
                        } else {
                            session.revealed.insert(i);
                        }
                    }
                }
            });
        });
        ui.add_space(10.0);
        rule(ui);
    }

    if !entry.notes.is_empty() {
        ui.add_space(10.0);
        ui.label(theme::label("Notes"));
        ui.label(RichText::new(&entry.notes).size(theme::SIZE_BODY).color(TEXT));
    }
    ui.add_space(18.0);
    ui.label(theme::muted(format!("Last changed {}", format_date(entry.modified))));

    if let Some((name, mut value)) = copy {
        s.copy(&name, &value);
        value.zeroize();
    }
    if edit {
        let entry = session.vault.data.entries[idx].clone();
        session.draft = Some(Draft { entry, is_new: false, revealed: HashSet::new(), error: None });
    }
    if delete {
        session.dialog = Dialog::Delete(session.vault.data.entries[idx].id.clone());
    }
}

fn edit_view(ui: &mut egui::Ui, session: &mut Session, s: &mut Shared) {
    let Some(draft) = session.draft.as_mut() else { return };
    let mut save = false;
    let mut cancel = false;
    let mut open_generator: Option<usize> = None;

    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.set_max_width(ui.available_width().min(680.0));
        ui.label(RichText::new(if draft.is_new { "New entry" } else { "Edit entry" }).font(theme::strong(theme::SIZE_TITLE)).color(TEXT));
        ui.add_space(14.0);

        let lid = ui.label(theme::label("Name")).id;
        let r = text_field(ui, &mut draft.entry.title, "For example: Bank, Gmail, Netflix", f32::INFINITY).labelled_by(lid);
        if draft.is_new && draft.entry.title.is_empty() && !r.has_focus() && ui.memory(|m| m.focused().is_none()) {
            r.request_focus();
        }
        ui.add_space(6.0);
        let lid = ui.label(theme::label("Website")).id;
        text_field(ui, &mut draft.entry.website, "example.com", f32::INFINITY).labelled_by(lid);
        ui.add_space(18.0);

        ui.label(RichText::new("Fields").font(theme::strong(15.5)).color(TEXT));
        ui.label(theme::muted("Hidden fields show as dots until you choose Show."));
        ui.add_space(8.0);

        let mut remove: Option<usize> = None;
        let count = draft.entry.fields.len();
        for i in 0..count {
            let revealed = draft.revealed.contains(&i);
            let field = &mut draft.entry.fields[i];
            ui.horizontal(|ui| {
                text_field(ui, &mut field.name, "Field name", 150.0);
                let buttons = if field.secret { 150.0 } else { 0.0 };
                let w = (ui.available_width() - buttons).max(120.0);
                ui.add(
                    egui::TextEdit::singleline(&mut field.value)
                        .password(field.secret && !revealed)
                        .hint_text("Value")
                        .desired_width(w)
                        .margin(Margin::symmetric(10, 7))
                        .font(if field.secret && revealed { theme::mono(14.5) } else { theme::body(theme::SIZE_BODY) }),
                );
                if field.secret {
                    if ui.add(theme::quiet(if revealed { "Hide" } else { "Show" })).clicked() {
                        if revealed {
                            draft.revealed.remove(&i);
                        } else {
                            draft.revealed.insert(i);
                        }
                    }
                    if ui.add(theme::quiet("Generate")).clicked() {
                        open_generator = Some(i);
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.checkbox(&mut field.secret, RichText::new("Hide value").size(theme::SIZE_SMALL).color(MUTED));
                if ui.add(theme::quiet("Remove field")).clicked() {
                    remove = Some(i);
                }
            });
            ui.add_space(6.0);
        }
        if let Some(i) = remove {
            draft.entry.fields.remove(i);
            draft.revealed.clear();
        }
        ui.horizontal(|ui| {
            if ui.add(theme::secondary("Add field")).clicked() {
                draft.entry.fields.push(Field { name: String::new(), value: String::new(), secret: false });
            }
            if ui.add(theme::secondary("Add hidden field")).clicked() {
                draft.entry.fields.push(Field { name: String::new(), value: String::new(), secret: true });
            }
        });
        ui.add_space(18.0);

        ui.label(theme::label("Notes"));
        ui.add(egui::TextEdit::multiline(&mut draft.entry.notes).desired_rows(4).desired_width(f32::INFINITY).margin(Margin::symmetric(10, 8)));
        ui.add_space(18.0);

        if let Some(e) = &draft.error {
            ui.label(RichText::new(e).size(theme::SIZE_SMALL + 0.5).color(DANGER));
            ui.add_space(6.0);
        }
        ui.horizontal(|ui| {
            save = ui.add(theme::primary("Save entry")).clicked();
            cancel = ui.add(theme::secondary("Cancel")).clicked();
        });
        ui.add_space(12.0);
    });

    if ui.input(|i| i.modifiers.ctrl && i.key_pressed(Key::S)) {
        save = true;
    }
    if let Some(field) = open_generator {
        let opts = GenOptions::default();
        let preview = Zeroizing::new(generator::generate(&opts).unwrap_or_default());
        session.dialog = Dialog::Generator { field, opts, preview };
    }
    if cancel {
        session.draft = None;
        return;
    }
    if save {
        let Some(draft) = session.draft.as_mut() else { return };
        draft.entry.title = draft.entry.title.trim().to_owned();
        if draft.entry.title.is_empty() {
            draft.error = Some("Give this entry a name.".into());
            return;
        }
        draft.entry.fields.retain(|f| !(f.name.trim().is_empty() && f.value.is_empty()));
        draft.entry.modified = unix_now();
        let entries = &mut session.vault.data.entries;
        let previous = if let Some(pos) = entries.iter().position(|e| e.id == draft.entry.id) {
            Some(std::mem::replace(&mut entries[pos], draft.entry.clone()))
        } else {
            entries.push(draft.entry.clone());
            None
        };
        match session.vault.save() {
            Ok(()) => {
                session.selected = Some(draft.entry.id.clone());
                session.revealed.clear();
                session.draft = None;
                s.toast("Entry saved.", OK);
            }
            Err(e) => {
                // Keep memory consistent with the file on disk.
                let entries = &mut session.vault.data.entries;
                if let Some(pos) = entries.iter().position(|x| x.id == draft.entry.id) {
                    match previous {
                        Some(old) => entries[pos] = old,
                        None => {
                            entries.remove(pos);
                        }
                    }
                }
                draft.error = Some(e.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

fn modal_frame() -> Frame {
    Frame::new().fill(theme::PANEL).stroke(Stroke::new(1.0, RULE)).corner_radius(10).inner_margin(Margin::same(24))
}

fn dialogs(ui: &mut egui::Ui, ctx: &egui::Context, session: &mut Session, s: &mut Shared) {
    let mut close = false;
    match &mut session.dialog {
        Dialog::None => {}
        Dialog::Delete(id) => {
            let id = id.clone();
            let title = session.vault.data.entries.iter().find(|e| e.id == id).map(|e| e.title.clone()).unwrap_or_default();
            let resp = egui::Modal::new(egui::Id::unique("delete")).frame(modal_frame()).show(ctx, |ui| {
                ui.set_width(380.0);
                ui.label(RichText::new(format!("Delete {title}?")).font(theme::strong(theme::SIZE_TITLE - 2.0)).color(TEXT));
                ui.add_space(4.0);
                ui.label(RichText::new("This removes the entry and all of its fields. It cannot be undone.").size(theme::SIZE_BODY).color(MUTED));
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::danger("Delete entry")).clicked() {
                        let entries = &mut session.vault.data.entries;
                        if let Some(pos) = entries.iter().position(|e| e.id == id) {
                            let removed = entries.remove(pos);
                            match session.vault.save() {
                                Ok(()) => {
                                    session.selected = None;
                                    s.toast("Entry deleted.", MUTED);
                                }
                                Err(e) => {
                                    session.vault.data.entries.insert(pos, removed);
                                    s.toast(e.to_string(), DANGER);
                                }
                            }
                        }
                        close = true;
                    }
                    if ui.add(theme::secondary("Cancel")).clicked() {
                        close = true;
                    }
                });
            });
            if resp.should_close() {
                close = true;
            }
        }
        Dialog::Generator { field, opts, preview } => {
            let field = *field;
            let resp = egui::Modal::new(egui::Id::unique("generator")).frame(modal_frame()).show(ctx, |ui| {
                ui.set_width(420.0);
                ui.label(RichText::new("Generate a password").font(theme::strong(theme::SIZE_TITLE - 2.0)).color(TEXT));
                ui.add_space(12.0);
                Frame::new().fill(theme::INSET).corner_radius(theme::RADIUS).inner_margin(Margin::symmetric(12, 12)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(egui::Label::new(RichText::new(preview.as_str()).font(theme::mono(16.0)).color(TEXT)).wrap());
                });
                ui.add_space(12.0);
                let before = opts.clone();
                ui.add(egui::Slider::new(&mut opts.length, generator::MIN_LENGTH..=generator::MAX_LENGTH).text("characters"));
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut opts.lower, "a-z");
                    ui.checkbox(&mut opts.upper, "A-Z");
                    ui.checkbox(&mut opts.digits, "0-9");
                    ui.checkbox(&mut opts.symbols, "Symbols");
                });
                ui.checkbox(&mut opts.avoid_ambiguous, "Avoid look-alike characters (I, l, 1, O, 0)");
                let changed = before.length != opts.length
                    || before.lower != opts.lower
                    || before.upper != opts.upper
                    || before.digits != opts.digits
                    || before.symbols != opts.symbols
                    || before.avoid_ambiguous != opts.avoid_ambiguous;
                ui.add_space(18.0);
                let mut regenerate = changed;
                ui.horizontal(|ui| {
                    if ui.add(theme::primary("Use password")).clicked() {
                        if let Some(d) = session.draft.as_mut()
                            && let Some(f) = d.entry.fields.get_mut(field)
                        {
                            f.value = preview.to_string();
                        }
                        close = true;
                    }
                    if ui.add(theme::secondary("New suggestion")).clicked() {
                        regenerate = true;
                    }
                    if ui.add(theme::secondary("Cancel")).clicked() {
                        close = true;
                    }
                });
                if regenerate && let Ok(p) = generator::generate(opts) {
                    *preview = Zeroizing::new(p);
                }
            });
            if resp.should_close() {
                close = true;
            }
        }
        Dialog::Settings => {
            let resp = egui::Modal::new(egui::Id::unique("settings")).frame(modal_frame()).show(ctx, |ui| {
                ui.set_width(460.0);
                let max_h = (ctx.content_rect().height() - 210.0).max(200.0);
                egui::ScrollArea::vertical().max_height(max_h).auto_shrink([false, true]).show(ui, |ui| {
                    ui.set_width(ui.available_width() - 12.0);
                    settings_body(ui, ctx, session, s);
                });
                ui.add_space(14.0);
                if ui.add(theme::secondary("Done")).clicked() {
                    close = true;
                }
            });
            if resp.should_close() && s.busy.is_none() {
                close = true;
            }
        }
    }
    let _ = ui;
    if close {
        session.dialog = Dialog::None;
    }
}

fn settings_body(ui: &mut egui::Ui, ctx: &egui::Context, session: &mut Session, s: &mut Shared) {
    ui.label(RichText::new("Settings").font(theme::strong(theme::SIZE_TITLE)).color(TEXT));
    ui.add_space(14.0);

    // Windows Hello
    ui.label(RichText::new("Windows Hello").font(theme::strong(15.5)).color(TEXT));
    let busy_hello = s.busy == Some(Busy::HelloSetup);
    if let Some(slot) = session.vault.hello_slot() {
        let name = slot.credential_name.clone();
        ui.label(RichText::new("On. You can unlock with your face, fingerprint or PIN.").size(theme::SIZE_BODY).color(MUTED));
        ui.add_space(6.0);
        if ui.add(theme::secondary("Turn off Windows Hello")).clicked() {
            match session.vault.disable_hello() {
                Ok(_) => {
                    thread::spawn(move || {
                        let _ = hello::delete(&name);
                    });
                    s.toast("Windows Hello is off. Unlock with your master password.", MUTED);
                }
                Err(e) => s.toast(e.to_string(), DANGER),
            }
        }
    } else if s.hello_supported == Some(false) {
        ui.label(
            RichText::new("Windows Hello is not set up on this PC. Set it up in Windows Settings under Sign-in options, then come back here.")
                .size(theme::SIZE_BODY)
                .color(MUTED),
        );
    } else {
        ui.label(
            RichText::new("Unlock with your face, fingerprint or PIN instead of your master password. Windows asks you to confirm twice while setting it up.")
                .size(theme::SIZE_BODY)
                .color(MUTED),
        );
        ui.add_space(6.0);
        let label = if busy_hello { "Waiting for Windows Hello\u{2026}" } else { "Set up Windows Hello" };
        if ui.add_enabled(s.busy.is_none(), theme::secondary(label)).clicked() {
            begin_hello_setup(ctx, session, s);
        }
    }

    ui.add_space(16.0);
    rule(ui);
    ui.add_space(14.0);

    // Master password
    ui.label(RichText::new("Master password").font(theme::strong(15.5)).color(TEXT));
    ui.add_space(4.0);
    let busy_pw = s.busy == Some(Busy::PasswordChange);
    let form = &mut session.settings;
    ui.add_enabled_ui(s.busy.is_none(), |ui| {
        let lid = ui.label(theme::label("Current master password")).id;
        password_field(ui, &mut form.current, lid);
        ui.add_space(4.0);
        let lid = ui.label(theme::label("New master password")).id;
        password_field(ui, &mut form.new, lid);
        ui.add_space(2.0);
        strength_meter(ui, &form.new);
        let lid = ui.label(theme::label("Type the new password again")).id;
        password_field(ui, &mut form.confirm, lid);
        ui.add_space(8.0);
        let label = if busy_pw { "Changing\u{2026}" } else { "Change master password" };
        if ui.add(theme::secondary(label)).clicked() {
            if form.new.chars().count() < MIN_MASTER_PASSWORD_LEN {
                form.message = Some((format!("Use at least {MIN_MASTER_PASSWORD_LEN} characters for your new master password."), false));
            } else if *form.new != *form.confirm {
                form.message = Some(("The new passwords do not match.".into(), false));
            } else {
                form.message = None;
                let current = Zeroizing::new(form.current.to_string());
                let new = Zeroizing::new(form.new.to_string());
                let (salt, kdf) = session.vault.password_kdf_inputs();
                s.start(ctx, Busy::PasswordChange, move || {
                    let result = (|| {
                        let current_kek = crypto::derive_key(current.as_bytes(), &salt, kdf).map_err(|e| e.to_string())?;
                        let new_salt = crypto::random_bytes::<SALT_LEN>().map_err(|e| e.to_string())?.to_vec();
                        let new_kek = crypto::derive_key(new.as_bytes(), &new_salt, KdfParams::STRONG).map_err(|e| e.to_string())?;
                        Ok((current_kek, new_salt, new_kek))
                    })();
                    Job::PasswordKeys(result)
                });
            }
        }
    });
    if let Some((msg, ok)) = &form.message {
        ui.add_space(4.0);
        ui.label(RichText::new(msg).size(theme::SIZE_SMALL + 0.5).color(if *ok { OK } else { DANGER }));
    }

    ui.add_space(16.0);
    rule(ui);
    ui.add_space(14.0);

    // Vault file
    ui.label(RichText::new("Vault file").font(theme::strong(15.5)).color(TEXT));
    ui.add(egui::Label::new(RichText::new(session.vault.path().display().to_string()).font(theme::mono(12.5)).color(MUTED)).wrap());
    ui.add_space(2.0);
    ui.label(
        RichText::new("Copy this file to back up your vault. The copy stays encrypted and opens only with your master password.")
            .size(theme::SIZE_SMALL + 0.5)
            .color(MUTED),
    );
}

// ---------------------------------------------------------------------------
// UI tests: drive the real app offscreen (no OS input), save screenshots.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ui_tests {
    use super::*;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    const TEST_PASSWORD: &str = "Brass-Dial-Test-2026";

    fn harness<'a>(path: PathBuf) -> Harness<'a, App> {
        Harness::builder()
            .with_size(Vec2::new(1000.0, 660.0))
            .with_accessibility_check(false)
            .build_eframe(move |cc| {
                theme::install(&cc.egui_ctx);
                App::new(&cc.egui_ctx, path)
            })
    }

    fn shot(h: &mut Harness<'_, App>, name: &str) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs").join("screenshots");
        std::fs::create_dir_all(&dir).unwrap();
        let img = h.render().expect("render");
        img.save(dir.join(format!("{name}.png"))).unwrap();
    }

    fn settle(h: &mut Harness<'_, App>) {
        for _ in 0..4 {
            h.step();
        }
    }

    fn wait(h: &mut Harness<'_, App>, what: &str, cond: impl Fn(&App) -> bool) {
        for _ in 0..2400 {
            h.step();
            if cond(h.state()) {
                settle(h);
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for {what}");
    }

    fn session(a: &App) -> &Session {
        match &a.screen {
            Screen::Unlocked(s) => s,
            _ => panic!("vault is not unlocked"),
        }
    }

    fn session_mut(a: &mut App) -> &mut Session {
        match &mut a.screen {
            Screen::Unlocked(s) => s,
            _ => panic!("vault is not unlocked"),
        }
    }

    fn type_into(h: &mut Harness<'_, App>, label: &str, text: &str) {
        h.get_by_label(label).focus();
        h.step();
        h.get_by_label(label).type_text(text);
        settle(h);
    }

    fn click(h: &mut Harness<'_, App>, label: &str) {
        h.get_by_label(label).scroll_to_me();
        settle(h);
        h.get_by_label(label).click();
        settle(h);
    }

    fn click_first(h: &mut Harness<'_, App>, label: &str) {
        h.get_all_by_label(label).next().unwrap_or_else(|| panic!("no {label}")).click();
        settle(h);
    }

    #[test]
    fn full_user_flow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("LocalVault.vault");
        let mut h = harness(path.clone());
        settle(&mut h);
        shot(&mut h, "1-first-run");

        // First run: create the vault.
        type_into(&mut h, "Master password", TEST_PASSWORD);
        type_into(&mut h, "Type it again", TEST_PASSWORD);
        click(&mut h, "Create vault");
        wait(&mut h, "vault creation", |a| matches!(a.screen, Screen::Unlocked(_)));
        assert!(path.exists());
        if h.query_by_label("Not now").is_some() {
            shot(&mut h, "2a-windows-hello-offer");
            click(&mut h, "Not now");
        }
        shot(&mut h, "2-empty-vault");

        // Add an entry with an extra hidden field.
        click_first(&mut h, "New entry");
        type_into(&mut h, "Name", "Example Bank");
        type_into(&mut h, "Website", "bank.example.com");
        {
            let d = session_mut(h.state_mut()).draft.as_mut().unwrap();
            d.entry.fields[0].value = "jake@example.com".into();
            d.entry.fields[1].value = "correct-horse-battery".into();
            d.entry.fields.push(Field { name: "Card PIN".into(), value: "4821".into(), secret: true });
        }
        settle(&mut h);
        shot(&mut h, "3-new-entry");
        click(&mut h, "Save entry");
        assert_eq!(session(h.state()).vault.data.entries.len(), 1);
        assert!(h.query_by_label("correct-horse-battery").is_none(), "password visible before Show");
        shot(&mut h, "4-entry-hidden");

        click_first(&mut h, "Show");
        assert!(h.query_by_label("correct-horse-battery").is_some(), "password not shown after Show");
        shot(&mut h, "5-entry-revealed");

        // Generate a new password for the entry.
        click(&mut h, "Edit");
        click_first(&mut h, "Generate");
        shot(&mut h, "6-generator");
        let generated = match &session(h.state()).dialog {
            Dialog::Generator { preview, .. } => preview.to_string(),
            _ => panic!("generator not open"),
        };
        click(&mut h, "Use password");
        click(&mut h, "Save entry");
        assert_eq!(session(h.state()).vault.data.entries[0].fields[1].value, generated);

        click(&mut h, "Settings");
        shot(&mut h, "7-settings");
        click(&mut h, "Done");

        // Lock, then try a wrong and a right password.
        click(&mut h, "Lock");
        assert!(matches!(h.state().screen, Screen::Locked(_)));
        type_into(&mut h, "Master password", "not the password");
        click(&mut h, "Unlock");
        wait(&mut h, "wrong password rejection", |a| matches!(&a.screen, Screen::Locked(l) if l.error.is_some()) && a.s.busy.is_none());
        shot(&mut h, "8-wrong-password");
        type_into(&mut h, "Master password", TEST_PASSWORD);
        click(&mut h, "Unlock");
        wait(&mut h, "unlock", |a| matches!(a.screen, Screen::Unlocked(_)));
        let e = &session(h.state()).vault.data.entries[0];
        assert_eq!(e.title, "Example Bank");
        assert_eq!(e.fields[2].value, "4821");

        // Nothing readable on disk.
        let raw = std::fs::read_to_string(&path).unwrap();
        for secret in ["Example Bank", "jake@example.com", "4821", generated.as_str()] {
            assert!(!raw.contains(secret), "{secret} found in the vault file");
        }
    }

    /// Screenshots of every view from the demo vault, without saving anything.
    /// Run with `cargo test screens_from_demo_vault -- --ignored` after make_demo_vault.
    #[test]
    #[ignore]
    fn screens_from_demo_vault() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("dist").join(crate::VAULT_FILE_NAME);
        let mut h = harness(path);
        settle(&mut h);
        shot(&mut h, "3-locked");
        type_into(&mut h, "Master password", TEST_PASSWORD);
        click(&mut h, "Unlock");
        wait(&mut h, "unlock", |a| matches!(a.screen, Screen::Unlocked(_)));
        assert_eq!(session(h.state()).vault.data.entries.len(), 3);
        shot(&mut h, "4-unlocked");
        click(&mut h, "Example Bank");
        assert!(h.query_by_label("Tq7#rLm2-vX9pD").is_none(), "password visible before Show");
        shot(&mut h, "5-entry");
        click_first(&mut h, "Show");
        assert!(h.query_by_label("Tq7#rLm2-vX9pD").is_some(), "password not shown after Show");
        shot(&mut h, "6-entry-revealed");
        click(&mut h, "Edit");
        shot(&mut h, "7-edit-entry");
        click_first(&mut h, "Generate");
        shot(&mut h, "8-generator");
        h.get_all_by_label("Cancel").last().unwrap().click();
        settle(&mut h);
        click(&mut h, "Cancel");
        click(&mut h, "Settings");
        shot(&mut h, "9-settings");
        click(&mut h, "Done");
        click(&mut h, "Delete");
        shot(&mut h, "10-delete-confirm");
        click(&mut h, "Cancel");
        assert_eq!(session(h.state()).vault.data.entries.len(), 3);
    }
    /// Creates dist/LocalVault.vault with the temporary password and a few
    /// made-up entries. Run on purpose with `cargo test make_demo_vault -- --ignored`.
    #[test]
    #[ignore]
    fn make_demo_vault() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("dist").join(crate::VAULT_FILE_NAME);
        assert!(!path.exists(), "{} already exists", path.display());
        let mut v = UnlockedVault::create(&path, TEST_PASSWORD, KdfParams::STRONG).unwrap();
        let samples: [(&str, &str, &[(&str, &str, bool)]); 3] = [
            ("Example Bank", "bank.example.com", &[("Username", "jake.demo", false), ("Password", "Tq7#rLm2-vX9pD", true), ("Card PIN", "4821", true)]),
            ("Example Mail", "mail.example.com", &[("Email", "jake.demo@example.com", false), ("Password", "plum-Orbit-63-sail", true), ("Recovery code", "K3DQ-77PA-XM2T", true)]),
            ("Home Wi-Fi", "", &[("Network", "DemoNet-5G", false), ("Password", "lantern-quiet-river", true)]),
        ];
        for (title, website, fields) in samples {
            let mut e = Entry::new_login().unwrap();
            e.title = title.into();
            e.website = website.into();
            e.fields = fields.iter().map(|(n, val, s)| Field { name: (*n).into(), value: (*val).into(), secret: *s }).collect();
            v.data.entries.push(e);
        }
        v.save().unwrap();
    }
}