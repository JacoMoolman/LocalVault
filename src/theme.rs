//! Visual identity: "vault steel". Blue graphite surfaces, brass for the few
//! things that matter (primary actions, focus, the lock dial), Segoe UI for
//! text and Consolas only where a revealed secret must be read character by
//! character.

use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Pos2, Shadow, Stroke, TextStyle, Vec2,
};

// Palette -------------------------------------------------------------------

pub const BG: Color32 = Color32::from_rgb(0x1B, 0x21, 0x28);
pub const PANEL: Color32 = Color32::from_rgb(0x22, 0x2A, 0x33);
pub const RAISED: Color32 = Color32::from_rgb(0x2B, 0x35, 0x40);
pub const HOVER: Color32 = Color32::from_rgb(0x33, 0x3F, 0x4B);
pub const INSET: Color32 = Color32::from_rgb(0x15, 0x1A, 0x20);
pub const RULE: Color32 = Color32::from_rgb(0x39, 0x45, 0x52);
pub const TEXT: Color32 = Color32::from_rgb(0xE4, 0xE8, 0xEC);
pub const MUTED: Color32 = Color32::from_rgb(0x8A, 0x97, 0xA4);
pub const BRASS: Color32 = Color32::from_rgb(0xCF, 0xA2, 0x4A);
pub const BRASS_DIM: Color32 = Color32::from_rgb(0x7E, 0x65, 0x33);
pub const ON_BRASS: Color32 = Color32::from_rgb(0x1B, 0x21, 0x28);
pub const DANGER: Color32 = Color32::from_rgb(0xDE, 0x6A, 0x5E);
pub const OK: Color32 = Color32::from_rgb(0x6D, 0xBA, 0x8B);

// Type scale (points) ---------------------------------------------------------

pub const SIZE_SMALL: f32 = 12.5;
pub const SIZE_BODY: f32 = 14.5;
pub const SIZE_TITLE: f32 = 21.0;
pub const SIZE_DISPLAY: f32 = 27.0;

pub const RADIUS: u8 = 6;

pub fn semibold() -> FontFamily {
    FontFamily::Name("semibold".into())
}

pub fn body(size: f32) -> FontId {
    FontId::new(size, FontFamily::Proportional)
}

pub fn strong(size: f32) -> FontId {
    FontId::new(size, semibold())
}

pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Monospace)
}

/// Uses the Windows system fonts when present (read only, nothing is
/// installed) and falls back to egui's bundled fonts otherwise.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    let font_dir = std::env::var_os("WINDIR").map(std::path::PathBuf::from).unwrap_or_else(|| "C:\\Windows".into()).join("Fonts");
    let mut load = |key: &str, file: &str| -> bool {
        match std::fs::read(font_dir.join(file)) {
            Ok(bytes) => {
                fonts.font_data.insert(key.to_owned(), Arc::new(FontData::from_owned(bytes)));
                true
            }
            Err(_) => false,
        }
    };
    let has_regular = load("segoe", "segoeui.ttf");
    let has_semibold = load("segoe-semibold", "seguisb.ttf");
    let has_mono = load("consolas", "consola.ttf");

    let proportional = fonts.families.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    if has_regular {
        fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "segoe".into());
    }
    if has_mono {
        fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "consolas".into());
    }
    let mut semi = Vec::new();
    if has_semibold {
        semi.push("segoe-semibold".to_owned());
    } else if has_regular {
        semi.push("segoe".to_owned());
    }
    semi.extend(proportional);
    fonts.families.insert(semibold(), semi);
    ctx.set_fonts(fonts);
}

pub fn install(ctx: &egui::Context) {
    install_fonts(ctx);
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Small, body(SIZE_SMALL)),
            (TextStyle::Body, body(SIZE_BODY)),
            (TextStyle::Button, body(SIZE_BODY)),
            (TextStyle::Monospace, mono(SIZE_BODY)),
            (TextStyle::Heading, strong(SIZE_TITLE)),
        ]
        .into();

        let s = &mut style.spacing;
        s.item_spacing = Vec2::new(8.0, 8.0);
        s.button_padding = Vec2::new(14.0, 7.0);
        s.interact_size = Vec2::new(40.0, 32.0);
        s.text_edit_width = 280.0;
        s.slider_width = 220.0;
        s.window_margin = Margin::same(24);

        let v = &mut style.visuals;
        v.dark_mode = true;
        v.override_text_color = None;
        v.panel_fill = BG;
        v.window_fill = PANEL;
        v.window_stroke = Stroke::new(1.0, RULE);
        v.window_corner_radius = CornerRadius::same(10);
        v.window_shadow = Shadow { offset: [0, 10], blur: 30, spread: 0, color: Color32::from_black_alpha(110) };
        v.popup_shadow = Shadow { offset: [0, 6], blur: 16, spread: 0, color: Color32::from_black_alpha(90) };
        v.menu_corner_radius = CornerRadius::same(RADIUS);
        v.extreme_bg_color = INSET;
        v.text_edit_bg_color = Some(INSET);
        v.faint_bg_color = PANEL;
        v.code_bg_color = INSET;
        v.hyperlink_color = BRASS;
        v.warn_fg_color = BRASS;
        v.error_fg_color = DANGER;
        v.selection.bg_fill = BRASS.gamma_multiply(0.35);
        v.selection.stroke = Stroke::new(1.0, BRASS);
        v.text_cursor.stroke = Stroke::new(2.0, BRASS);
        v.striped = false;
        v.handle_shape = egui::style::HandleShape::Circle;

        let r = CornerRadius::same(RADIUS);
        let w = &mut v.widgets;
        w.noninteractive.bg_fill = PANEL;
        w.noninteractive.weak_bg_fill = PANEL;
        w.noninteractive.bg_stroke = Stroke::new(1.0, RULE);
        w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
        w.noninteractive.corner_radius = r;

        w.inactive.bg_fill = RAISED;
        w.inactive.weak_bg_fill = RAISED;
        w.inactive.bg_stroke = Stroke::new(1.0, RULE);
        w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
        w.inactive.corner_radius = r;
        w.inactive.expansion = 0.0;

        w.hovered.bg_fill = HOVER;
        w.hovered.weak_bg_fill = HOVER;
        w.hovered.bg_stroke = Stroke::new(1.0, BRASS_DIM);
        w.hovered.fg_stroke = Stroke::new(1.0, TEXT);
        w.hovered.corner_radius = r;
        w.hovered.expansion = 0.0;

        w.active.bg_fill = RULE;
        w.active.weak_bg_fill = RULE;
        w.active.bg_stroke = Stroke::new(1.0, BRASS);
        w.active.fg_stroke = Stroke::new(1.0, TEXT);
        w.active.corner_radius = r;
        w.active.expansion = 0.0;

        w.open = w.active;
    });
}

// Buttons ---------------------------------------------------------------------

/// Brass, for the one action a screen is about.
pub fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).font(strong(SIZE_BODY)).color(ON_BRASS))
        .fill(BRASS)
        .stroke(Stroke::NONE)
        .corner_radius(RADIUS)
}

pub fn secondary(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).size(SIZE_BODY).color(TEXT)).corner_radius(RADIUS)
}

/// Small, frameless text action used inside field rows (Show, Copy).
pub fn quiet(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).size(SIZE_SMALL + 0.5).color(MUTED)).frame_when_inactive(false).corner_radius(RADIUS)
}

pub fn danger(text: &str) -> egui::Button<'static> {
    egui::Button::new(egui::RichText::new(text.to_owned()).font(strong(SIZE_BODY)).color(DANGER))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, DANGER.gamma_multiply(0.6)))
        .corner_radius(RADIUS)
}

pub fn muted(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into()).size(SIZE_SMALL).color(MUTED)
}

pub fn label(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text.into()).size(SIZE_SMALL + 0.5).color(MUTED)
}

// The vault dial ----------------------------------------------------------------

/// The app's single decorative element: a brass combination dial. `turn` is a
/// rotation in turns; it spins only while the vault is being opened.
pub fn paint_dial(painter: &egui::Painter, center: Pos2, radius: f32, turn: f32) {
    use std::f32::consts::TAU;
    painter.circle_filled(center, radius, PANEL);
    painter.circle_stroke(center, radius, Stroke::new(2.0, BRASS));
    painter.circle_stroke(center, radius * 0.80, Stroke::new(1.0, RULE));

    let ticks = 60;
    for i in 0..ticks {
        let a = (i as f32 / ticks as f32 + turn) * TAU - TAU / 4.0;
        let dir = Vec2::new(a.cos(), a.sin());
        let major = i % 5 == 0;
        let inner = radius * if major { 0.83 } else { 0.88 };
        let color = if major { BRASS.gamma_multiply(0.85) } else { MUTED.gamma_multiply(0.55) };
        painter.line_segment([center + dir * inner, center + dir * (radius * 0.94)], Stroke::new(if major { 1.6 } else { 1.0 }, color));
    }

    // Fixed index mark at the top.
    let top = center - Vec2::new(0.0, radius + 3.0);
    painter.add(egui::Shape::convex_polygon(
        vec![top + Vec2::new(-5.0, -7.0), top + Vec2::new(5.0, -7.0), top],
        BRASS,
        Stroke::NONE,
    ));

    // Hub with a grip line that turns with the dial.
    painter.circle_filled(center, radius * 0.42, RAISED);
    painter.circle_stroke(center, radius * 0.42, Stroke::new(1.5, BRASS_DIM));
    let a = turn * TAU - TAU / 4.0;
    let dir = Vec2::new(a.cos(), a.sin());
    painter.line_segment([center - dir * radius * 0.30, center + dir * radius * 0.30], Stroke::new(3.0, BRASS));
    painter.circle_filled(center, 3.5, BRASS);
}

/// Window and taskbar icon: the dial, drawn into a 64x64 RGBA buffer.
pub fn app_icon() -> egui::IconData {
    let size = 64u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let c = (size as f32 - 1.0) / 2.0;
    let put = |buf: &mut [u8], x: u32, y: u32, col: Color32, alpha: f32| {
        let i = ((y * size + x) * 4) as usize;
        let a = (alpha.clamp(0.0, 1.0) * 255.0) as u8;
        if a >= buf[i + 3] {
            buf[i] = col.r();
            buf[i + 1] = col.g();
            buf[i + 2] = col.b();
            buf[i + 3] = a;
        }
    };
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            let d = (dx * dx + dy * dy).sqrt();
            let edge = |r: f32| (r - d + 0.5).clamp(0.0, 1.0);
            // Disc, brass ring, hub and grip line.
            put(&mut rgba, x, y, BG, edge(31.0));
            let ring = edge(30.0) * (1.0 - edge(25.5));
            put(&mut rgba, x, y, BRASS, ring);
            put(&mut rgba, x, y, RAISED, edge(13.0));
            if dx.abs() < 2.2 && dy.abs() < 10.0 {
                put(&mut rgba, x, y, BRASS, 1.0);
            }
        }
    }
    egui::IconData { rgba, width: size, height: size }
}
