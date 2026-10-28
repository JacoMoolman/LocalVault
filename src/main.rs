// No console window behind the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod crypto;
mod generator;
mod hello;
mod theme;
mod vault;
mod window;

use std::path::PathBuf;

use eframe::egui;

// ---------------------------------------------------------------------------
// Settings: edit these values and rebuild.
// ---------------------------------------------------------------------------

/// The vault file is kept next to LocalVault.exe, so the app is portable and
/// writes nothing anywhere else on the PC.
pub const VAULT_FILE_NAME: &str = "LocalVault.vault";

/// The app closes itself after this many seconds without mouse or keyboard input.
pub const IDLE_CLOSE_SECONDS: u64 = 5 * 60;

/// Copied secrets are removed from the clipboard after this many seconds.
pub const CLIPBOARD_CLEAR_SECONDS: u64 = 30;

/// Shortest master password accepted when creating a vault or changing it.
pub const MIN_MASTER_PASSWORD_LEN: usize = 10;

// ---------------------------------------------------------------------------

fn vault_path() -> PathBuf {
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)).unwrap_or_else(|| PathBuf::from("."));
    dir.join(VAULT_FILE_NAME)
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("LocalVault")
            .with_inner_size([1000.0, 660.0])
            .with_min_inner_size([760.0, 520.0])
            .with_icon(theme::app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "LocalVault",
        options,
        Box::new(|cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::new(&cc.egui_ctx, vault_path())))
        }),
    )
}
