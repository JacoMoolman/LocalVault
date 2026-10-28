//! Per-window tweaks for this app's own window. Nothing here changes any
//! Windows setting; it only affects the LocalVault window while it is open.

use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsWindowVisible};
use windows::core::BOOL;

/// Gives this process's visible top-level windows a dark title bar, to match
/// the app. Returns true once at least one window was found.
pub fn apply_dark_title_bar() -> bool {
    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = unsafe { &mut *(lparam.0 as *mut (u32, bool)) };
        let mut pid = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == state.0 && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            let dark = BOOL(1);
            let ok = unsafe {
                DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark as *const BOOL as *const core::ffi::c_void, size_of::<BOOL>() as u32)
            };
            if ok.is_ok() {
                state.1 = true;
            }
        }
        BOOL(1)
    }
    let mut state: (u32, bool) = (unsafe { GetCurrentProcessId() }, false);
    unsafe {
        let _ = EnumWindows(Some(visit), LPARAM(&mut state as *mut _ as isize));
    }
    state.1
}
