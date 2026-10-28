//! Windows Hello (face, fingerprint or PIN) through the WinRT
//! `KeyCredentialManager` API.
//!
//! Windows Hello creates an RSA key inside the TPM / Windows Hello container.
//! The private key never leaves it and can only be used after the user passes
//! Windows Hello. LocalVault asks that key to sign a fixed random challenge and
//! turns the signature into the key that unlocks the vault. PKCS#1 v1.5 RSA
//! signatures are deterministic; `create_and_sign` checks that by signing twice
//! and refuses to enable Windows Hello if the two signatures differ.
//!
//! Every call blocks until the user finishes the Windows prompt, so call these
//! from a worker thread.

use std::thread;
use std::time::{Duration, Instant};

use windows::Security::Credentials::{KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize};
use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetClassNameW, IsWindowVisible, SetForegroundWindow};
use windows::core::{Array, BOOL, HSTRING};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq)]
pub enum HelloError {
    NotAvailable,
    Cancelled,
    NotFound,
    DeviceLocked,
    NotDeterministic,
    Other(String),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::NotAvailable => write!(f, "Windows Hello is not set up on this PC. Set it up in Windows Settings first, or use your master password."),
            HelloError::Cancelled => write!(f, "Windows Hello was cancelled."),
            HelloError::NotFound => write!(f, "This vault's Windows Hello key is not on this PC. Unlock with your master password, then set up Windows Hello again in Settings."),
            HelloError::DeviceLocked => write!(f, "Windows Hello is temporarily locked after too many attempts. Use your master password."),
            HelloError::NotDeterministic => write!(f, "This PC's Windows Hello key cannot be used to unlock vaults. Keep using your master password."),
            HelloError::Other(e) => write!(f, "Windows Hello failed: {e}"),
        }
    }
}

impl From<windows::core::Error> for HelloError {
    fn from(e: windows::core::Error) -> Self {
        HelloError::Other(e.message().to_string())
    }
}

fn status_error(status: KeyCredentialStatus) -> HelloError {
    match status {
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => HelloError::Cancelled,
        KeyCredentialStatus::NotFound => HelloError::NotFound,
        KeyCredentialStatus::SecurityDeviceLocked => HelloError::DeviceLocked,
        other => HelloError::Other(format!("status code {}", other.0)),
    }
}

fn init_thread() {
    // Safe to call more than once per thread; an "already initialised" result is fine.
    unsafe {
        let _ = RoInitialize(RO_INIT_MULTITHREADED);
    }
}

pub fn is_available() -> bool {
    init_thread();
    KeyCredentialManager::IsSupportedAsync().and_then(|op| op.join()).unwrap_or(false)
}

/// Creates (or replaces) the Windows Hello key called `name` and returns its
/// signature over `challenge`. Windows shows its prompt twice.
pub fn create_and_sign(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    init_thread();
    if !is_available() {
        return Err(HelloError::NotAvailable);
    }
    let hname = HSTRING::from(name);
    let _focus = FocusAssist::start();
    let result = KeyCredentialManager::RequestCreateAsync(&hname, KeyCredentialCreationOption::ReplaceExisting)?.join()?;
    let status = result.Status()?;
    if status != KeyCredentialStatus::Success {
        return Err(status_error(status));
    }
    let credential = result.Credential()?;
    let first = sign_with(&credential, challenge)?;
    let second = sign_with(&credential, challenge)?;
    if first != second {
        let _ = delete(name);
        return Err(HelloError::NotDeterministic);
    }
    Ok(first)
}

/// Asks Windows Hello to sign `challenge` with the existing key `name`.
pub fn sign(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    init_thread();
    if !is_available() {
        return Err(HelloError::NotAvailable);
    }
    let _focus = FocusAssist::start();
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(name))?.join()?;
    let status = result.Status()?;
    if status != KeyCredentialStatus::Success {
        return Err(status_error(status));
    }
    sign_with(&result.Credential()?, challenge)
}

fn sign_with(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
    let buffer = CryptographicBuffer::CreateFromByteArray(challenge)?;
    let op = credential.RequestSignAsync(&buffer)?.join()?;
    let status = op.Status()?;
    if status != KeyCredentialStatus::Success {
        return Err(status_error(status));
    }
    let mut out = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&op.Result()?, &mut out)?;
    Ok(Zeroizing::new(out.to_vec()))
}

/// Removes the Windows Hello key called `name` from this PC.
pub fn delete(name: &str) -> Result<(), HelloError> {
    init_thread();
    KeyCredentialManager::DeleteAsync(&HSTRING::from(name))?.join()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Keeping the Windows Hello prompt in front
// ---------------------------------------------------------------------------

/// Window class of the Windows Hello prompt. Best effort: if Windows uses a
/// different class, the prompt simply is not raised and nothing else changes.
const HELLO_DIALOG_CLASS: &str = "Credential Dialog Xaml Host";

/// While a request is running this watches for the Windows Hello prompt and
/// brings it to the front once, so it does not open hidden behind the vault.
struct FocusAssist {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl FocusAssist {
    fn start() -> FocusAssist {
        use std::sync::atomic::Ordering;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        thread::spawn(move || {
            let started = Instant::now();
            while !flag.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(20) {
                if let Some(hwnd) = find_hello_dialog() {
                    unsafe {
                        let _ = SetForegroundWindow(hwnd);
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        FocusAssist { stop }
    }
}

impl Drop for FocusAssist {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

pub(crate) fn window_class(hwnd: HWND) -> String {
    let mut buf = [0u16; 256];
    let len = unsafe { GetClassNameW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..len.max(0) as usize])
}

fn find_hello_dialog() -> Option<HWND> {
    unsafe extern "system" fn visit(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let found = unsafe { &mut *(lparam.0 as *mut Option<HWND>) };
        if unsafe { IsWindowVisible(hwnd) }.as_bool() && window_class(hwnd) == HELLO_DIALOG_CLASS {
            *found = Some(hwnd);
            return BOOL(0);
        }
        BOOL(1)
    }
    let mut found: Option<HWND> = None;
    unsafe {
        let _ = EnumWindows(Some(visit), LPARAM(&mut found as *mut _ as isize));
    }
    found
}
