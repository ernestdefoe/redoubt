//! Asking Windows for administrator rights, from the interface.
//!
//! Registering the AMSI provider and installing the service both write to
//! `HKLM` and the Service Control Manager, which need elevation. Telling a
//! person to open an administrator terminal and type a command is not a
//! feature; it is a wall. Most people will simply not have protection on.
//!
//! So the interface asks instead. `ShellExecuteExW` with the `runas` verb is
//! the supported way for a non-elevated process to request elevation: Windows
//! shows its own consent dialog, and the elevated work happens in a *separate*
//! process. The interface itself never becomes elevated - which is the point.
//! A long-lived local HTTP server running as administrator would be a far
//! worse thing to have on the machine than a command someone has to type.
//!
//! Three outcomes matter and they are kept distinct, because they need
//! different words in front of a person:
//!
//! - **Completed** - the child ran; its exit code says whether it worked.
//! - **Declined** - the consent dialog was dismissed. Nothing changed, nothing
//!   is broken, and it must not be reported as a failure.
//! - **Failed** - the request itself could not be made.

use std::ffi::c_void;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// `ERROR_CANCELLED`. What Windows returns when the consent dialog is
/// dismissed - by clicking No, or by a standard user with no administrator to
/// hand.
const ERROR_CANCELLED: u32 = 1223;

/// How an elevation request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The elevated process ran to completion. Zero means it did its job.
    Completed { exit_code: u32 },
    /// The person said no, or had no administrator credentials to offer.
    /// Not an error: the machine is exactly as it was.
    Declined,
    /// The request could not be made at all.
    Failed { reason: String },
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Outcome::Completed { exit_code: 0 })
    }

    /// A sentence to put in front of a person, with no jargon in it.
    pub fn message(&self, what: &str) -> String {
        match self {
            Outcome::Completed { exit_code: 0 } => format!("{what} succeeded."),
            Outcome::Completed { exit_code } => {
                format!("{what} did not complete (exit code {exit_code}).")
            }
            Outcome::Declined => {
                format!("{what} needs administrator approval. Nothing was changed.")
            }
            Outcome::Failed { reason } => format!("{what} could not be started: {reason}"),
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A process handle that always closes.
struct Process(HANDLE);

impl Drop for Process {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: obtained from ShellExecuteExW with NOCLOSEPROCESS.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Run `exe args...` elevated, and wait for it to finish.
///
/// Blocks until the person answers the consent dialog and the child exits, so
/// the caller must not be holding anything the child needs. In the interface
/// this runs on a job thread rather than in a request handler.
pub fn run_elevated(exe: &Path, args: &[&str]) -> Outcome {
    if !exe.is_file() {
        return Outcome::Failed { reason: format!("{} does not exist", exe.display()) };
    }

    // ShellExecuteEx requires COM on the calling thread. A thread that is
    // already initialised returns S_FALSE or RPC_E_CHANGED_MODE; neither is a
    // problem for us, so the result is deliberately not checked.
    // SAFETY: no arguments, and we never call CoUninitialize - this thread is
    // short-lived and owned by the job that spawned it.
    unsafe {
        CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);
    }

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&args.join(" "));
    // The child inherits the working directory otherwise, which for a service
    // binary is a needless surprise.
    let dir = exe
        .parent()
        .map(|p| wide(&p.to_string_lossy()))
        .unwrap_or_else(|| wide(""));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        // NOCLOSEPROCESS hands back a handle so we can wait for the exit code;
        // NOASYNC keeps the request alive even if this thread goes away first.
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        hwnd: std::ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: if args.is_empty() { std::ptr::null() } else { params.as_ptr() },
        lpDirectory: dir.as_ptr(),
        // The child prints to a console nobody is watching; the interface
        // reports the outcome instead. A window flashing up reads as a virus.
        nShow: SW_HIDE,
        hInstApp: std::ptr::null_mut(),
        lpIDList: std::ptr::null_mut(),
        lpClass: std::ptr::null(),
        hkeyClass: std::ptr::null_mut(),
        dwHotKey: 0,
        Anonymous: unsafe { std::mem::zeroed() },
        hProcess: std::ptr::null_mut(),
    };

    // SAFETY: every pointer in `info` outlives the call, and cbSize is right.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(code) if code as u32 == ERROR_CANCELLED => Outcome::Declined,
            _ => Outcome::Failed { reason: err.to_string() },
        };
    }

    let process = Process(info.hProcess);
    if process.0.is_null() {
        // Started, but we cannot observe it. Reporting success would be a
        // guess, and the caller can always re-read the real state instead.
        return Outcome::Failed {
            reason: "the elevated process gave no handle to wait on".into(),
        };
    }

    // SAFETY: `process.0` is a live process handle.
    if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
        return Outcome::Failed { reason: "waiting for the elevated process failed".into() };
    }

    let mut code: u32 = 0;
    // SAFETY: the process has exited, so the code is final.
    if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
        return Outcome::Failed { reason: "could not read the elevated exit code".into() };
    }

    Outcome::Completed { exit_code: code }
}

/// Locate `redoubtd.exe`, which is what actually does the elevated work.
///
/// It sits beside whichever binary is running: the interface ships next to it.
pub fn redoubtd_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    if exe.file_stem().is_some_and(|s| s.eq_ignore_ascii_case("redoubtd")) {
        return Some(exe);
    }
    let beside = exe.with_file_name("redoubtd.exe");
    beside.is_file().then_some(beside)
}

/// Suppress an unused import warning on a type only used through pointers.
#[allow(dead_code)]
fn _unused(_: *mut c_void) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declined_prompt_is_not_a_failure() {
        // The wording matters: a person who clicks No has not broken
        // anything, and telling them something failed invites them to go
        // looking for a problem that does not exist.
        let m = Outcome::Declined.message("Enabling script scanning");
        assert!(m.contains("Nothing was changed"), "{m}");
        assert!(!m.to_lowercase().contains("fail"), "{m}");
        assert!(!Outcome::Declined.succeeded());
    }

    #[test]
    fn only_a_zero_exit_counts_as_success() {
        assert!(Outcome::Completed { exit_code: 0 }.succeeded());
        assert!(!Outcome::Completed { exit_code: 1 }.succeeded());
        assert!(!Outcome::Failed { reason: "x".into() }.succeeded());
    }

    #[test]
    fn a_nonzero_exit_says_so_without_blaming_the_person() {
        let m = Outcome::Completed { exit_code: 2 }.message("Installing the service");
        assert!(m.contains("exit code 2"), "{m}");
    }

    #[test]
    fn a_missing_binary_is_refused_before_any_prompt() {
        // Raising a consent dialog and then failing would be the worst of
        // both: the person approves something that cannot happen.
        let out = run_elevated(Path::new(r"Z:\nope\redoubtd.exe"), &["amsi-install"]);
        match out {
            Outcome::Failed { reason } => assert!(reason.contains("does not exist"), "{reason}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn redoubtd_is_found_beside_the_running_binary() {
        // In the test harness the running binary is the test executable, so
        // this only asserts the function does not panic and is honest about
        // not finding it.
        if let Some(p) = redoubtd_path() {
            assert!(p.is_file(), "{} should exist", p.display());
        }
    }
}
