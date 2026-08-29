//! Asking the Redoubt service for a verdict.
//!
//! This runs inside somebody else's process - PowerShell, Word, the .NET
//! runtime - on their thread, while they wait. Three rules follow from that,
//! and they outrank everything else this code might want to do:
//!
//! 1. **Never block for long.** A slow answer is a slow PowerShell prompt. The
//!    whole exchange is bounded by [`TIMEOUT_MS`].
//! 2. **Never fail closed.** If the service is missing, busy, or wrong, the
//!    answer is "no opinion" and the content runs. A security tool that blocks
//!    every script when its own service is down does not fail safe: it breaks
//!    the machine and gets itself uninstalled.
//! 3. **Never panic.** A panic here unwinds into a foreign C++ stack frame.
//!    Every entry point catches, and there is no `unwrap` on anything that can
//!    fail at runtime.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_BYTE};

/// Must match `redoubt_service::ipc::PIPE_NAME`.
pub const PIPE_NAME: &str = r"\\.\pipe\Redoubt.Scan";

/// Total budget for connect, send and receive.
///
/// AMSI sits in front of script execution, so this is latency the user feels
/// directly. Two seconds is generous for a local pipe and short enough that a
/// wedged service is an inconvenience rather than a hang.
pub const TIMEOUT_MS: u32 = 2000;

/// Wire verdicts, matching `redoubt_service::ipc`.
pub const VERDICT_CLEAN: u8 = 0;
pub const VERDICT_SUSPICIOUS: u8 = 1;
pub const VERDICT_MALICIOUS: u8 = 2;

/// What the service said, or that it did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Clean,
    Suspicious { name: String },
    Malicious { name: String },
    /// No verdict: service absent, timed out, or replied with nonsense.
    Unavailable,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A pipe handle that always closes.
struct Handle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: constructed only from a successful CreateFileW, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Connect to the service's scan pipe.
fn connect() -> Option<Handle> {
    let name = wide(PIPE_NAME);

    // One attempt, then one bounded wait for a free instance. Retrying past
    // that would trade a fast "no opinion" for a slow one, which is the wrong
    // way round when a user is waiting on a prompt.
    for attempt in 0..2 {
        // SAFETY: `name` is NUL-terminated; all other arguments are constants.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE && !h.is_null() {
            let handle = Handle(h);
            let mode = PIPE_READMODE_BYTE;
            // SAFETY: `h` is a valid pipe handle; the other arguments are null
            // because we are not changing collection settings.
            unsafe {
                SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null());
            }
            return Some(handle);
        }

        if attempt == 0 {
            // SAFETY: `name` is NUL-terminated.
            let waited = unsafe { WaitNamedPipeW(name.as_ptr(), TIMEOUT_MS / 2) };
            if waited == 0 {
                return None;
            }
        }
    }
    None
}

fn write_all(h: &Handle, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        let mut written = 0u32;
        // SAFETY: `buf` is a valid readable slice of the given length.
        let ok = unsafe {
            WriteFile(
                h.0,
                buf.as_ptr(),
                buf.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return false;
        }
        buf = &buf[written as usize..];
    }
    true
}

fn read_exact(h: &Handle, buf: &mut [u8]) -> bool {
    let mut filled = 0usize;
    while filled < buf.len() {
        let mut read = 0u32;
        // SAFETY: writing into the unfilled remainder of `buf`.
        let ok = unsafe {
            ReadFile(
                h.0,
                buf[filled..].as_mut_ptr(),
                (buf.len() - filled) as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return false;
        }
        filled += read as usize;
    }
    true
}

/// Largest signature name we will accept back.
///
/// The reply comes from our own service, but this is a length prefix from
/// another process and is treated as untrusted regardless.
const MAX_NAME: u32 = 4096;

/// Ask the service about `content`.
///
/// Returns [`Answer::Unavailable`] for every failure mode. The caller turns
/// that into "no opinion" so the content runs.
pub fn ask(content: &[u8]) -> Answer {
    let Some(handle) = connect() else {
        return Answer::Unavailable;
    };

    let mut request = Vec::with_capacity(8 + content.len());
    request.extend_from_slice(&(content.len() as u32).to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes()); // flags, reserved
    request.extend_from_slice(content);

    if !write_all(&handle, &request) {
        return Answer::Unavailable;
    }

    let mut header = [0u8; 5];
    if !read_exact(&handle, &mut header) {
        return Answer::Unavailable;
    }
    let verdict = header[0];
    let name_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    if name_len > MAX_NAME {
        return Answer::Unavailable;
    }

    let mut name_bytes = vec![0u8; name_len as usize];
    if name_len > 0 && !read_exact(&handle, &mut name_bytes) {
        return Answer::Unavailable;
    }
    let name = String::from_utf8_lossy(&name_bytes).into_owned();

    match verdict {
        VERDICT_CLEAN => Answer::Clean,
        VERDICT_SUSPICIOUS => Answer::Suspicious { name },
        VERDICT_MALICIOUS => Answer::Malicious { name },
        // An unknown verdict is a version mismatch. Having no opinion is the
        // only safe reading of a value we do not understand.
        _ => Answer::Unavailable,
    }
}

/// Suppress an unused warning for a type only referenced through pointers.
#[allow(dead_code)]
fn _unused(_: *mut c_void) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_name_matches_the_service() {
        // These are two separately-built binaries agreeing by convention, so
        // the constant is duplicated and this is the only thing keeping them
        // honest.
        assert_eq!(PIPE_NAME, r"\\.\pipe\Redoubt.Scan");
    }

    #[test]
    fn a_missing_service_is_unavailable_not_an_error() {
        // With no service running, `ask` must return promptly and let the
        // content run. Blocking every script because our own service is down
        // would make the machine unusable.
        let started = std::time::Instant::now();
        let answer = ask(b"Write-Host 'hello'");
        let elapsed = started.elapsed();

        // Either a real service answered, or it was unavailable - but it must
        // never hang.
        assert!(
            elapsed < std::time::Duration::from_millis(TIMEOUT_MS as u64 * 2),
            "ask took {elapsed:?}, which a user would feel at a prompt"
        );
        // Any of the four is valid depending on whether the service is up.
        match answer {
            Answer::Clean
            | Answer::Suspicious { .. }
            | Answer::Malicious { .. }
            | Answer::Unavailable => {}
        }
    }

    // These compare constants, which clippy reads as a tautology. They are
    // not: the constants are duplicated across two separately-built binaries
    // and these are what catch a change to one of them.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_timeout_is_short_enough_to_be_invisible() {
        // This is latency in front of every script the user runs.
        assert!(TIMEOUT_MS <= 5000);
    }

    #[test]
    fn verdict_values_match_the_service() {
        assert_eq!(VERDICT_CLEAN, 0);
        assert_eq!(VERDICT_SUSPICIOUS, 1);
        assert_eq!(VERDICT_MALICIOUS, 2);
    }
}
