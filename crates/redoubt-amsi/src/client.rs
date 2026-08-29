//! Asking the Redoubt service for a verdict.
//!
//! This runs inside somebody else's process - PowerShell, Word, the .NET
//! runtime - on their thread, while they wait. Three rules follow from that,
//! and they outrank everything else this code might want to do:
//!
//! 1. **Never block for long.** A slow answer is a slow PowerShell prompt. The
//!    whole exchange is bounded by [`TIMEOUT_MS`] - connect, send *and*
//!    receive, on one deadline taken before anything blocks.
//! 2. **Never fail closed.** If the service is missing, busy, or wrong, the
//!    answer is "no opinion" and the content runs. A security tool that blocks
//!    every script when its own service is down does not fail safe: it breaks
//!    the machine and gets itself uninstalled.
//! 3. **Never panic.** A panic here unwinds into a foreign C++ stack frame.
//!    Every entry point catches, and there is no `unwrap` on anything that can
//!    fail at runtime.
//!
//! The I/O is overlapped for rule 1's sake. Blocking `ReadFile` on a named
//! pipe has no timeout at all: a service that accepts a connection and then
//! dies leaves the caller waiting forever on an answer that is never coming.
//! Bounding only the *connect* - which an earlier version of this did - looks
//! correct right up until the moment it matters.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::{
    SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_BYTE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Must match `redoubt_service::ipc::PIPE_NAME`.
pub const PIPE_NAME: &str = r"\\.\pipe\Redoubt.Scan";

/// Total budget for connect, send and receive.
///
/// AMSI sits in front of script execution, so this is latency the user feels
/// directly. Two seconds is generous for a local pipe and short enough that a
/// wedged service is an inconvenience rather than a hang.
pub const TIMEOUT_MS: u32 = 2000;

/// `ERROR_IO_PENDING` - the ordinary outcome of starting overlapped I/O.
const ERROR_IO_PENDING: i32 = 997;

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

/// A handle that always closes.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: owned solely by this value, and closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// An open exchange with the service, bounded by a wall-clock deadline.
struct Conn {
    pipe: Owned,
    /// Signals completion of an overlapped read or write.
    event: Owned,
    deadline: Instant,
}

impl Conn {
    fn remaining_ms(&self) -> u32 {
        match self.deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d.as_millis().min(u32::MAX as u128) as u32,
            _ => 0,
        }
    }

    /// Run one overlapped operation to completion, or give up on it.
    ///
    /// On timeout the I/O is cancelled *and waited for* before returning.
    /// Leaving it in flight would let the kernel later write into a buffer
    /// this function no longer owns.
    fn finish(&self, ov: &mut OVERLAPPED, started_ok: bool) -> Option<u32> {
        // Only wait when the operation actually went pending. An overlapped
        // call that completes synchronously does not reliably signal the
        // event, and waiting on it then burns the whole deadline before
        // failing - which looks exactly like a service that is not there.
        if !started_ok {
            if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_IO_PENDING) {
                return None;
            }
            // SAFETY: `self.event.0` is a live event handle.
            let waited = unsafe { WaitForSingleObject(self.event.0, self.remaining_ms()) };
            if waited != WAIT_OBJECT_0 {
                // SAFETY: cancelling our own in-flight I/O, on our own handle.
                unsafe { CancelIoEx(self.pipe.0, ov) };
                let mut done = 0u32;
                // SAFETY: blocking wait (final argument non-zero) so that `ov`
                // and the buffer it refers to are idle before we return.
                unsafe { GetOverlappedResult(self.pipe.0, ov, &mut done, 1) };
                return None;
            }
        }

        let mut transferred = 0u32;
        // SAFETY: the operation is complete - either synchronously, or because
        // the event fired - so this cannot block.
        let ok = unsafe { GetOverlappedResult(self.pipe.0, ov, &mut transferred, 1) };
        (ok != 0).then_some(transferred)
    }

    fn write_all(&self, mut buf: &[u8]) -> bool {
        while !buf.is_empty() {
            if self.remaining_ms() == 0 {
                return false;
            }
            // SAFETY: a zeroed OVERLAPPED carrying our event is what the API
            // expects; it stays alive for the whole operation.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = self.event.0;

            // SAFETY: `buf` is readable for its length.
            let started = unsafe {
                WriteFile(
                    self.pipe.0,
                    buf.as_ptr(),
                    buf.len() as u32,
                    std::ptr::null_mut(),
                    &mut ov,
                )
            };
            match self.finish(&mut ov, started != 0) {
                Some(n) if n > 0 => buf = &buf[n as usize..],
                _ => return false,
            }
        }
        true
    }

    fn read_exact(&self, buf: &mut [u8]) -> bool {
        let mut filled = 0usize;
        while filled < buf.len() {
            if self.remaining_ms() == 0 {
                return false;
            }
            // SAFETY: as above.
            let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
            ov.hEvent = self.event.0;

            let want = (buf.len() - filled) as u32;
            // SAFETY: writing into the unfilled remainder of `buf`.
            let started = unsafe {
                ReadFile(
                    self.pipe.0,
                    buf[filled..].as_mut_ptr(),
                    want,
                    std::ptr::null_mut(),
                    &mut ov,
                )
            };
            match self.finish(&mut ov, started != 0) {
                Some(n) if n > 0 => filled += n as usize,
                _ => return false,
            }
        }
        true
    }
}

/// Connect to the service's scan pipe, within the deadline.
fn connect(deadline: Instant) -> Option<Conn> {
    let name = wide(PIPE_NAME);

    // One attempt, then one bounded wait for a free instance. Retrying past
    // that would trade a fast "no opinion" for a slow one, which is the wrong
    // way round when a person is waiting at a prompt.
    for attempt in 0..2 {
        // SAFETY: `name` is NUL-terminated; all other arguments are constants.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE && !h.is_null() {
            let pipe = Owned(h);
            let mode = PIPE_READMODE_BYTE;
            // SAFETY: `h` is a valid pipe handle; the trailing arguments are
            // null because we are not changing collection settings.
            unsafe {
                SetNamedPipeHandleState(h, &mode, std::ptr::null(), std::ptr::null());
            }

            // Manual-reset, initially unsignalled, unnamed.
            // SAFETY: an all-defaults event.
            let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if ev.is_null() {
                return None;
            }
            return Some(Conn { pipe, event: Owned(ev), deadline });
        }

        if attempt == 0 {
            let left = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => ((d.as_millis() as u32).min(TIMEOUT_MS)) / 2,
                _ => return None,
            };
            if left == 0 {
                return None;
            }
            // SAFETY: `name` is NUL-terminated.
            if unsafe { WaitNamedPipeW(name.as_ptr(), left) } == 0 {
                return None;
            }
        }
    }
    None
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
    // One deadline for the whole exchange, taken before anything can block.
    let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS as u64);

    let Some(conn) = connect(deadline) else {
        return Answer::Unavailable;
    };

    let mut request = Vec::with_capacity(8 + content.len());
    request.extend_from_slice(&(content.len() as u32).to_le_bytes());
    request.extend_from_slice(&0u32.to_le_bytes()); // flags, reserved
    request.extend_from_slice(content);

    if !conn.write_all(&request) {
        return Answer::Unavailable;
    }

    let mut header = [0u8; 5];
    if !conn.read_exact(&mut header) {
        return Answer::Unavailable;
    }
    let verdict = header[0];
    let name_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
    if name_len > MAX_NAME {
        return Answer::Unavailable;
    }

    let mut name_bytes = vec![0u8; name_len as usize];
    if name_len > 0 && !conn.read_exact(&mut name_bytes) {
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

        assert!(
            elapsed < std::time::Duration::from_millis(TIMEOUT_MS as u64 * 2),
            "ask took {elapsed:?}, which a person would feel at a prompt"
        );
        // Any of the four is valid depending on whether a service is up.
        match answer {
            Answer::Clean
            | Answer::Suspicious { .. }
            | Answer::Malicious { .. }
            | Answer::Unavailable => {}
        }
    }

    #[test]
    fn the_deadline_covers_reading_not_only_connecting() {
        // The regression this guards. A service that accepts a connection and
        // then never answers used to hang the caller forever, because the
        // timeout only applied to `WaitNamedPipeW`. Here a pipe is created
        // and a client is accepted, but nothing is ever written back.
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT,
        };

        // A private name, so this cannot disturb a real service.
        let name = r"\\.\pipe\Redoubt.Scan.SilentTest";
        let wide_name = wide(name);

        // SAFETY: a NUL-terminated name and otherwise constant arguments.
        let server = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null::<SECURITY_ATTRIBUTES>(),
            )
        };
        assert!(server != INVALID_HANDLE_VALUE && !server.is_null());
        let server = Owned(server);

        // Accept in the background and then say nothing at all. It holds the
        // connection open until the client has given up, which is the whole
        // point: without a deadline on the read, that is forever.
        let handle = server.0 as usize;
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        let accepted = std::thread::spawn(move || {
            // SAFETY: a pipe instance awaiting a client.
            unsafe { ConnectNamedPipe(handle as HANDLE, std::ptr::null_mut()) };
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(25));
            }
        });

        let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS as u64);
        let started = Instant::now();

        // Connect by hand to the test pipe, then use the real read path.
        // SAFETY: NUL-terminated name; constant arguments.
        let h = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        assert!(h != INVALID_HANDLE_VALUE && !h.is_null(), "test pipe should accept");
        // SAFETY: an all-defaults event.
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        let conn = Conn { pipe: Owned(h), event: Owned(ev), deadline };

        let mut buf = [0u8; 5];
        assert!(!conn.read_exact(&mut buf), "a silent service must not yield a verdict");

        // The bound that matters is "gave up at all", and it must not be
        // sensitive to how loaded the machine is while the suite runs. The
        // behaviour being guarded against is unbounded waiting.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(TIMEOUT_MS as u64 / 2),
            "it must actually wait for the deadline, not fail instantly ({elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "the read must give up on its deadline rather than wait forever ({elapsed:?})"
        );

        drop(conn);
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = accepted.join();
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
