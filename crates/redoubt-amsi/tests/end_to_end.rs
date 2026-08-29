//! The provider talking to a real service over a real pipe.
//!
//! `com_roundtrip.rs` proves the COM half: vtables, interface negotiation,
//! reading an `IAmsiStream`, verdict mapping. The service's own suite proves
//! the pipe half: a client connects, sends bytes, and the engine answers.
//!
//! Neither proves the join, and the join is where a security product either
//! decides something or quietly decides nothing. This starts an actual
//! `ScanServer` with a real index behind it and drives the provider's `Scan`
//! through the COM vtable, so a verdict has to travel the whole way:
//!
//! ```text
//!   Scan -> IAmsiStream -> named pipe -> engine -> pipe -> AMSI_RESULT_*
//! ```
//!
//! What is *not* covered here is Windows loading the DLL, which needs two
//! `HKLM` keys and administrator rights. That link is exercised by
//! `redoubtd amsi-install` and cannot be reached from a test.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use redoubt_amsi::client::{ask, Answer};
use redoubt_amsi::com::*;
use redoubt_amsi::DllGetClassObject;

use redoubt_core::config::Config;
use redoubt_core::hashing;
use redoubt_core::scanner::ScanEngine;
use redoubt_core::sigindex::{Group, IndexBuilder};
use redoubt_core::sigs::{HashSig, HashValue};
use redoubt_service::ipc;

/// Stands in for a malicious script. Deliberately *not* EICAR: Defender
/// quarantines EICAR the moment it reaches disk, and the fixture index has to
/// be written to disk to be memory-mapped.
const SCRIPT: &[u8] = b"$x = 'Redoubt end-to-end sample'; Invoke-Expression $x";

const NAME: &str = "Redoubt.Test.ScriptSample";

/// A one-signature index over [`SCRIPT`], plus an engine mapping it.
fn engine_for(dir: &std::path::Path) -> Arc<ScanEngine> {
    for sub in ["signatures", "rules", "quarantine", "logs", "cache"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }

    let mut b = IndexBuilder::new(9002, 0);
    b.add_hash(
        HashSig {
            hash: HashValue::from_hex(
                &hashing::digest_bytes(SCRIPT).sha256_value().to_string(),
            )
            .unwrap(),
            size: Some(SCRIPT.len() as u64),
            name: NAME.into(),
        },
        Group::File,
    );

    b.write(&dir.join("signatures/redoubt.sigidx")).unwrap();

    let mut cfg = Config::default();
    cfg.paths.signatures = dir.join("signatures");
    cfg.paths.rules = dir.join("rules");
    cfg.paths.quarantine = dir.join("quarantine");
    cfg.exclusions.paths = Vec::new();

    Arc::new(ScanEngine::load(cfg).unwrap())
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("redoubt-amsi-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

// ─────────────────────────── a minimal IAmsiStream ───────────────────────────

#[repr(C)]
struct Stream {
    vtbl: *const IAmsiStreamVtbl,
    refs: AtomicU32,
    content: Vec<u8>,
}

unsafe extern "system" fn qi(this: *mut c_void, _iid: *const Guid, out: *mut *mut c_void) -> Hresult {
    unsafe { *out = this };
    S_OK
}

unsafe extern "system" fn add_ref(this: *mut c_void) -> u32 {
    let s = unsafe { &*(this as *const Stream) };
    s.refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn release(this: *mut c_void) -> u32 {
    let s = unsafe { &*(this as *const Stream) };
    s.refs.fetch_sub(1, Ordering::Relaxed) - 1
}

unsafe extern "system" fn get_attribute(
    this: *mut c_void,
    attribute: u32,
    size: u32,
    data: *mut u8,
    written: *mut u32,
) -> Hresult {
    let s = unsafe { &*(this as *const Stream) };
    match attribute {
        AMSI_ATTRIBUTE_CONTENT_SIZE => {
            if size < 8 {
                return E_INVALIDARG;
            }
            let n = s.content.len() as u64;
            unsafe {
                std::ptr::copy_nonoverlapping(n.to_ne_bytes().as_ptr(), data, 8);
                *written = 8;
            }
            S_OK
        }
        AMSI_ATTRIBUTE_CONTENT_ADDRESS => {
            if size < std::mem::size_of::<usize>() as u32 {
                return E_INVALIDARG;
            }
            let addr = s.content.as_ptr() as usize;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    addr.to_ne_bytes().as_ptr(),
                    data,
                    std::mem::size_of::<usize>(),
                );
                *written = std::mem::size_of::<usize>() as u32;
            }
            S_OK
        }
        _ => E_INVALIDARG,
    }
}

unsafe extern "system" fn read(
    this: *mut c_void,
    position: u64,
    size: u32,
    buffer: *mut u8,
    got: *mut u32,
) -> Hresult {
    let s = unsafe { &*(this as *const Stream) };
    let start = position as usize;
    if start >= s.content.len() {
        unsafe { *got = 0 };
        return S_OK;
    }
    let n = (s.content.len() - start).min(size as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(s.content.as_ptr().add(start), buffer, n);
        *got = n as u32;
    }
    S_OK
}

static VTBL: IAmsiStreamVtbl = IAmsiStreamVtbl {
    base: IUnknownVtbl { query_interface: qi, add_ref, release },
    get_attribute,
    read,
};

fn stream(content: &[u8]) -> Box<Stream> {
    Box::new(Stream { vtbl: &VTBL, refs: AtomicU32::new(1), content: content.to_vec() })
}

/// Drive `Scan` the way AMSI does, through the vtable.
unsafe fn scan_through_com(content: &[u8]) -> u32 {
    let mut factory: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        DllGetClassObject(&CLSID_REDOUBT_PROVIDER, &IID_ICLASSFACTORY, &mut factory)
    };
    assert_eq!(hr, S_OK);

    let fvtbl = unsafe { &**(factory as *const *const IClassFactoryVtbl) };
    let mut provider: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        (fvtbl.create_instance)(
            factory,
            std::ptr::null_mut(),
            &IID_IANTIMALWARE_PROVIDER,
            &mut provider,
        )
    };
    assert_eq!(hr, S_OK);
    unsafe { (fvtbl.base.release)(factory) };

    let mut s = stream(content);
    let pvtbl = unsafe { &**(provider as *const *const IAntimalwareProviderVtbl) };
    let mut result: u32 = 0xDEAD_BEEF;
    let hr = unsafe {
        (pvtbl.scan)(provider, &mut *s as *mut Stream as *mut c_void, &mut result)
    };
    assert_eq!(hr, S_OK, "Scan must succeed at the COM level even when it blocks");

    unsafe { (pvtbl.base.release)(provider) };
    result
}

// ─────────────────────────── the tests ───────────────────────────

#[test]
fn a_malicious_script_is_blocked_through_the_whole_chain() {
    // Held for the duration: the pipe name is global, and the service's own
    // suite runs in a separate process that would otherwise bind it too.
    let _lock = ipc::testlock::acquire();

    let dir = temp_dir("blocked");
    let engine = engine_for(&dir);
    let mut server = ipc::ScanServer::start(engine).expect("the scan channel should bind");

    // Sanity: the client half agrees before COM is involved, so a failure
    // below points at the COM layer rather than at the pipe.
    match ask(SCRIPT) {
        Answer::Malicious { name } => assert_eq!(name, NAME),
        other => panic!("the service should have called this malicious, got {other:?}"),
    }

    let result = unsafe { scan_through_com(SCRIPT) };
    assert_eq!(
        result, AMSI_RESULT_DETECTED,
        "a signature match must block the script, not merely be logged"
    );

    let counters = server.counters();
    assert!(counters.requests.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    assert!(counters.malicious.load(std::sync::atomic::Ordering::Relaxed) >= 2);

    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_ordinary_script_runs() {
    let _lock = ipc::testlock::acquire();

    let dir = temp_dir("clean");
    let engine = engine_for(&dir);
    let mut server = ipc::ScanServer::start(engine).unwrap();

    let result = unsafe { scan_through_com(b"Get-ChildItem -Path C:\\ | Select-Object -First 5") };
    assert_eq!(
        result, AMSI_RESULT_NOT_DETECTED,
        "an unremarkable script must not be blocked"
    );

    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stopped_service_lets_scripts_run() {
    let _lock = ipc::testlock::acquire();

    let dir = temp_dir("stopped");
    let engine = engine_for(&dir);
    let mut server = ipc::ScanServer::start(engine).unwrap();
    server.stop();

    // The whole point of failing open. With Redoubt down, the machine keeps
    // working - including for content Redoubt would otherwise have blocked.
    let result = unsafe { scan_through_com(SCRIPT) };
    assert_eq!(
        result, AMSI_RESULT_NOT_DETECTED,
        "with no service, the provider must have no opinion rather than block"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
