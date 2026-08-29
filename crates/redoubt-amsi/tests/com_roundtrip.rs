//! Drive the provider exactly the way AMSI does.
//!
//! Registration needs administrator rights and a host that actually invokes
//! AMSI, so it cannot be exercised in a unit test. What *can* be exercised is
//! everything up to that point: the class factory, the interface negotiation,
//! the vtable layout, reading an `IAmsiStream`, and the verdict mapping.
//!
//! This builds a fake `IAmsiStream` with a hand-written vtable and calls
//! through the real exported entry points. If the vtable field order is wrong,
//! or a method's signature does not match the IDL, this crashes or returns
//! nonsense - which is the whole point.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

use redoubt_amsi::com::*;
use redoubt_amsi::{DllCanUnloadNow, DllGetClassObject};

// ─────────────────────────── a fake IAmsiStream ───────────────────────────

#[repr(C)]
struct FakeStream {
    vtbl: *const IAmsiStreamVtbl,
    refs: AtomicU32,
    content: Vec<u8>,
    /// When false, `GetAttribute(CONTENT_ADDRESS)` fails so the provider has
    /// to fall back to `Read`. Both paths occur with real hosts.
    offer_address: bool,
    reads: AtomicU32,
}

unsafe extern "system" fn stream_qi(
    this: *mut c_void,
    _iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    unsafe {
        *out = this;
    }
    S_OK
}

unsafe extern "system" fn stream_add_ref(this: *mut c_void) -> u32 {
    let s = unsafe { &*(this as *const FakeStream) };
    s.refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn stream_release(this: *mut c_void) -> u32 {
    let s = unsafe { &*(this as *const FakeStream) };
    s.refs.fetch_sub(1, Ordering::Relaxed) - 1
}

unsafe extern "system" fn stream_get_attribute(
    this: *mut c_void,
    attribute: u32,
    size: u32,
    data: *mut u8,
    written: *mut u32,
) -> Hresult {
    let s = unsafe { &*(this as *const FakeStream) };
    match attribute {
        AMSI_ATTRIBUTE_CONTENT_SIZE => {
            if size < 8 {
                return E_INVALIDARG;
            }
            let len = s.content.len() as u64;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &len as *const u64 as *const u8,
                    data,
                    8,
                );
                *written = 8;
            }
            S_OK
        }
        AMSI_ATTRIBUTE_CONTENT_ADDRESS => {
            if !s.offer_address {
                return E_INVALIDARG;
            }
            let ptr = s.content.as_ptr();
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &ptr as *const *const u8 as *const u8,
                    data,
                    std::mem::size_of::<*const u8>(),
                );
                *written = std::mem::size_of::<*const u8>() as u32;
            }
            S_OK
        }
        _ => E_INVALIDARG,
    }
}

unsafe extern "system" fn stream_read(
    this: *mut c_void,
    position: u64,
    size: u32,
    buffer: *mut u8,
    read: *mut u32,
) -> Hresult {
    let s = unsafe { &*(this as *const FakeStream) };
    s.reads.fetch_add(1, Ordering::Relaxed);

    let start = position as usize;
    if start >= s.content.len() {
        unsafe { *read = 0 };
        return S_OK;
    }
    let n = (s.content.len() - start).min(size as usize);
    unsafe {
        std::ptr::copy_nonoverlapping(s.content[start..].as_ptr(), buffer, n);
        *read = n as u32;
    }
    S_OK
}

static STREAM_VTBL: IAmsiStreamVtbl = IAmsiStreamVtbl {
    base: IUnknownVtbl {
        query_interface: stream_qi,
        add_ref: stream_add_ref,
        release: stream_release,
    },
    get_attribute: stream_get_attribute,
    read: stream_read,
};

fn fake_stream(content: &[u8], offer_address: bool) -> Box<FakeStream> {
    Box::new(FakeStream {
        vtbl: &STREAM_VTBL,
        refs: AtomicU32::new(1),
        content: content.to_vec(),
        offer_address,
        reads: AtomicU32::new(0),
    })
}

// ─────────────────────────── helpers ───────────────────────────

/// Obtain an `IAntimalwareProvider` the way COM would.
unsafe fn create_provider() -> *mut c_void {
    let mut factory: *mut c_void = std::ptr::null_mut();
    let hr = unsafe {
        DllGetClassObject(
            &CLSID_REDOUBT_PROVIDER,
            &IID_ICLASSFACTORY,
            &mut factory,
        )
    };
    assert_eq!(hr, S_OK, "DllGetClassObject should hand out a class factory");
    assert!(!factory.is_null());

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
    assert_eq!(hr, S_OK, "CreateInstance should produce a provider");
    assert!(!provider.is_null());

    unsafe { (fvtbl.base.release)(factory) };
    provider
}

unsafe fn scan(provider: *mut c_void, stream: &mut FakeStream) -> u32 {
    let vtbl = unsafe { &**(provider as *const *const IAntimalwareProviderVtbl) };
    let mut result: u32 = 0xDEAD_BEEF;
    let hr = unsafe {
        (vtbl.scan)(
            provider,
            stream as *mut FakeStream as *mut c_void,
            &mut result,
        )
    };
    assert_eq!(hr, S_OK, "Scan should always succeed at the COM level");
    result
}

unsafe fn release(provider: *mut c_void) {
    let vtbl = unsafe { &**(provider as *const *const IAntimalwareProviderVtbl) };
    unsafe { (vtbl.base.release)(provider) };
}

// ─────────────────────────── the tests ───────────────────────────

#[test]
fn the_class_factory_produces_a_working_provider() {
    unsafe {
        let provider = create_provider();

        // DisplayName must hand back a CoTaskMem string the caller can free.
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);
        let mut name: *mut u16 = std::ptr::null_mut();
        assert_eq!((vtbl.display_name)(provider, &mut name), S_OK);
        assert!(!name.is_null());

        let mut len = 0;
        while *name.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(name, len));
        assert_eq!(text, "Redoubt");
        windows_sys::Win32::System::Com::CoTaskMemFree(name as *mut c_void);

        release(provider);
    }
}

#[test]
fn an_unknown_class_id_is_refused() {
    let other = Guid::new(0x1234_5678, 0x1111, 0x2222, [0; 8]);
    let mut out: *mut c_void = std::ptr::null_mut();
    let hr = unsafe { DllGetClassObject(&other, &IID_ICLASSFACTORY, &mut out) };
    assert_eq!(hr, CLASS_E_CLASSNOTAVAILABLE);
    assert!(out.is_null(), "the out pointer must be cleared on failure");
}

#[test]
fn an_unsupported_interface_is_refused() {
    let mut out: *mut c_void = std::ptr::null_mut();
    let odd = Guid::new(0xDEAD_BEEF, 0, 0, [0; 8]);
    let hr = unsafe { DllGetClassObject(&CLSID_REDOUBT_PROVIDER, &odd, &mut out) };
    assert_eq!(hr, E_NOINTERFACE);
    assert!(out.is_null());
}

#[test]
fn aggregation_is_refused_rather_than_ignored() {
    // Silently ignoring the outer unknown corrupts the caller's reference
    // counting in ways that surface much later and elsewhere.
    unsafe {
        let mut factory: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            DllGetClassObject(&CLSID_REDOUBT_PROVIDER, &IID_ICLASSFACTORY, &mut factory),
            S_OK
        );
        let fvtbl = &**(factory as *const *const IClassFactoryVtbl);

        let mut outer = 0u8;
        let mut out: *mut c_void = std::ptr::null_mut();
        let hr = (fvtbl.create_instance)(
            factory,
            &mut outer as *mut u8 as *mut c_void,
            &IID_IANTIMALWARE_PROVIDER,
            &mut out,
        );
        assert_eq!(hr, CLASS_E_NOAGGREGATION);
        assert!(out.is_null());

        (fvtbl.base.release)(factory);
    }
}

#[test]
fn scanning_reads_content_through_the_address_attribute() {
    unsafe {
        let provider = create_provider();
        let mut stream = fake_stream(b"Write-Host 'ordinary'", true);
        let result = scan(provider, &mut stream);

        // With no service running this is NOT_DETECTED; with one running and
        // the content clean it is also NOT_DETECTED. Either way it must never
        // be left as the caller's uninitialised value.
        assert_ne!(result, 0xDEAD_BEEF, "Scan must always write a result");
        assert!(result == AMSI_RESULT_NOT_DETECTED || result == AMSI_RESULT_CLEAN);
        // The fast path was available, so Read should not have been needed.
        assert_eq!(stream.reads.load(Ordering::Relaxed), 0);

        release(provider);
    }
}

#[test]
fn scanning_falls_back_to_read_when_no_address_is_offered() {
    // Hosts differ. A provider that only handles the address path silently
    // sees nothing from the others.
    unsafe {
        let provider = create_provider();
        let mut stream = fake_stream(b"Write-Host 'ordinary'", false);
        let result = scan(provider, &mut stream);

        assert_ne!(result, 0xDEAD_BEEF);
        assert!(
            stream.reads.load(Ordering::Relaxed) > 0,
            "the Read path should have been used"
        );

        release(provider);
    }
}

#[test]
fn an_empty_stream_is_not_detected() {
    unsafe {
        let provider = create_provider();
        let mut stream = fake_stream(b"", true);
        assert_eq!(scan(provider, &mut stream), AMSI_RESULT_NOT_DETECTED);
        release(provider);
    }
}

#[test]
fn a_null_stream_does_not_crash_and_does_not_block() {
    // AMSI should never do this, but a provider that faults on bad input takes
    // PowerShell down with it.
    unsafe {
        let provider = create_provider();
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);
        let mut result = 0xDEAD_BEEFu32;
        assert_eq!((vtbl.scan)(provider, std::ptr::null_mut(), &mut result), S_OK);
        assert_eq!(result, AMSI_RESULT_NOT_DETECTED, "must fail open");
        release(provider);
    }
}

#[test]
fn a_null_result_pointer_is_refused_rather_than_written_through() {
    unsafe {
        let provider = create_provider();
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);
        let mut stream = fake_stream(b"x", true);
        let hr = (vtbl.scan)(
            provider,
            &mut *stream as *mut FakeStream as *mut c_void,
            std::ptr::null_mut(),
        );
        assert_eq!(hr, E_POINTER);
        release(provider);
    }
}

#[test]
fn close_session_is_callable_and_returns_nothing() {
    // CloseSession returns void, not HRESULT. If the vtable declared it wrong
    // the call would read a garbage register as a result.
    unsafe {
        let provider = create_provider();
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);
        (vtbl.close_session)(provider, 12345);
        (vtbl.close_session)(provider, 0);
        release(provider);
    }
}

#[test]
fn the_dll_reports_it_cannot_unload_while_an_object_lives() {
    // Unloading while a vtable pointer is still live crashes the host on its
    // next call.
    unsafe {
        let provider = create_provider();
        assert_eq!(DllCanUnloadNow(), S_FALSE, "an object is still alive");
        release(provider);
        assert_eq!(DllCanUnloadNow(), S_OK, "everything has been released");
    }
}

#[test]
fn reference_counting_balances() {
    unsafe {
        let provider = create_provider();
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);

        assert_eq!((vtbl.base.add_ref)(provider), 2);
        assert_eq!((vtbl.base.add_ref)(provider), 3);
        assert_eq!((vtbl.base.release)(provider), 2);
        assert_eq!((vtbl.base.release)(provider), 1);
        assert_eq!((vtbl.base.release)(provider), 0, "the last release frees it");

        assert_eq!(DllCanUnloadNow(), S_OK);
    }
}

#[test]
fn querying_iunknown_from_the_provider_works() {
    unsafe {
        let provider = create_provider();
        let vtbl = &**(provider as *const *const IAntimalwareProviderVtbl);

        let mut unk: *mut c_void = std::ptr::null_mut();
        assert_eq!((vtbl.base.query_interface)(provider, &IID_IUNKNOWN, &mut unk), S_OK);
        assert!(!unk.is_null());
        // QueryInterface took a reference of its own.
        (vtbl.base.release)(unk);

        release(provider);
    }
}
