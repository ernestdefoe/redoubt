//! Redoubt's AMSI provider.
//!
//! AMSI is the one place Windows will let a scanner see a script **before it
//! runs**, without a kernel driver. PowerShell, VBScript, JScript, Office VBA
//! and the .NET runtime all hand their content to registered providers and
//! honour a block. That makes this the only pre-execution defence Redoubt has,
//! and it covers the vector most consumer infections actually arrive through.
//!
//! # This DLL is a guest in other people's processes
//!
//! It is loaded into PowerShell, Word, Excel and any .NET host. Everything
//! about its design follows from that:
//!
//! - **It holds no engine.** The signature index is hundreds of megabytes; a
//!   copy per host process would be ruinous. Content goes down a named pipe to
//!   the Redoubt service, which owns the one engine on the machine.
//! - **It never panics.** Unwinding into a foreign C++ frame is undefined
//!   behaviour, so every COM entry point is wrapped in `catch_unwind`.
//! - **It fails open.** Any problem at all (no service, a timeout, a malformed
//!   reply) yields `AMSI_RESULT_NOT_DETECTED`, and the content runs. A
//!   provider that blocks everything when its own service is down does not
//!   fail safe: it breaks the machine and gets itself uninstalled.
//!
//! # Registration
//!
//! Two registry keys, both under `HKLM` and both needing administrator rights:
//! the COM class under `CLSID`, and the class id listed under
//! `SOFTWARE\Microsoft\AMSI\Providers`. `redoubtd amsi-install` writes both.

#![allow(clippy::missing_safety_doc)]

pub mod client;
pub mod com;

use std::ffi::c_void;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU32, Ordering};

use com::*;

/// Largest content we will pull out of a stream.
///
/// AMSI submits script text and macro bodies. Something far larger is either
/// not a script or is an attempt to make this allocate; either way the honest
/// answer is that we have no opinion.
const MAX_CONTENT: u64 = 16 * 1024 * 1024;

/// Run a COM entry point, converting any panic into an HRESULT.
///
/// Unwinding across the FFI boundary into the host's C++ frames is undefined
/// behaviour and would take PowerShell down with it.
fn guard<F: FnOnce() -> Hresult>(f: F) -> Hresult {
    std::panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or(E_POINTER)
}

// ───────────────────────────── the provider ─────────────────────────────

#[repr(C)]
struct Provider {
    vtbl: *const IAntimalwareProviderVtbl,
    refs: AtomicU32,
}

static PROVIDER_VTBL: IAntimalwareProviderVtbl = IAntimalwareProviderVtbl {
    base: IUnknownVtbl {
        query_interface: provider_query_interface,
        add_ref: provider_add_ref,
        release: provider_release,
    },
    scan: provider_scan,
    close_session: provider_close_session,
    display_name: provider_display_name,
};

impl Provider {
    fn new() -> *mut Provider {
        com::object_added();
        Box::into_raw(Box::new(Provider {
            vtbl: &PROVIDER_VTBL,
            refs: AtomicU32::new(1),
        }))
    }
}

unsafe extern "system" fn provider_query_interface(
    this: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    guard(|| {
        if out.is_null() {
            return E_POINTER;
        }
        // SAFETY: the caller guarantees `out` is a writable pointer slot.
        unsafe { *out = std::ptr::null_mut() };
        if iid.is_null() {
            return E_POINTER;
        }
        // SAFETY: the caller guarantees `iid` points at a GUID.
        let iid = unsafe { *iid };

        if iid == IID_IUNKNOWN || iid == IID_IANTIMALWARE_PROVIDER {
            // SAFETY: `this` is a Provider we handed out.
            unsafe {
                provider_add_ref(this);
                *out = this;
            }
            S_OK
        } else {
            E_NOINTERFACE
        }
    })
}

unsafe extern "system" fn provider_add_ref(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a Provider allocated by `Provider::new`.
    let p = unsafe { &*(this as *const Provider) };
    p.refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn provider_release(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a Provider allocated by `Provider::new`.
    let p = unsafe { &*(this as *const Provider) };
    let remaining = p.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if remaining == 0 {
        // SAFETY: the last reference has gone, so nothing else can observe it.
        unsafe { drop(Box::from_raw(this as *mut Provider)) };
        com::object_removed();
    }
    remaining
}

/// Pull the content out of an `IAmsiStream`.
///
/// AMSI offers two routes. `CONTENT_ADDRESS` is a pointer to a buffer the host
/// already holds, which costs nothing to use. When that is absent the content
/// must be pulled through `Read` in chunks. Both are supported because hosts
/// differ, and a provider that only handles one silently sees nothing from the
/// other.
unsafe fn read_content(stream: *mut c_void) -> Option<Vec<u8>> {
    if stream.is_null() {
        return None;
    }
    // SAFETY: AMSI guarantees `stream` points at an IAmsiStream.
    let vtbl = unsafe { &**(stream as *const *const IAmsiStreamVtbl) };

    // Size first: without it there is nothing to bound a read by.
    let mut size: u64 = 0;
    let mut written: u32 = 0;
    // SAFETY: `size` is a u64 with room for the 8 bytes requested.
    let hr = unsafe {
        (vtbl.get_attribute)(
            stream,
            AMSI_ATTRIBUTE_CONTENT_SIZE,
            8,
            &mut size as *mut u64 as *mut u8,
            &mut written,
        )
    };
    if hr != S_OK || written != 8 || size == 0 || size > MAX_CONTENT {
        return None;
    }
    let size_usize = size as usize;

    // Fast path: the host already has the bytes in memory.
    let mut address: *const u8 = std::ptr::null();
    let mut addr_written: u32 = 0;
    // SAFETY: `address` is a pointer-sized slot.
    let hr = unsafe {
        (vtbl.get_attribute)(
            stream,
            AMSI_ATTRIBUTE_CONTENT_ADDRESS,
            std::mem::size_of::<*const u8>() as u32,
            &mut address as *mut *const u8 as *mut u8,
            &mut addr_written,
        )
    };
    if hr == S_OK && !address.is_null() && addr_written as usize == std::mem::size_of::<*const u8>()
    {
        // SAFETY: AMSI guarantees the buffer is valid for `size` bytes for the
        // duration of the Scan call.
        let slice = unsafe { std::slice::from_raw_parts(address, size_usize) };
        return Some(slice.to_vec());
    }

    // Slow path: read it through.
    let mut buf = vec![0u8; size_usize];
    let mut filled = 0usize;
    while filled < size_usize {
        let want = (size_usize - filled).min(64 * 1024) as u32;
        let mut got: u32 = 0;
        // SAFETY: writing into the unfilled remainder of `buf`.
        let hr = unsafe {
            (vtbl.read)(
                stream,
                filled as u64,
                want,
                buf[filled..].as_mut_ptr(),
                &mut got,
            )
        };
        if hr != S_OK || got == 0 {
            break;
        }
        filled += got as usize;
    }
    if filled == 0 {
        return None;
    }
    buf.truncate(filled);
    Some(buf)
}

unsafe extern "system" fn provider_scan(
    _this: *mut c_void,
    stream: *mut c_void,
    result: *mut u32,
) -> Hresult {
    guard(|| {
        if result.is_null() {
            return E_POINTER;
        }
        // Set the fail-open answer *first*, so every early return below leaves
        // a valid verdict behind rather than whatever the caller's memory held.
        // SAFETY: the caller guarantees `result` is writable.
        unsafe { *result = AMSI_RESULT_NOT_DETECTED };

        // SAFETY: `stream` is checked for null inside.
        let Some(content) = (unsafe { read_content(stream) }) else {
            return S_OK;
        };

        match client::ask(&content) {
            client::Answer::Malicious { .. } => {
                // SAFETY: as above.
                unsafe { *result = AMSI_RESULT_DETECTED };
            }
            // Suspicious deliberately does not block. Heuristic and PUA
            // findings reach that level, and blocking a script on a heuristic
            // is how a provider gets a reputation for breaking things. It is
            // still recorded by the service that produced it.
            client::Answer::Suspicious { .. } | client::Answer::Clean => {
                unsafe { *result = AMSI_RESULT_NOT_DETECTED };
            }
            client::Answer::Unavailable => {
                unsafe { *result = AMSI_RESULT_NOT_DETECTED };
            }
        }
        S_OK
    })
}

unsafe extern "system" fn provider_close_session(_this: *mut c_void, _session: u64) {
    // Nothing is kept between calls: each Scan is a complete question and a
    // complete answer, so there is no session state to release.
}

unsafe extern "system" fn provider_display_name(
    _this: *mut c_void,
    out: *mut *mut u16,
) -> Hresult {
    guard(|| {
        if out.is_null() {
            return E_POINTER;
        }
        let name = com::co_task_mem_wide("Redoubt");
        if name.is_null() {
            return E_OUTOFMEMORY;
        }
        // SAFETY: the caller guarantees `out` is a writable pointer slot and
        // takes ownership of the CoTaskMem allocation.
        unsafe { *out = name };
        S_OK
    })
}

// ───────────────────────────── class factory ─────────────────────────────

#[repr(C)]
struct ClassFactory {
    vtbl: *const IClassFactoryVtbl,
    refs: AtomicU32,
}

static FACTORY_VTBL: IClassFactoryVtbl = IClassFactoryVtbl {
    base: IUnknownVtbl {
        query_interface: factory_query_interface,
        add_ref: factory_add_ref,
        release: factory_release,
    },
    create_instance: factory_create_instance,
    lock_server: factory_lock_server,
};

unsafe extern "system" fn factory_query_interface(
    this: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    guard(|| {
        if out.is_null() {
            return E_POINTER;
        }
        // SAFETY: caller guarantees a writable slot.
        unsafe { *out = std::ptr::null_mut() };
        if iid.is_null() {
            return E_POINTER;
        }
        // SAFETY: caller guarantees `iid` points at a GUID.
        let iid = unsafe { *iid };

        if iid == IID_IUNKNOWN || iid == IID_ICLASSFACTORY {
            // SAFETY: `this` is a ClassFactory we handed out.
            unsafe {
                factory_add_ref(this);
                *out = this;
            }
            S_OK
        } else {
            E_NOINTERFACE
        }
    })
}

unsafe extern "system" fn factory_add_ref(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a ClassFactory.
    let f = unsafe { &*(this as *const ClassFactory) };
    f.refs.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn factory_release(this: *mut c_void) -> u32 {
    // SAFETY: `this` is a ClassFactory.
    let f = unsafe { &*(this as *const ClassFactory) };
    let remaining = f.refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if remaining == 0 {
        // SAFETY: last reference gone.
        unsafe { drop(Box::from_raw(this as *mut ClassFactory)) };
        com::object_removed();
    }
    remaining
}

unsafe extern "system" fn factory_create_instance(
    _this: *mut c_void,
    outer: *mut c_void,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    guard(|| {
        if out.is_null() {
            return E_POINTER;
        }
        // SAFETY: caller guarantees a writable slot.
        unsafe { *out = std::ptr::null_mut() };

        // Aggregation is not supported, and saying so is required rather than
        // optional: silently ignoring the outer unknown corrupts the caller's
        // reference counting.
        if !outer.is_null() {
            return CLASS_E_NOAGGREGATION;
        }
        if iid.is_null() {
            return E_POINTER;
        }

        let provider = Provider::new();
        // SAFETY: `provider` was just created with one reference.
        let hr = unsafe { provider_query_interface(provider as *mut c_void, iid, out) };
        // Drop the creation reference; QueryInterface took its own.
        unsafe { provider_release(provider as *mut c_void) };
        hr
    })
}

unsafe extern "system" fn factory_lock_server(_this: *mut c_void, lock: i32) -> Hresult {
    if lock != 0 {
        com::object_added();
    } else {
        com::object_removed();
    }
    S_OK
}

// ───────────────────────────── DLL exports ─────────────────────────────

/// COM's entry point for handing out a class factory.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const Guid,
    iid: *const Guid,
    out: *mut *mut c_void,
) -> Hresult {
    guard(|| {
        if out.is_null() {
            return E_POINTER;
        }
        // SAFETY: caller guarantees a writable slot.
        unsafe { *out = std::ptr::null_mut() };
        if clsid.is_null() || iid.is_null() {
            return E_POINTER;
        }
        // SAFETY: caller guarantees both point at GUIDs.
        if unsafe { *clsid } != CLSID_REDOUBT_PROVIDER {
            return CLASS_E_CLASSNOTAVAILABLE;
        }

        com::object_added();
        let factory = Box::into_raw(Box::new(ClassFactory {
            vtbl: &FACTORY_VTBL,
            refs: AtomicU32::new(1),
        }));

        // SAFETY: `factory` was just created with one reference.
        let hr = unsafe { factory_query_interface(factory as *mut c_void, iid, out) };
        unsafe { factory_release(factory as *mut c_void) };
        hr
    })
}

/// COM asks whether the DLL can be unloaded.
///
/// Reporting `S_OK` while objects are still alive lets the host unload the DLL
/// out from under live vtable pointers, which crashes it on the next call.
#[no_mangle]
pub unsafe extern "system" fn DllCanUnloadNow() -> Hresult {
    if com::objects_alive() == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

/// `regsvr32` support. `redoubtd amsi-install` does the same thing directly.
#[no_mangle]
pub unsafe extern "system" fn DllRegisterServer() -> Hresult {
    guard(|| match register::register_self() {
        Ok(()) => S_OK,
        Err(code) => code,
    })
}

#[no_mangle]
pub unsafe extern "system" fn DllUnregisterServer() -> Hresult {
    guard(|| match register::unregister_self() {
        Ok(()) => S_OK,
        Err(code) => code,
    })
}

/// Writing the two registry keys AMSI needs.
mod register {
    use super::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const E_FAIL: Hresult = -2147467259; // 0x80004005

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Path of this DLL on disk, which is what goes in `InprocServer32`.
    fn module_path() -> Option<String> {
        // A null module handle would give the *host's* path - PowerShell's -
        // so the address of a function in this DLL is used to find our own.
        let mut module: windows_sys::Win32::Foundation::HMODULE = std::ptr::null_mut();
        // SAFETY: passing the address of one of our own functions to locate
        // the module that contains it.
        let ok = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleExW(
                0x0000_0004 | 0x0000_0002, // FROM_ADDRESS | UNCHANGED_REFCOUNT
                DllCanUnloadNow as *const u16,
                &mut module,
            )
        };
        if ok == 0 {
            return None;
        }

        let mut buf = [0u16; 32768];
        // SAFETY: `buf` is a valid writable buffer of the given length.
        let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }

    fn set_string(root: HKEY, subkey: &str, name: Option<&str>, value: &str) -> Result<(), Hresult> {
        let mut key: HKEY = std::ptr::null_mut();
        let sub = wide(subkey);
        // SAFETY: `sub` is NUL-terminated; `key` receives the opened handle.
        let rc = unsafe {
            RegCreateKeyExW(
                root,
                sub.as_ptr(),
                0,
                std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &mut key,
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            return Err(E_FAIL);
        }

        let data = wide(value);
        let name_w = name.map(wide);
        // SAFETY: `data` is a NUL-terminated UTF-16 buffer of the given size.
        let rc = unsafe {
            RegSetValueExW(
                key,
                name_w.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                0,
                REG_SZ,
                data.as_ptr() as *const u8,
                std::mem::size_of_val(&data[..]) as u32,
            )
        };
        // SAFETY: `key` came from RegCreateKeyExW.
        unsafe { RegCloseKey(key) };

        if rc == 0 {
            Ok(())
        } else {
            Err(E_FAIL)
        }
    }

    pub fn register_self() -> Result<(), Hresult> {
        let path = module_path().ok_or(E_FAIL)?;
        let clsid = CLSID_REDOUBT_PROVIDER.to_registry_string();

        // 1. The COM class: where the DLL is and how it may be threaded.
        let base = format!(r"SOFTWARE\Classes\CLSID\{clsid}");
        set_string(HKEY_LOCAL_MACHINE, &base, None, "Redoubt AMSI Provider")?;
        set_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"{base}\InprocServer32"),
            None,
            &path,
        )?;
        // "Both" lets COM call us on any apartment without marshalling. A
        // provider is called from whatever thread the host happens to be on.
        set_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"{base}\InprocServer32"),
            Some("ThreadingModel"),
            "Both",
        )?;

        // 2. The AMSI registration itself. Without this the class exists but
        //    nothing ever calls it.
        set_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"SOFTWARE\Microsoft\AMSI\Providers\{clsid}"),
            None,
            "Redoubt AMSI Provider",
        )?;
        Ok(())
    }

    pub fn unregister_self() -> Result<(), Hresult> {
        let clsid = CLSID_REDOUBT_PROVIDER.to_registry_string();
        for path in [
            format!(r"SOFTWARE\Microsoft\AMSI\Providers\{clsid}"),
            format!(r"SOFTWARE\Classes\CLSID\{clsid}"),
        ] {
            let w = wide(&path);
            // SAFETY: `w` is NUL-terminated. A missing key is not an error -
            // unregistering something already gone should succeed.
            unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, w.as_ptr()) };
        }
        Ok(())
    }
}
