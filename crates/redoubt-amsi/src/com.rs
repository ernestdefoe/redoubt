//! The COM plumbing: hand-written vtables for the interfaces AMSI needs.
//!
//! These are laid out by hand rather than generated because the provider side
//! of AMSI is not in `windows-sys`, and because a DLL loaded into every
//! PowerShell, Office and .NET process on the machine should depend on as
//! little as possible.
//!
//! Everything here is `#[repr(C)]` and the field order **is** the ABI. Adding,
//! removing or reordering a function pointer silently changes which method the
//! caller invokes, so the layouts mirror the IDL exactly and in order.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};

pub type Hresult = i32;

pub const S_OK: Hresult = 0;
pub const S_FALSE: Hresult = 1;
pub const E_NOINTERFACE: Hresult = -2147467262; // 0x80004002
pub const E_POINTER: Hresult = -2147467261; // 0x80004003
pub const E_INVALIDARG: Hresult = -2147024809; // 0x80070057
pub const E_OUTOFMEMORY: Hresult = -2147024882; // 0x8007000E
pub const CLASS_E_NOAGGREGATION: Hresult = -2147221232; // 0x80040110
pub const CLASS_E_CLASSNOTAVAILABLE: Hresult = -2147221231; // 0x80040111

/// A COM interface identifier.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }

    /// Render in registry form, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
    pub fn to_registry_string(&self) -> String {
        format!(
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

/// `IUnknown` - {00000000-0000-0000-C000-000000000046}
pub const IID_IUNKNOWN: Guid =
    Guid::new(0x0000_0000, 0x0000, 0x0000, [0xC0, 0x00, 0, 0, 0, 0, 0, 0x46]);

/// `IClassFactory` - {00000001-0000-0000-C000-000000000046}
pub const IID_ICLASSFACTORY: Guid =
    Guid::new(0x0000_0001, 0x0000, 0x0000, [0xC0, 0x00, 0, 0, 0, 0, 0, 0x46]);

/// `IAntimalwareProvider` - {b2cabfe3-fe04-42b1-a5df-08d483d4d125}
///
/// The interface AMSI calls on a provider. Defined in `amsi.h`.
pub const IID_IANTIMALWARE_PROVIDER: Guid = Guid::new(
    0xb2ca_bfe3,
    0xfe04,
    0x42b1,
    [0xa5, 0xdf, 0x08, 0xd4, 0x83, 0xd4, 0xd1, 0x25],
);

/// Redoubt's own class id. Fixed forever: it is written into the registry and
/// is how AMSI finds this DLL.
pub const CLSID_REDOUBT_PROVIDER: Guid = Guid::new(
    0x7b8e_4c21,
    0x3d5a,
    0x4f19,
    [0x9e, 0x6b, 0x2c, 0x1d, 0x8a, 0x0f, 0x5e, 0x33],
);

/// AMSI's verdict values, from `amsi.h`.
///
/// Anything at or above `DETECTED` blocks. `NOT_DETECTED` explicitly means
/// "this provider has no opinion", which is what must be returned whenever
/// Redoubt cannot reach a verdict.
pub const AMSI_RESULT_CLEAN: u32 = 0;
pub const AMSI_RESULT_NOT_DETECTED: u32 = 1;
pub const AMSI_RESULT_DETECTED: u32 = 32768;

/// `AMSI_ATTRIBUTE`, from `amsi.h`.
pub const AMSI_ATTRIBUTE_APP_NAME: u32 = 0;
pub const AMSI_ATTRIBUTE_CONTENT_NAME: u32 = 1;
pub const AMSI_ATTRIBUTE_CONTENT_SIZE: u32 = 2;
pub const AMSI_ATTRIBUTE_CONTENT_ADDRESS: u32 = 3;
pub const AMSI_ATTRIBUTE_SESSION: u32 = 4;

/// `IUnknown`'s three methods, in ABI order.
#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface:
        unsafe extern "system" fn(*mut c_void, *const Guid, *mut *mut c_void) -> Hresult,
    pub add_ref: unsafe extern "system" fn(*mut c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut c_void) -> u32,
}

/// `IAmsiStream` - the content AMSI is asking about.
///
/// We only ever call this; we never implement it. The host provides it.
#[repr(C)]
pub struct IAmsiStreamVtbl {
    pub base: IUnknownVtbl,
    pub get_attribute: unsafe extern "system" fn(
        *mut c_void,
        u32,      // AMSI_ATTRIBUTE
        u32,      // data size
        *mut u8,  // data
        *mut u32, // bytes written
    ) -> Hresult,
    pub read: unsafe extern "system" fn(
        *mut c_void,
        u64,      // position
        u32,      // size
        *mut u8,  // buffer
        *mut u32, // bytes read
    ) -> Hresult,
}

/// `IAntimalwareProvider`, in ABI order.
///
/// `CloseSession` returns `void`, not `HRESULT`. Declaring it as returning
/// `HRESULT` would not crash but would read a garbage register as a result.
#[repr(C)]
pub struct IAntimalwareProviderVtbl {
    pub base: IUnknownVtbl,
    pub scan: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut u32) -> Hresult,
    pub close_session: unsafe extern "system" fn(*mut c_void, u64),
    pub display_name: unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> Hresult,
}

/// `IClassFactory`, in ABI order.
#[repr(C)]
pub struct IClassFactoryVtbl {
    pub base: IUnknownVtbl,
    pub create_instance: unsafe extern "system" fn(
        *mut c_void,
        *mut c_void, // outer unknown, for aggregation
        *const Guid,
        *mut *mut c_void,
    ) -> Hresult,
    pub lock_server: unsafe extern "system" fn(*mut c_void, i32) -> Hresult,
}

/// Live COM object count. `DllCanUnloadNow` reports `S_FALSE` while this is
/// non-zero; unloading a DLL that still owns live objects crashes the host.
pub static OBJECT_COUNT: AtomicU32 = AtomicU32::new(0);

pub fn object_added() {
    OBJECT_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn object_removed() {
    OBJECT_COUNT.fetch_sub(1, Ordering::Relaxed);
}

pub fn objects_alive() -> u32 {
    OBJECT_COUNT.load(Ordering::Relaxed)
}

/// A UTF-16, NUL-terminated copy of `s` allocated with `CoTaskMemAlloc`.
///
/// `DisplayName` hands a string to the caller, who frees it with
/// `CoTaskMemFree`. Returning a Rust allocation there would have the host free
/// memory from an allocator that never made it.
pub fn co_task_mem_wide(s: &str) -> *mut u16 {
    use windows_sys::Win32::System::Com::CoTaskMemAlloc;

    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = std::mem::size_of_val(&wide[..]);

    // SAFETY: allocating `bytes` for a buffer we immediately fill.
    let ptr = unsafe { CoTaskMemAlloc(bytes) } as *mut u16;
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: `ptr` has room for exactly `wide.len()` u16 values.
    unsafe {
        std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
    }
    ptr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_render_in_registry_form() {
        assert_eq!(
            IID_IUNKNOWN.to_registry_string(),
            "{00000000-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            IID_IANTIMALWARE_PROVIDER.to_registry_string(),
            "{B2CABFE3-FE04-42B1-A5DF-08D483D4D125}"
        );
        assert_eq!(
            CLSID_REDOUBT_PROVIDER.to_registry_string(),
            "{7B8E4C21-3D5A-4F19-9E6B-2C1D8A0F5E33}"
        );
    }

    #[test]
    fn the_class_id_is_distinct_from_every_interface_id() {
        // Registering under an interface id rather than our own class id would
        // put Redoubt in the registry claiming to be something else.
        assert_ne!(CLSID_REDOUBT_PROVIDER, IID_IUNKNOWN);
        assert_ne!(CLSID_REDOUBT_PROVIDER, IID_ICLASSFACTORY);
        assert_ne!(CLSID_REDOUBT_PROVIDER, IID_IANTIMALWARE_PROVIDER);
    }

    #[test]
    fn vtable_layouts_match_the_idl() {
        // The field order *is* the ABI. If these sizes change, a method call
        // from the host lands on the wrong function pointer.
        let ptr = std::mem::size_of::<usize>();
        assert_eq!(std::mem::size_of::<IUnknownVtbl>(), 3 * ptr);
        assert_eq!(std::mem::size_of::<IAmsiStreamVtbl>(), 5 * ptr);
        assert_eq!(std::mem::size_of::<IAntimalwareProviderVtbl>(), 6 * ptr);
        assert_eq!(std::mem::size_of::<IClassFactoryVtbl>(), 5 * ptr);
    }

    // These compare constants, which clippy reads as a tautology. They are
    // not: the constants are duplicated across two separately-built binaries
    // and these are what catch a change to one of them.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn amsi_result_values_match_the_header() {
        // Getting DETECTED wrong means either never blocking or blocking
        // everything, and both look like the provider "not working".
        assert_eq!(AMSI_RESULT_CLEAN, 0);
        assert_eq!(AMSI_RESULT_NOT_DETECTED, 1);
        assert_eq!(AMSI_RESULT_DETECTED, 32768);
        assert!(AMSI_RESULT_DETECTED > AMSI_RESULT_NOT_DETECTED);
    }

    #[test]
    fn the_object_count_tracks_lifetimes() {
        let before = objects_alive();
        object_added();
        assert_eq!(objects_alive(), before + 1);
        object_removed();
        assert_eq!(objects_alive(), before);
    }
}
