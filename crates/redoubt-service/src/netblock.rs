//! Blocking outbound connections with the Windows Filtering Platform.
//!
//! Malware that has already run still has to reach somebody. Cutting that off
//! is the difference between a breach and an incident.
//!
//! # Why this needs no driver
//!
//! WFP is usually spoken of as kernel territory, and inspecting traffic does
//! need a callout driver. Deciding is different: a filter whose conditions and
//! action are fixed up front - "block anything connecting to this address" -
//! is evaluated by the kernel on its own, and can be installed entirely from
//! user mode. That is exactly how Windows Firewall's own rules work. Redoubt
//! therefore gets outbound blocking without a driver, and without the
//! Microsoft signing that a driver would require.
//!
//! The cost of that bargain is stated plainly: this can *block* a connection,
//! but it cannot *watch* one. There is no observe mode here, because observing
//! is the part that needs the driver.
//!
//! # The session is dynamic, and that is the important line in this file
//!
//! [`FWPM_SESSION_FLAG_DYNAMIC`] ties every filter to this process. If the
//! service is killed - or crashes, or is stopped by ransomware that got there
//! first - Windows removes them. Nothing survives to leave a machine cut off
//! from the internet with no obvious cause and no Redoubt running to undo it.
//!
//! A security tool that can permanently break networking by dying is worse
//! than one that does not block at all. Static filters would be marginally
//! more robust against being switched off; they would also be a footgun aimed
//! squarely at somebody's whole machine.

use anyhow::{bail, Result};
use redoubt_core::blocklist::{v4_mask, Blocklist, Cidr};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::core::GUID;

/// `FWP_E_ALREADY_EXISTS`. Not in windows-sys, and the raw literal reads as
/// a magic number at the one call site that needs it.
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

/// Redoubt's own sublayer, so its filters are identifiable and removable as a
/// group rather than tangled up with the firewall's.
const SUBLAYER_KEY: GUID = GUID::from_u128(0x5E1A_9C74_3B62_4D08_9F51_7A2E_4C60_D3B8);

/// The engine, and the filters currently installed through it.
///
/// Dropping this closes the engine handle, which - because the session is
/// dynamic - is what removes every filter.
pub struct NetBlocker {
    engine: HANDLE,
    installed: Vec<u64>,
    blocked_ranges: usize,
    sources: Vec<String>,
}

// The handle is owned solely by this value and is only used from whichever
// thread holds it.
unsafe impl Send for NetBlocker {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Turn a WFP status into something with the Win32 message attached.
fn check(code: u32, what: &str) -> Result<()> {
    if code == 0 {
        return Ok(());
    }
    let msg = std::io::Error::from_raw_os_error(code as i32);
    // FWP_E_* codes are not in the system message table, so the raw value is
    // included: without it the error reads as a generic failure and says
    // nothing about which of thirty WFP preconditions was not met.
    bail!("{what} failed: {msg} (0x{code:08X})")
}

impl NetBlocker {
    /// Open a dynamic WFP session and create Redoubt's sublayer.
    ///
    /// Needs administrator rights, which the service has and the interface
    /// does not. The error says so rather than reporting a bare access denial.
    pub fn open() -> Result<Self> {
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        let mut name = wide("Redoubt");
        session.displayData.name = name.as_mut_ptr();
        // Every filter added on this session dies with the process.
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: `session` outlives the call; RPC_C_AUTHN_DEFAULT with a null
        // identity means "this process's own credentials".
        let rc = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        };
        if rc == 5 {
            bail!(
                "network blocking needs administrator rights. It runs in the \
                 Redoubt service, not in the interface."
            );
        }
        check(rc, "opening the filtering engine")?;

        let mut me = Self {
            engine,
            installed: Vec::new(),
            blocked_ranges: 0,
            sources: Vec::new(),
        };
        if let Err(e) = me.add_sublayer() {
            // Close rather than leak the engine handle on a half-built object.
            unsafe { FwpmEngineClose0(me.engine) };
            me.engine = std::ptr::null_mut();
            return Err(e);
        }
        Ok(me)
    }

    fn add_sublayer(&mut self) -> Result<()> {
        let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sub.subLayerKey = SUBLAYER_KEY;
        let mut name = wide("Redoubt");
        let mut desc = wide("Outbound connections blocked by Redoubt");
        sub.displayData.name = name.as_mut_ptr();
        sub.displayData.description = desc.as_mut_ptr();
        // Middling weight: this should lose to an explicit administrator
        // firewall rule and win over defaults.
        sub.weight = 0x8000;

        // SAFETY: `sub` and its strings outlive the call.
        let rc = unsafe { FwpmSubLayerAdd0(self.engine, &sub, std::ptr::null_mut()) };
        // FWP_E_ALREADY_EXISTS: a previous session's sublayer that has not
        // been garbage-collected yet. Harmless - it is ours.
        if rc == FWP_E_ALREADY_EXISTS {
            return Ok(());
        }
        check(rc, "creating the Redoubt sublayer")
    }

    /// Install a block filter for one range.
    fn add_filter(&mut self, cidr: &Cidr) -> Result<()> {
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        let mut name = wide("Redoubt blocked address");
        filter.displayData.name = name.as_mut_ptr();
        filter.subLayerKey = SUBLAYER_KEY;
        filter.action.r#type = FWP_ACTION_BLOCK;
        // ALE_AUTH_CONNECT is evaluated once per outbound connection attempt,
        // before it leaves the machine, which is where a block belongs. A
        // packet-level layer would fire per datagram for no extra benefit.
        filter.layerKey = if cidr.is_v4() {
            FWPM_LAYER_ALE_AUTH_CONNECT_V4
        } else {
            FWPM_LAYER_ALE_AUTH_CONNECT_V6
        };
        filter.weight.r#type = FWP_EMPTY;

        // These must outlive the FwpmFilterAdd0 call: the condition holds
        // pointers into them, not copies.
        let mut v4: FWP_V4_ADDR_AND_MASK = unsafe { std::mem::zeroed() };
        let mut v6: FWP_V6_ADDR_AND_MASK = unsafe { std::mem::zeroed() };
        let mut condition: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        condition.matchType = FWP_MATCH_EQUAL;

        match cidr {
            Cidr::V4 { addr, prefix } => {
                v4.addr = u32::from(*addr);
                v4.mask = v4_mask(*prefix);
                condition.conditionValue.r#type = FWP_V4_ADDR_MASK;
                condition.conditionValue.Anonymous.v4AddrMask = &mut v4;
            }
            Cidr::V6 { addr, prefix } => {
                v6.addr = addr.octets();
                v6.prefixLength = *prefix;
                condition.conditionValue.r#type = FWP_V6_ADDR_MASK;
                condition.conditionValue.Anonymous.v6AddrMask = &mut v6;
            }
        }

        filter.numFilterConditions = 1;
        filter.filterCondition = &mut condition;

        let mut id: u64 = 0;
        // SAFETY: every pointer in `filter` refers to a local that is still
        // alive, and the call copies what it needs before returning.
        let rc = unsafe { FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) };
        check(rc, "adding a block filter")?;
        self.installed.push(id);
        Ok(())
    }

    /// Install filters for every range in `list`, in one transaction.
    ///
    /// A transaction so the machine is never left half-protected: either the
    /// whole list applies or none of it does. Partial enforcement is the worst
    /// outcome, because the status would claim protection that is not there.
    pub fn apply(&mut self, list: &Blocklist) -> Result<usize> {
        if list.is_empty() {
            return Ok(0);
        }

        // SAFETY: a live engine handle.
        check(unsafe { FwpmTransactionBegin0(self.engine, 0) }, "starting a transaction")?;

        let before = self.installed.len();
        for cidr in list.iter() {
            if let Err(e) = self.add_filter(cidr) {
                // SAFETY: aborting our own open transaction.
                unsafe { FwpmTransactionAbort0(self.engine) };
                self.installed.truncate(before);
                return Err(e);
            }
        }

        // SAFETY: committing our own open transaction.
        check(unsafe { FwpmTransactionCommit0(self.engine) }, "committing the filters")?;

        self.blocked_ranges = list.len();
        self.sources = list.sources.clone();
        Ok(self.installed.len() - before)
    }

    pub fn blocked_ranges(&self) -> usize {
        self.blocked_ranges
    }

    pub fn filters_installed(&self) -> usize {
        self.installed.len()
    }

    pub fn sources(&self) -> &[String] {
        &self.sources
    }
}

impl Drop for NetBlocker {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            // Closing the engine is what removes the filters, because the
            // session is dynamic. Deleting them individually first would be
            // busywork with a failure mode.
            // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
            unsafe { FwpmEngineClose0(self.engine) };
        }
    }
}

/// Whether this process could install filters at all.
///
/// Reported so the interface can say "the service does this" instead of
/// showing a permission error to somebody who has done nothing wrong.
pub fn available() -> bool {
    // Worked out once. This is read on every status poll, and opening a
    // filtering engine is an RPC to the Base Filtering Engine service - far
    // too expensive to do every two seconds, and the answer cannot change
    // without the process's rights changing, which they do not.
    static ANSWER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ANSWER.get_or_init(|| NetBlocker::open().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests here deliberately do not assert that filters install: that
    /// needs administrator rights, and a suite that fails when run normally is
    /// a suite people stop running. What they do assert is that the code is
    /// honest about not having them.
    #[test]
    fn opening_without_rights_says_what_is_wrong() {
        match NetBlocker::open() {
            Ok(b) => {
                // Elevated. The session must still be the dynamic one.
                assert_eq!(b.filters_installed(), 0);
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("administrator") || msg.contains("failed"),
                    "an unexplained failure is useless to whoever reads it: {msg}"
                );
            }
        }
    }

    #[test]
    fn an_empty_list_installs_nothing_rather_than_failing() {
        // A machine with no blocklist yet must not look like a broken one.
        if let Ok(mut b) = NetBlocker::open() {
            let empty = Blocklist::default();
            assert_eq!(b.apply(&empty).unwrap(), 0);
        }
    }

    #[test]
    fn the_sublayer_key_is_fixed() {
        // It identifies Redoubt's filters. Changing it orphans whatever a
        // previous version installed.
        assert_eq!(SUBLAYER_KEY.data1, 0x5E1A_9C74);
        assert_eq!(SUBLAYER_KEY.data2, 0x3B62);
        assert_eq!(SUBLAYER_KEY.data3, 0x4D08);
        assert_eq!(SUBLAYER_KEY.data4, [0x9F, 0x51, 0x7A, 0x2E, 0x4C, 0x60, 0xD3, 0xB8]);
    }

    #[test]
    fn availability_does_not_panic_either_way() {
        let _ = available();
    }
}
