//! Registering `redoubtd` with the Windows Service Control Manager.
//!
//! Protection that only runs while someone is logged in and has started it by
//! hand is not really protection. As a service it starts at boot, before the
//! user does, and restarts if it dies.
//!
//! # Elevation
//!
//! Creating, deleting, starting and stopping a service all need administrator
//! rights. Every function here reports that plainly when it is refused rather
//! than failing with a bare OS error code, because "access denied" from a
//! security tool is otherwise indistinguishable from a bug.

use anyhow::{Context, Result};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// Internal service name, used with `sc` and the registry.
pub const SERVICE_NAME: &str = "Redoubt";

/// What appears in services.msc.
pub const DISPLAY_NAME: &str = "Redoubt Protection";

const DESCRIPTION: &str = "Watches for malware and ransomware, and keeps signatures current. \
                           Runs in observe mode until enforcement is turned on.";

/// Windows service type for a process that owns its own service.
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

/// `ERROR_ACCESS_DENIED`
const ACCESS_DENIED: i32 = 5;
/// `ERROR_SERVICE_DOES_NOT_EXIST`
const SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// The underlying Win32 error code, if there is one.
///
/// `windows_service::Error` renders as the unhelpful "IO error in winapi call"
/// whatever actually went wrong, so matching on its text finds nothing. The
/// code has to come from the wrapped `io::Error`.
fn os_code(e: &windows_service::Error) -> Option<i32> {
    match e {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

/// Turn an access-denied failure into an instruction.
fn explain(e: windows_service::Error, action: &str) -> anyhow::Error {
    match os_code(&e) {
        Some(ACCESS_DENIED) => anyhow::anyhow!(
            "{action} needs administrator rights. Run this from an elevated \
             prompt (right-click Terminal or Command Prompt, Run as administrator)."
        ),
        Some(code) => anyhow::anyhow!("{action} failed: {e} (Windows error {code})"),
        None => anyhow::anyhow!("{action} failed: {e}"),
    }
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access)
        .map_err(|e| explain(e, "opening the service manager"))
}

/// Path of the currently running executable, for the service's ImagePath.
fn own_exe() -> Result<PathBuf> {
    std::env::current_exe().context("locating the running executable")
}

/// Register the service.
///
/// The binary is registered where it currently sits rather than being copied
/// anywhere: a service whose image is a build-output path that later moves is
/// a service that silently stops working, so the path is reported back for the
/// caller to show.
pub fn install() -> Result<PathBuf> {
    let exe = own_exe()?;
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: SERVICE_TYPE,
        // Automatic rather than delayed: the point of resident protection is
        // to be running before anything else has a chance to.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        // Tells the binary it is being started by the SCM rather than a shell.
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        // LocalSystem: reading other users' processes and writing to
        // %ProgramData% both need more than a normal account.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| explain(e, "creating the service"))?;

    service
        .set_description(DESCRIPTION)
        .map_err(|e| explain(e, "setting the service description"))?;

    Ok(exe)
}

/// Remove the service, stopping it first if it is running.
pub fn uninstall() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .map_err(|e| explain(e, "opening the service"))?;

    let status = service
        .query_status()
        .map_err(|e| explain(e, "querying the service"))?;
    if status.current_state != ServiceState::Stopped {
        service.stop().map_err(|e| explain(e, "stopping the service"))?;
        // Deleting a service that is still stopping leaves it marked for
        // deletion until every handle closes, which looks like the uninstall
        // silently failed.
        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(200));
            if service
                .query_status()
                .map(|s| s.current_state == ServiceState::Stopped)
                .unwrap_or(true)
            {
                break;
            }
        }
    }

    service.delete().map_err(|e| explain(e, "deleting the service"))?;
    Ok(())
}

/// Start the installed service.
pub fn start() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .map_err(|e| explain(e, "opening the service"))?;
    service
        .start::<&str>(&[])
        .map_err(|e| explain(e, "starting the service"))?;
    Ok(())
}

/// Stop the running service.
pub fn stop() -> Result<()> {
    let manager = manager(ServiceManagerAccess::CONNECT)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .map_err(|e| explain(e, "opening the service"))?;
    service.stop().map_err(|e| explain(e, "stopping the service"))?;
    Ok(())
}

/// What the SCM currently thinks of the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Installed {
    /// Registered, with its current run state.
    Yes { running: bool, image: Option<PathBuf> },
    No,
    /// Could not be determined - usually because querying needs elevation.
    Unknown(String),
}

/// Query the service without needing write access.
pub fn status() -> Installed {
    let manager = match ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    ) {
        Ok(m) => m,
        Err(e) => return Installed::Unknown(e.to_string()),
    };

    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG)
    {
        Ok(service) => {
            let running = service
                .query_status()
                .map(|s| s.current_state == ServiceState::Running)
                .unwrap_or(false);
            let image = service.query_config().ok().map(|c| c.executable_path);
            Installed::Yes { running, image }
        }
        Err(e) => match os_code(&e) {
            // A definite answer; anything else means we could not tell.
            Some(SERVICE_DOES_NOT_EXIST) => Installed::No,
            Some(code) => Installed::Unknown(format!("{e} (Windows error {code})")),
            None => Installed::Unknown(e.to_string()),
        },
    }
}


// ---------------------------------------------------------------------------
// AMSI provider registration
// ---------------------------------------------------------------------------

/// Registering the AMSI provider DLL.
///
/// Two `HKLM` keys are needed and both require administrator rights: the COM
/// class, and the class id listed under AMSI's own Providers key. Writing only
/// the first produces a class that exists and is never called - which looks
/// exactly like a provider that does not work.
pub mod amsi {
    use super::*;
    use std::path::{Path, PathBuf};
    use winreg::enums::*;
    use winreg::RegKey;

    /// Must match `redoubt_amsi::com::CLSID_REDOUBT_PROVIDER`.
    ///
    /// Duplicated rather than shared because the service must not depend on
    /// the provider crate: the DLL is built for loading into other processes
    /// and links nothing of ours.
    pub const CLSID: &str = "{7B8E4C21-3D5A-4F19-9E6B-2C1D8A0F5E33}";

    pub const DLL_NAME: &str = "redoubt_amsi.dll";

    fn clsid_key() -> String {
        format!(r"SOFTWARE\Classes\CLSID\{CLSID}")
    }

    fn providers_key() -> String {
        format!(r"SOFTWARE\Microsoft\AMSI\Providers\{CLSID}")
    }

    /// Locate the provider DLL, preferring one beside the running binary.
    pub fn find_dll(explicit: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = explicit {
            return p.is_file().then(|| p.to_path_buf());
        }
        let exe = std::env::current_exe().ok()?;
        let beside = exe.with_file_name(DLL_NAME);
        beside.is_file().then_some(beside)
    }

    /// What is currently registered.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Registration {
        /// Fully registered, with the DLL path AMSI will load.
        Complete { dll: PathBuf },
        /// The COM class exists but AMSI is not told about it, so nothing ever
        /// calls it. Reported separately because it is indistinguishable from
        /// "not working" without looking.
        ClassOnly { dll: PathBuf },
        None,
    }

    pub fn status() -> Registration {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let dll: Option<PathBuf> = hklm
            .open_subkey(format!(r"{}\InprocServer32", clsid_key()))
            .ok()
            .and_then(|k| k.get_value::<String, _>("").ok())
            .map(PathBuf::from);

        let listed = hklm.open_subkey(providers_key()).is_ok();

        match (dll, listed) {
            (Some(dll), true) => Registration::Complete { dll },
            (Some(dll), false) => Registration::ClassOnly { dll },
            (None, _) => Registration::None,
        }
    }

    fn denied(e: &std::io::Error) -> bool {
        e.raw_os_error() == Some(5)
    }

    fn wrap(e: std::io::Error, action: &str) -> anyhow::Error {
        if denied(&e) {
            anyhow::anyhow!(
                "{action} needs administrator rights. Run this from an elevated \
                 prompt (right-click Terminal, Run as administrator)."
            )
        } else {
            anyhow::anyhow!("{action} failed: {e}")
        }
    }

    /// Register the provider so AMSI loads it.
    pub fn install(dll: &Path) -> Result<()> {
        if !dll.is_file() {
            anyhow::bail!("{} does not exist", dll.display());
        }
        let dll_path = dll
            .canonicalize()
            .unwrap_or_else(|_| dll.to_path_buf())
            .to_string_lossy()
            // canonicalize yields a \\?\ prefix, which COM will not load.
            .trim_start_matches(r"\\?\")
            .to_string();

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

        let (class, _) = hklm
            .create_subkey(clsid_key())
            .map_err(|e| wrap(e, "creating the COM class key"))?;
        class
            .set_value("", &"Redoubt AMSI Provider")
            .map_err(|e| wrap(e, "naming the COM class"))?;

        let (inproc, _) = hklm
            .create_subkey(format!(r"{}\InprocServer32", clsid_key()))
            .map_err(|e| wrap(e, "creating InprocServer32"))?;
        inproc
            .set_value("", &dll_path)
            .map_err(|e| wrap(e, "setting the DLL path"))?;
        // "Both" lets COM call the provider on whatever thread the host is on,
        // without marshalling.
        inproc
            .set_value("ThreadingModel", &"Both")
            .map_err(|e| wrap(e, "setting the threading model"))?;

        // The registration that actually makes AMSI call us.
        let (providers, _) = hklm
            .create_subkey(providers_key())
            .map_err(|e| wrap(e, "listing the provider with AMSI"))?;
        providers
            .set_value("", &"Redoubt AMSI Provider")
            .map_err(|e| wrap(e, "naming the provider"))?;

        Ok(())
    }

    /// Remove both keys. A missing key is not an error.
    pub fn uninstall() -> Result<()> {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for key in [providers_key(), clsid_key()] {
            match hklm.delete_subkey_all(&key) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(wrap(e, "removing the registration")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_identifies_itself_clearly() {
        // These names appear in services.msc and in `sc` output, where a
        // cryptic name is indistinguishable from something unwanted.
        assert_eq!(SERVICE_NAME, "Redoubt");
        assert!(DISPLAY_NAME.contains("Redoubt"));
        assert!(DESCRIPTION.len() > 40, "the description should explain what it does");
        assert!(
            DESCRIPTION.contains("observe"),
            "the description should say it does not act by default"
        );
    }

    #[test]
    fn status_answers_without_elevation() {
        // Querying must work unelevated, so the UI can show the real state
        // rather than guessing.
        match status() {
            Installed::Yes { .. } | Installed::No => {}
            Installed::Unknown(e) => {
                panic!("querying the service should not need elevation: {e}")
            }
        }
    }

    #[test]
    fn access_denied_becomes_an_instruction() {
        // A bare "os error 5" from a security tool reads like a bug.
        let e = explain(
            windows_service::Error::Winapi(std::io::Error::from_raw_os_error(5)),
            "creating the service",
        );
        let text = e.to_string();
        assert!(text.contains("administrator"), "{text}");
        assert!(text.contains("elevated"), "{text}");
    }

    #[test]
    fn the_amsi_class_id_matches_the_provider_dll() {
        // Two separately-built binaries agreeing by convention. If these ever
        // diverge the registration points at a class that does not exist, and
        // AMSI silently never calls anything.
        assert_eq!(amsi::CLSID, "{7B8E4C21-3D5A-4F19-9E6B-2C1D8A0F5E33}");
        assert_eq!(amsi::DLL_NAME, "redoubt_amsi.dll");
    }

    #[test]
    fn amsi_status_answers_without_elevation() {
        // Reading HKLM does not need admin; only writing does.
        match amsi::status() {
            amsi::Registration::Complete { .. }
            | amsi::Registration::ClassOnly { .. }
            | amsi::Registration::None => {}
        }
    }

    #[test]
    fn installing_a_missing_dll_is_refused_before_touching_the_registry() {
        let err = amsi::install(std::path::Path::new(r"Z:\nope\redoubt_amsi.dll")).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn other_failures_keep_their_detail() {
        let e = explain(
            windows_service::Error::Winapi(std::io::Error::from_raw_os_error(
                SERVICE_DOES_NOT_EXIST,
            )),
            "opening the service",
        );
        let text = e.to_string();
        assert!(text.contains("opening the service"));
        assert!(
            text.contains("1060"),
            "the Windows error code must survive - the crate's own message is              just \"IO error in winapi call\" whatever went wrong: {text}"
        );
    }
}
