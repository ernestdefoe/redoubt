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
