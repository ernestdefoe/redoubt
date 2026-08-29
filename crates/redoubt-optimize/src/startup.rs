//! Startup entry management.
//!
//! Enumerates what launches at sign-in and lets it be turned off.
//!
//! # Disabling is a move, not a delete
//!
//! Turning an entry off relocates its registry value into a Redoubt-owned
//! backup key, or renames its shortcut with a `.disabled` suffix. Nothing is
//! destroyed, so re-enabling restores the exact original. That matters more
//! here than almost anywhere else in the product: an entry disabled by mistake
//! can stop a laptop's trackpad driver or a VPN from starting, and "reinstall
//! the software" is not an acceptable undo.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

/// Where Redoubt parks disabled entries. Under its own key, so nothing else
/// on the system interprets or cleans them up.
const BACKUP_KEY: &str = r"SOFTWARE\Redoubt\DisabledStartup";

/// Where an entry comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// `HKCU\...\Run` - this user only.
    UserRun,
    /// `HKLM\...\Run` - every user. Needs elevation to change.
    MachineRun,
    /// A shortcut in the user's Startup folder.
    UserStartupFolder,
    /// A shortcut in the all-users Startup folder. Needs elevation.
    CommonStartupFolder,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::UserRun => "Registry (this user)",
            Source::MachineRun => "Registry (all users)",
            Source::UserStartupFolder => "Startup folder (this user)",
            Source::CommonStartupFolder => "Startup folder (all users)",
        }
    }

    pub fn needs_admin(self) -> bool {
        matches!(self, Source::MachineRun | Source::CommonStartupFolder)
    }

    fn hive(self) -> Option<RegKey> {
        match self {
            Source::UserRun => Some(RegKey::predef(HKEY_CURRENT_USER)),
            Source::MachineRun => Some(RegKey::predef(HKEY_LOCAL_MACHINE)),
            _ => None,
        }
    }
}

const RUN_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

/// One thing that starts with Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Stable identifier: source and name.
    pub id: String,
    /// The registry value name, or the shortcut's filename.
    pub name: String,
    /// The command or target, as recorded.
    pub command: String,
    pub source: Source,
    pub source_label: String,
    pub needs_admin: bool,
    pub enabled: bool,
    /// The executable the command resolves to, when it can be worked out.
    pub image: Option<PathBuf>,
}

fn make_id(source: Source, name: &str) -> String {
    format!("{}:{}", source_key(source), name)
}

fn source_key(source: Source) -> &'static str {
    match source {
        Source::UserRun => "hkcu-run",
        Source::MachineRun => "hklm-run",
        Source::UserStartupFolder => "user-startup",
        Source::CommonStartupFolder => "common-startup",
    }
}

/// Pull the executable out of a command line.
///
/// Handles the two shapes that actually occur: a quoted path followed by
/// arguments, and an unquoted path where the first token is the executable.
pub fn parse_image(command: &str) -> Option<PathBuf> {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(PathBuf::from(&rest[..end]));
    }
    // Unquoted: take up to the first space. Paths with spaces and no quotes
    // are ambiguous, and guessing wrong is worse than declining.
    let first = trimmed.split_whitespace().next()?;
    Some(PathBuf::from(first))
}

fn startup_folder(source: Source) -> Option<PathBuf> {
    let p = match source {
        Source::UserStartupFolder => std::env::var_os("APPDATA").map(|a| {
            PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")
        })?,
        Source::CommonStartupFolder => std::env::var_os("ProgramData").map(|a| {
            PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")
        })?,
        _ => return None,
    };
    p.is_dir().then_some(p)
}

/// Read the disabled-entry backup for a source.
fn backup_key(source: Source, write: bool) -> Option<RegKey> {
    let hive = source.hive().or_else(|| Some(RegKey::predef(HKEY_CURRENT_USER)))?;
    let path = format!("{BACKUP_KEY}\\{}", source_key(source));
    if write {
        hive.create_subkey(&path).ok().map(|(k, _)| k)
    } else {
        hive.open_subkey(&path).ok()
    }
}

/// Every startup entry this process can see.
///
/// Reading `HKLM` does not need elevation; only changing it does.
pub fn entries() -> Vec<Entry> {
    let mut out = Vec::new();

    for source in [Source::UserRun, Source::MachineRun] {
        let Some(hive) = source.hive() else { continue };

        if let Ok(run) = hive.open_subkey(RUN_PATH) {
            for (name, value) in run.enum_values().flatten() {
                let command = value.to_string();
                out.push(Entry {
                    id: make_id(source, &name),
                    image: parse_image(&command),
                    name,
                    command,
                    source,
                    source_label: source.label().to_string(),
                    needs_admin: source.needs_admin(),
                    enabled: true,
                });
            }
        }

        // Anything Redoubt has parked, excluding names that are also live in
        // the Run key.
        //
        // Disabling writes the backup *before* deleting the Run value, so
        // both exist for an instant - and permanently if the machine stops in
        // between. The Run key is authoritative for whether something starts,
        // so a name present there is reported once, as enabled. Without this
        // the same entry appears twice with contradictory states.
        if let Some(backup) = backup_key(source, false) {
            for (name, value) in backup.enum_values().flatten() {
                if out.iter().any(|e| e.source == source && e.name == name) {
                    tracing::debug!(
                        %name,
                        "startup entry is in both the Run key and the backup; \
                         treating the Run key as authoritative"
                    );
                    continue;
                }
                let command = value.to_string();
                out.push(Entry {
                    id: make_id(source, &name),
                    image: parse_image(&command),
                    name,
                    command,
                    source,
                    source_label: source.label().to_string(),
                    needs_admin: source.needs_admin(),
                    enabled: false,
                });
            }
        }
    }

    for source in [Source::UserStartupFolder, Source::CommonStartupFolder] {
        let Some(dir) = startup_folder(source) else { continue };
        let Ok(read) = std::fs::read_dir(&dir) else { continue };

        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if file_name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let disabled = file_name.to_lowercase().ends_with(".disabled");
            let name = if disabled {
                file_name.trim_end_matches(".disabled").trim_end_matches(".DISABLED").to_string()
            } else {
                file_name
            };

            // Same rule as the registry: if both `X.lnk` and `X.lnk.disabled`
            // exist - which a crash mid-rename leaves behind - the live file
            // wins and the entry is reported once.
            if let Some(existing) = out
                .iter_mut()
                .find(|e| e.source == source && e.name == name)
            {
                if !disabled {
                    existing.enabled = true;
                    existing.command = path.to_string_lossy().into_owned();
                    existing.image = Some(path);
                }
                continue;
            }

            out.push(Entry {
                id: make_id(source, &name),
                command: path.to_string_lossy().into_owned(),
                image: Some(path),
                name,
                source,
                source_label: source.label().to_string(),
                needs_admin: source.needs_admin(),
                enabled: !disabled,
            });
        }
    }

    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

fn find(id: &str) -> Option<Entry> {
    entries().into_iter().find(|e| e.id == id)
}

/// Turn an entry off, keeping everything needed to turn it back on.
pub fn disable(id: &str) -> Result<()> {
    let entry = find(id).with_context(|| format!("no startup entry {id}"))?;
    if !entry.enabled {
        return Ok(());
    }

    match entry.source {
        Source::UserRun | Source::MachineRun => {
            let hive = entry.source.hive().context("no registry hive")?;
            let run = hive
                .open_subkey_with_flags(RUN_PATH, KEY_ALL_ACCESS)
                .with_context(|| {
                    if entry.needs_admin {
                        "opening the machine Run key needs an elevated process"
                    } else {
                        "opening the Run key"
                    }
                })?;
            let backup = backup_key(entry.source, true).context("creating the backup key")?;

            // Backup first. If this fails the entry stays enabled, which is
            // the safe direction to fail in.
            backup
                .set_value(&entry.name, &entry.command)
                .context("backing up the entry before disabling it")?;
            run.delete_value(&entry.name).context("removing the Run value")?;
        }
        Source::UserStartupFolder | Source::CommonStartupFolder => {
            let path = PathBuf::from(&entry.command);
            let target = path.with_file_name(format!("{}.disabled", entry.name));
            std::fs::rename(&path, &target)
                .with_context(|| format!("renaming {}", path.display()))?;
        }
    }
    Ok(())
}

/// Turn a previously disabled entry back on.
pub fn enable(id: &str) -> Result<()> {
    let entry = find(id).with_context(|| format!("no startup entry {id}"))?;
    if entry.enabled {
        return Ok(());
    }

    match entry.source {
        Source::UserRun | Source::MachineRun => {
            let hive = entry.source.hive().context("no registry hive")?;
            let run = hive
                .open_subkey_with_flags(RUN_PATH, KEY_ALL_ACCESS)
                .context("opening the Run key")?;
            run.set_value(&entry.name, &entry.command)
                .context("restoring the Run value")?;

            if let Some(backup) = backup_key(entry.source, true) {
                let _ = backup.delete_value(&entry.name);
            }
        }
        Source::UserStartupFolder | Source::CommonStartupFolder => {
            let disabled = PathBuf::from(&entry.command);
            let disabled = if disabled.to_string_lossy().to_lowercase().ends_with(".disabled") {
                disabled
            } else {
                disabled.with_file_name(format!("{}.disabled", entry.name))
            };
            let target = disabled.with_file_name(&entry.name);
            std::fs::rename(&disabled, &target)
                .with_context(|| format!("restoring {}", target.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that mutate the machine's real `Run` key.
    ///
    /// Cargo runs tests in parallel threads within one process, and these
    /// share a single global resource. Without this, the enumeration test can
    /// observe another test's entry mid-write and report a duplicate - a
    /// property of the test harness, not of the code under test.
    static REGISTRY: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the registry lock, ignoring poisoning from an unrelated failure.
    fn registry_guard() -> std::sync::MutexGuard<'static, ()> {
        REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn parses_a_quoted_command() {
        assert_eq!(
            parse_image(r#""C:\Program Files\App\app.exe" --background"#),
            Some(PathBuf::from(r"C:\Program Files\App\app.exe"))
        );
        assert_eq!(
            parse_image(r#""C:\Program Files (x86)\Thing\thing.exe""#),
            Some(PathBuf::from(r"C:\Program Files (x86)\Thing\thing.exe"))
        );
    }

    #[test]
    fn parses_an_unquoted_command() {
        assert_eq!(
            parse_image(r"C:\Windows\System32\rundll32.exe shell32.dll,Control_RunDLL"),
            Some(PathBuf::from(r"C:\Windows\System32\rundll32.exe"))
        );
        assert_eq!(
            parse_image(r"C:\Tools\agent.exe"),
            Some(PathBuf::from(r"C:\Tools\agent.exe"))
        );
    }

    #[test]
    fn declines_to_guess_on_empty_input() {
        assert_eq!(parse_image(""), None);
        assert_eq!(parse_image("   "), None);
        // An unterminated quote is malformed; guessing would be worse than
        // declining, since the result is shown to the user as "what runs".
        assert_eq!(parse_image(r#""C:\unterminated\path.exe"#), None);
    }

    #[test]
    fn sources_declare_their_elevation_needs() {
        assert!(!Source::UserRun.needs_admin());
        assert!(!Source::UserStartupFolder.needs_admin());
        assert!(Source::MachineRun.needs_admin());
        assert!(Source::CommonStartupFolder.needs_admin());
    }

    #[test]
    fn source_labels_are_distinct_and_say_the_scope() {
        let all = [
            Source::UserRun,
            Source::MachineRun,
            Source::UserStartupFolder,
            Source::CommonStartupFolder,
        ];
        let mut labels: Vec<&str> = all.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(before, labels.len(), "two sources share a label");

        // A user must be able to tell "just me" from "everyone".
        assert!(Source::UserRun.label().contains("this user"));
        assert!(Source::MachineRun.label().contains("all users"));
    }

    #[test]
    fn ids_are_unique_per_source_and_name() {
        assert_ne!(
            make_id(Source::UserRun, "Thing"),
            make_id(Source::MachineRun, "Thing"),
            "the same name in two hives must not collide"
        );
    }

    #[test]
    fn enumerating_this_machine_returns_coherent_entries() {
        // Read-only, but it must not run while another test is mid-write.
        let _guard = registry_guard();

        let all = entries();
        let mut seen = std::collections::HashSet::new();
        let dupes: Vec<&str> = all
            .iter()
            .filter(|e| !seen.insert(e.id.as_str()))
            .map(|e| e.id.as_str())
            .collect();
        assert!(dupes.is_empty(), "duplicate startup entry ids: {dupes:?}");

        for e in &all {
            assert!(!e.name.is_empty());
            assert_eq!(e.needs_admin, e.source.needs_admin());
            assert_eq!(e.source_label, e.source.label());
        }
    }

    #[test]
    fn an_entry_in_both_the_run_key_and_the_backup_is_reported_once() {
        // Disabling writes the backup before deleting the Run value. A crash
        // in between leaves both, permanently. Reporting the entry twice with
        // contradictory states is how a UI ends up showing a toggle that flips
        // itself back.
        let _guard = registry_guard();
        let name = format!("RedoubtDup_{}", std::process::id());
        let command = r"C:\Redoubt	est
ever-runs.exe";

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = hkcu.open_subkey_with_flags(RUN_PATH, KEY_ALL_ACCESS).unwrap();
        run.set_value(&name, &command).unwrap();
        let backup = backup_key(Source::UserRun, true).unwrap();
        backup.set_value(&name, &command).unwrap();

        let all = entries();
        let matching: Vec<&Entry> = all.iter().filter(|e| e.name == name).collect();
        assert_eq!(matching.len(), 1, "the entry should appear exactly once");
        assert!(
            matching[0].enabled,
            "the Run key is authoritative, so it should read as enabled"
        );

        run.delete_value(&name).ok();
        backup.delete_value(&name).ok();
    }

    #[test]
    fn a_disable_and_enable_round_trip_preserves_the_command() {
        // Uses HKCU only, and a name nothing else will touch.
        let _guard = registry_guard();
        let name = format!("RedoubtTest_{}", std::process::id());
        let command = r#""C:\Redoubt\test\never-runs.exe" --flag"#;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = hkcu
            .open_subkey_with_flags(RUN_PATH, KEY_ALL_ACCESS)
            .expect("HKCU Run should be writable");
        run.set_value(&name, &command).unwrap();

        let id = make_id(Source::UserRun, &name);

        let before = find(&id).expect("entry should be listed");
        assert!(before.enabled);
        assert_eq!(before.command, command);

        disable(&id).unwrap();
        let disabled = find(&id).expect("a disabled entry must still be listed");
        assert!(!disabled.enabled, "it should now read as disabled");
        assert!(
            run.get_value::<String, _>(&name).is_err(),
            "the Run value should be gone while disabled"
        );

        enable(&id).unwrap();
        let after = find(&id).expect("entry should be back");
        assert!(after.enabled);
        assert_eq!(
            after.command, command,
            "re-enabling must restore the exact original command"
        );

        // Clean up.
        run.delete_value(&name).ok();
        if let Some(b) = backup_key(Source::UserRun, true) {
            b.delete_value(&name).ok();
        }
    }
}
