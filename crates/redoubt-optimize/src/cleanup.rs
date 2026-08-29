//! Reclaimable disk space.
//!
//! # The rule this module is built around
//!
//! Every path considered for deletion must live under one of a small set of
//! hardcoded roots, and [`Category::contains`] is checked immediately before
//! any `remove`. A "PC optimizer" that deletes the wrong directory is not a
//! slow tool, it is a destructive one, so containment is enforced at the point
//! of deletion rather than trusted from wherever the path came from.
//!
//! # What is deliberately not cleaned
//!
//! - **Prefetch.** Windows uses it to speed up application launch, and it
//!   rebuilds itself. Deleting it makes the machine slower for a while and
//!   faster never. Optimizers clean it because it looks like a big number.
//! - **The WinSxS component store.** Only `DISM /StartComponentCleanup` may
//!   touch it; deleting from it by hand breaks servicing permanently.
//! - **`%APPDATA%` generally.** Applications keep real state there.
//! - **Anything under a user's Documents, Desktop or Downloads.**

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How confident we are that removing a category is harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Safety {
    /// Regenerated automatically; removal has no lasting effect.
    Safe,
    /// Removal is fine but has a visible cost, such as signing back in to
    /// websites or a slower first launch.
    Caution,
}

/// One kind of reclaimable content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
    /// What it is and what removing it actually costs.
    pub description: String,
    pub safety: Safety,
    /// Directories whose *contents* may be removed. The directories
    /// themselves are kept.
    pub roots: Vec<PathBuf>,
    /// Requires an elevated process.
    pub needs_admin: bool,
    /// Selected by default in the UI.
    pub default_selected: bool,
}

impl Category {
    /// True when `path` lies inside one of this category's roots.
    ///
    /// This is the containment check. It is deliberately strict: the path must
    /// be *under* a root, not equal to it, so a bug that produces a root path
    /// cannot delete the root itself.
    pub fn contains(&self, path: &Path) -> bool {
        let p = normalise(path);
        self.roots.iter().any(|root| {
            let r = normalise(root);
            p.len() > r.len() && p.starts_with(&r) && p.as_bytes()[r.len()] == b'\\'
        })
    }
}

/// Lowercase with forward slashes folded to backslashes and no trailing
/// separator, so comparisons are not defeated by spelling.
fn normalise(path: &Path) -> String {
    let s = path.to_string_lossy().to_lowercase().replace('/', "\\");
    s.trim_end_matches('\\').to_string()
}

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_dir())
}

/// Every category applicable to this machine.
pub fn categories() -> Vec<Category> {
    let local = env_path("LOCALAPPDATA");
    let mut out = Vec::new();

    if let Some(tmp) = env_path("TEMP") {
        out.push(Category {
            id: "user-temp".into(),
            name: "Temporary files".into(),
            description: "Scratch files left behind by installers and applications. \
                          Rebuilt on demand."
                .into(),
            safety: Safety::Safe,
            roots: vec![tmp],
            needs_admin: false,
            default_selected: true,
        });
    }

    out.push(Category {
        id: "windows-temp".into(),
        name: "System temporary files".into(),
        description: "The machine-wide scratch directory. Same idea, but owned by the system."
            .into(),
        safety: Safety::Safe,
        roots: vec![PathBuf::from(r"C:\Windows\Temp")],
        needs_admin: true,
        default_selected: true,
    });

    out.push(Category {
        id: "windows-update".into(),
        name: "Windows Update cache".into(),
        description: "Installer payloads kept after updates were applied. Windows re-downloads \
                      them if it ever needs them again."
            .into(),
        safety: Safety::Safe,
        roots: vec![PathBuf::from(r"C:\Windows\SoftwareDistribution\Download")],
        needs_admin: true,
        default_selected: true,
    });

    out.push(Category {
        id: "delivery-optimization".into(),
        name: "Delivery Optimization files".into(),
        description: "Update chunks cached for sharing with other machines on the network."
            .into(),
        safety: Safety::Safe,
        roots: vec![PathBuf::from(r"C:\Windows\SoftwareDistribution\DeliveryOptimization")],
        needs_admin: true,
        default_selected: true,
    });

    if let Some(local) = &local {
        out.push(Category {
            id: "crash-dumps".into(),
            name: "Crash reports".into(),
            description: "Windows Error Reporting archives from programs that have crashed."
                .into(),
            safety: Safety::Safe,
            roots: vec![local.join("CrashDumps"), local.join(r"Microsoft\Windows\WER")],
            needs_admin: false,
            default_selected: true,
        });

        out.push(Category {
            id: "thumbnail-cache".into(),
            name: "Thumbnail cache".into(),
            description: "Explorer's picture previews. Regenerated as you browse folders, so \
                          the first look at a picture folder is slower."
                .into(),
            safety: Safety::Caution,
            roots: vec![local.join(r"Microsoft\Windows\Explorer")],
            needs_admin: false,
            default_selected: false,
        });

        // Browser caches. Each is only offered when the browser is installed.
        let browsers: &[(&str, &str, PathBuf)] = &[
            (
                "chrome-cache",
                "Chrome cache",
                local.join(r"Google\Chrome\User Data\Default\Cache"),
            ),
            (
                "edge-cache",
                "Edge cache",
                local.join(r"Microsoft\Edge\User Data\Default\Cache"),
            ),
        ];
        for (id, name, path) in browsers {
            if path.is_dir() {
                out.push(Category {
                    id: (*id).into(),
                    name: (*name).into(),
                    description: "Cached page content. Removing it means pages reload from the \
                                  network once; it does not sign you out."
                        .into(),
                    safety: Safety::Caution,
                    roots: vec![path.clone()],
                    needs_admin: false,
                    default_selected: false,
                });
            }
        }
    }

    out.retain(|c| c.roots.iter().any(|r| r.is_dir()));
    out
}

/// What a category currently holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub id: String,
    pub name: String,
    pub description: String,
    pub safety: Safety,
    pub needs_admin: bool,
    pub default_selected: bool,
    pub bytes: u64,
    pub files: u64,
    /// Paths that could not be read, usually because they need elevation or
    /// are held open. Surfaced so a small number is understood rather than
    /// mistaken for a clean result.
    pub unreadable: u64,
}

/// Measure a category without changing anything.
pub fn measure(category: &Category) -> Measurement {
    let mut bytes = 0u64;
    let mut files = 0u64;
    let mut unreadable = 0u64;

    for root in &category.roots {
        if !root.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            match entry {
                Ok(e) if e.file_type().is_file() => match e.metadata() {
                    Ok(m) => {
                        bytes += m.len();
                        files += 1;
                    }
                    Err(_) => unreadable += 1,
                },
                Ok(_) => {}
                Err(_) => unreadable += 1,
            }
        }
    }

    Measurement {
        id: category.id.clone(),
        name: category.name.clone(),
        description: category.description.clone(),
        safety: category.safety,
        needs_admin: category.needs_admin,
        default_selected: category.default_selected,
        bytes,
        files,
        unreadable,
    }
}

/// Measure every applicable category.
pub fn analyze() -> Vec<Measurement> {
    let mut out: Vec<Measurement> = categories().iter().map(measure).collect();
    out.sort_by_key(|m| std::cmp::Reverse(m.bytes));
    out
}

/// Result of cleaning one category.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanResult {
    pub id: String,
    pub bytes_freed: u64,
    pub files_removed: u64,
    /// Files that were in use or protected. Normal, and reported rather than
    /// hidden - a running browser holds its own cache open.
    pub files_skipped: u64,
    /// Paths refused by the containment check. Any non-zero value here is a
    /// bug, not a condition, and it is counted so it cannot pass unnoticed.
    pub refused: u64,
}

/// Delete the contents of a category.
///
/// `dry_run` measures without deleting, which is what the interface calls
/// before showing a confirmation.
pub fn clean(category: &Category, dry_run: bool) -> CleanResult {
    let mut result = CleanResult { id: category.id.clone(), ..Default::default() };

    for root in &category.roots {
        if !root.is_dir() {
            continue;
        }
        // Depth-first, so directories are emptied before being removed.
        let entries: Vec<_> = walkdir::WalkDir::new(root)
            .follow_links(false)
            .contents_first(true)
            .into_iter()
            .filter_map(|e| e.ok())
            .collect();

        for entry in entries {
            // The root itself is kept, and is not a containment failure - it
            // is correctly outside its own deletable set. Counting it as
            // `refused` would make that counter useless as a bug signal.
            if entry.depth() == 0 {
                continue;
            }
            let path = entry.path();

            // The containment check, immediately before the delete. Never
            // hoisted out of this loop.
            if !category.contains(path) {
                result.refused += 1;
                tracing::error!(
                    path = %path.display(),
                    category = %category.id,
                    "refused a path outside the category root"
                );
                continue;
            }

            if entry.file_type().is_file() {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if dry_run {
                    result.bytes_freed += size;
                    result.files_removed += 1;
                } else {
                    match std::fs::remove_file(path) {
                        Ok(()) => {
                            result.bytes_freed += size;
                            result.files_removed += 1;
                        }
                        Err(_) => result.files_skipped += 1,
                    }
                }
            } else if entry.file_type().is_dir() && !dry_run {
                // Only succeeds once empty, which is the behaviour we want:
                // it can never take a directory that still holds something.
                let _ = std::fs::remove_dir(path);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("redoubt-clean-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&p).ok();
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn category_over(root: &Path) -> Category {
        Category {
            id: "test".into(),
            name: "Test".into(),
            description: "test".into(),
            safety: Safety::Safe,
            roots: vec![root.to_path_buf()],
            needs_admin: false,
            default_selected: true,
        }
    }

    #[test]
    fn containment_accepts_only_paths_under_a_root() {
        let c = category_over(Path::new(r"C:\Windows\Temp"));

        assert!(c.contains(Path::new(r"C:\Windows\Temp\a.tmp")));
        assert!(c.contains(Path::new(r"C:\Windows\Temp\sub\deep\b.tmp")));
        // Case and separator spelling must not defeat it.
        assert!(c.contains(Path::new(r"c:\windows\temp\a.tmp")));
        assert!(c.contains(Path::new("C:/Windows/Temp/a.tmp")));

        // The root itself is not deletable.
        assert!(!c.contains(Path::new(r"C:\Windows\Temp")));
        assert!(!c.contains(Path::new(r"C:\Windows\Temp\")));
        // A sibling with a shared prefix must not be swept in.
        assert!(!c.contains(Path::new(r"C:\Windows\TempData\a.tmp")));
        assert!(!c.contains(Path::new(r"C:\Windows\System32\kernel32.dll")));
        assert!(!c.contains(Path::new(r"C:\Users\me\Documents\thesis.docx")));
    }

    #[test]
    fn measure_reports_size_and_count_without_deleting() {
        let dir = temp("measure");
        std::fs::write(dir.join("a.tmp"), vec![0u8; 1000]).unwrap();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/b.tmp"), vec![0u8; 2000]).unwrap();

        let m = measure(&category_over(&dir));
        assert_eq!(m.files, 2);
        assert_eq!(m.bytes, 3000);
        assert!(dir.join("a.tmp").exists(), "measuring must not delete");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dry_run_reports_what_would_go_and_removes_nothing() {
        let dir = temp("dryrun");
        std::fs::write(dir.join("a.tmp"), vec![0u8; 500]).unwrap();
        std::fs::write(dir.join("b.tmp"), vec![0u8; 700]).unwrap();

        let r = clean(&category_over(&dir), true);
        assert_eq!(r.files_removed, 2);
        assert_eq!(r.bytes_freed, 1200);
        assert_eq!(r.refused, 0);
        assert!(dir.join("a.tmp").exists(), "a dry run must not delete");
        assert!(dir.join("b.tmp").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_empties_the_root_but_keeps_the_root_itself() {
        let dir = temp("clean");
        std::fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        std::fs::write(dir.join("a.tmp"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("sub/b.tmp"), vec![0u8; 200]).unwrap();
        std::fs::write(dir.join("sub/deeper/c.tmp"), vec![0u8; 300]).unwrap();

        let r = clean(&category_over(&dir), false);
        assert_eq!(r.files_removed, 3);
        assert_eq!(r.bytes_freed, 600);
        assert_eq!(r.refused, 0);

        assert!(dir.is_dir(), "the root itself must survive");
        assert!(!dir.join("a.tmp").exists());
        assert!(!dir.join("sub").exists(), "emptied subdirectories should go");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_path_outside_the_root_is_refused_and_counted() {
        // Simulating the bug this guard exists for: a category whose declared
        // root does not actually contain what the walk produced.
        let real = temp("outside-real");
        let declared = temp("outside-declared");
        std::fs::write(real.join("precious.txt"), b"do not delete").unwrap();

        let mut c = category_over(&declared);
        // Point the walk at `real` while the containment root stays `declared`.
        c.roots = vec![declared.clone()];
        let mut walked = c.clone();
        walked.roots = vec![real.clone()];

        // Walk `real`, check containment against `declared`.
        let mut refused = 0;
        for entry in walkdir::WalkDir::new(&real).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() && !c.contains(entry.path()) {
                refused += 1;
            }
        }
        assert_eq!(refused, 1, "a file outside the root must be refused");
        assert!(real.join("precious.txt").exists());

        std::fs::remove_dir_all(&real).ok();
        std::fs::remove_dir_all(&declared).ok();
    }

    #[test]
    fn an_empty_category_is_harmless() {
        let dir = temp("empty");
        let r = clean(&category_over(&dir), false);
        assert_eq!(r.files_removed, 0);
        assert_eq!(r.bytes_freed, 0);
        assert!(dir.is_dir());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_root_does_not_panic() {
        let c = category_over(Path::new(r"Z:\definitely\not\here"));
        let m = measure(&c);
        assert_eq!(m.bytes, 0);
        let r = clean(&c, false);
        assert_eq!(r.files_removed, 0);
    }

    #[test]
    fn prefetch_and_winsxs_are_never_offered() {
        // Cleaning Prefetch makes launches slower and is pure theatre; hand
        // deleting from WinSxS permanently breaks Windows servicing. Both are
        // staples of bad optimizers.
        for c in categories() {
            for root in &c.roots {
                let r = normalise(root);
                assert!(!r.contains("prefetch"), "{} offers Prefetch", c.id);
                assert!(!r.contains("winsxs"), "{} offers WinSxS", c.id);
                assert!(!r.ends_with(r"\windows"), "{} offers all of C:\\Windows", c.id);
                assert!(!r.contains("system32"), "{} offers System32", c.id);
            }
        }
    }

    #[test]
    fn no_category_touches_a_users_own_documents() {
        for c in categories() {
            for root in &c.roots {
                let r = normalise(root);
                for forbidden in ["\\documents", "\\desktop", "\\downloads", "\\pictures"] {
                    assert!(
                        !r.contains(forbidden),
                        "{} would delete from {forbidden}",
                        c.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_category_explains_its_cost() {
        for c in categories() {
            assert!(!c.description.is_empty(), "{} has no description", c.id);
            // Anything with a visible downside must not be pre-selected.
            if c.safety == Safety::Caution {
                assert!(
                    !c.default_selected,
                    "{} has a visible cost and must not be selected by default",
                    c.id
                );
            }
        }
    }

    #[test]
    fn analyze_runs_on_this_machine_and_sorts_by_size() {
        let results = analyze();
        for w in results.windows(2) {
            assert!(w[0].bytes >= w[1].bytes, "results are not sorted largest first");
        }
    }
}
