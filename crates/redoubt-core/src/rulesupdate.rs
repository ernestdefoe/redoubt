//! Fetching YARA rule sets.
//!
//! Rules come from public git repositories, pulled as GitHub tarballs rather
//! than by shelling out to `git`. That keeps the dependency surface to a
//! stream decompressor and avoids requiring git on the machine.
//!
//! Only `.yar`/`.yara` files under a source's declared subdirectory are
//! extracted, and each is written by its **base name only** - archive paths
//! are attacker-influenced in principle, so nothing from the tar is allowed to
//! steer where a file lands.

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::rules::RuleSet;

fn default_true() -> bool {
    true
}

/// A git repository publishing YARA rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraSource {
    /// Directory name under `paths.rules` to store this source's rules in.
    pub name: String,
    /// Repository URL, e.g. `https://github.com/elastic/protections-artifacts`.
    pub repo: String,
    pub branch: String,
    /// Only take rules under this path inside the repo. Empty means all.
    pub subdir: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl YaraSource {
    /// Owner and repository name parsed out of the URL.
    fn owner_repo(&self) -> Result<(String, String)> {
        let trimmed = self.repo.trim_end_matches('/').trim_end_matches(".git");
        // `rsplit` returns the whole string when the separator is absent, so
        // the host has to be checked explicitly - otherwise any URL at all
        // parses into a plausible-looking owner/repo pair.
        let Some((_, tail)) = trimmed.split_once("github.com/") else {
            bail!("only github.com rule repositories are supported, got {:?}", self.repo);
        };
        let mut parts = tail.split('/').filter(|s| !s.is_empty());
        match (parts.next(), parts.next()) {
            (Some(owner), Some(repo)) => Ok((owner.to_string(), repo.to_string())),
            _ => bail!("cannot parse a GitHub owner/repo out of {:?}", self.repo),
        }
    }

    /// The codeload tarball URL for this source.
    pub fn tarball_url(&self) -> Result<String> {
        let (owner, repo) = self.owner_repo()?;
        Ok(format!(
            "https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{}",
            self.branch
        ))
    }
}

/// The default rule sources.
///
/// Elastic's `protections-artifacts` is the pick here: actively maintained,
/// permissively licensed, and written for production use rather than as a
/// research dump - which matters, because a noisy rule set trains the user to
/// ignore alerts.
pub fn default_yara_sources() -> Vec<YaraSource> {
    vec![YaraSource {
        name: "elastic".to_string(),
        repo: "https://github.com/elastic/protections-artifacts".to_string(),
        branch: "main".to_string(),
        subdir: "yara/rules".to_string(),
        enabled: true,
    }]
}

/// What one source contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOutcome {
    pub name: String,
    pub files_written: usize,
    pub bytes: u64,
    pub error: Option<String>,
}

/// Result of a rules update.
#[derive(Debug, Clone)]
pub struct RuleUpdateReport {
    pub sources: Vec<SourceOutcome>,
    /// Rules that compiled after the update.
    pub compiled_rules: usize,
    /// Rule files that failed to compile, with the reason.
    pub compile_failures: Vec<(PathBuf, String)>,
}

impl RuleUpdateReport {
    pub fn total_files(&self) -> usize {
        self.sources.iter().map(|s| s.files_written).sum()
    }

    pub fn errors(&self) -> Vec<&str> {
        self.sources.iter().filter_map(|s| s.error.as_deref()).collect()
    }
}

fn is_rule_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".yar") || lower.ends_with(".yara")
}

/// Extract rule files from a gzipped tar stream into `dest`.
///
/// Returns `(files_written, bytes)`. The archive's directory structure is
/// discarded: each rule is written as `dest/<basename>`. That is deliberate -
/// it means no entry name can escape `dest`, however it is crafted.
fn extract_rules<R: Read>(reader: R, subdir: &str, dest: &Path) -> Result<(usize, u64)> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("creating {}", dest.display()))?;

    let mut archive = tar::Archive::new(GzDecoder::new(reader));
    let mut written = 0usize;
    let mut bytes = 0u64;

    for entry in archive.entries().context("reading rule archive")? {
        let mut entry = entry.context("reading rule archive entry")?;
        let path = entry.path().context("rule archive entry has a bad path")?.into_owned();
        let path_str = path.to_string_lossy().replace('\\', "/");

        // Strip the archive's top-level `<repo>-<branch>/` directory.
        let relative = match path_str.split_once('/') {
            Some((_, rest)) => rest.to_string(),
            None => continue,
        };
        if !subdir.is_empty() && !relative.starts_with(subdir) {
            continue;
        }

        let Some(base) = Path::new(&relative).file_name() else {
            continue;
        };
        let base = base.to_string_lossy().into_owned();
        if !is_rule_file(&base) {
            continue;
        }
        // Belt and braces: a base name can still not contain a separator, but
        // assert it rather than trust it.
        if base.contains('/') || base.contains('\\') || base.contains("..") {
            tracing::warn!(entry = %base, "skipping rule entry with a suspicious name");
            continue;
        }

        let mut data = Vec::new();
        entry.read_to_end(&mut data).with_context(|| format!("reading {base}"))?;
        std::fs::write(dest.join(&base), &data)
            .with_context(|| format!("writing rule {base}"))?;
        written += 1;
        bytes += data.len() as u64;
    }

    Ok((written, bytes))
}

/// Fetch every enabled source and recompile the rule set.
pub fn update_rules(cfg: &Config, mut progress: impl FnMut(&str)) -> Result<RuleUpdateReport> {
    std::fs::create_dir_all(&cfg.paths.rules)
        .with_context(|| format!("creating {}", cfg.paths.rules.display()))?;

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .user_agent(format!(
            "Redoubt/{} (+https://github.com/ernestdefoe/redoubt)",
            crate::VERSION
        ))
        .timeout_global(Some(std::time::Duration::from_secs(600)))
        .build()
        .into();

    let mut outcomes = Vec::new();

    for source in cfg.updates.yara_sources.iter().filter(|s| s.enabled) {
        let dest = cfg.paths.rules.join(&source.name);
        let outcome = match fetch_source(&agent, source, &dest, &mut progress) {
            Ok((files, bytes)) => SourceOutcome {
                name: source.name.clone(),
                files_written: files,
                bytes,
                error: None,
            },
            Err(e) => SourceOutcome {
                name: source.name.clone(),
                files_written: 0,
                bytes: 0,
                error: Some(format!("{e:#}")),
            },
        };
        outcomes.push(outcome);
    }

    progress("compiling rules...");
    let compiled = RuleSet::compile_dir(&cfg.paths.rules)?;

    Ok(RuleUpdateReport {
        sources: outcomes,
        compiled_rules: compiled.rule_count(),
        compile_failures: compiled.report().failed.clone(),
    })
}

fn fetch_source(
    agent: &ureq::Agent,
    source: &YaraSource,
    dest: &Path,
    progress: &mut impl FnMut(&str),
) -> Result<(usize, u64)> {
    let url = source.tarball_url()?;
    progress(&format!("  {:<12} {url}", source.name));

    let mut resp = agent
        .get(&url)
        .call()
        .with_context(|| format!("downloading {url}"))?;

    // Replace the source's directory wholesale, so rules deleted upstream do
    // not linger and keep firing after the publisher retracted them.
    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .with_context(|| format!("clearing {}", dest.display()))?;
    }

    extract_rules(resp.body_mut().as_reader(), &source.subdir, dest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut ar = tar::Builder::new(&mut tar_bytes);
            for (name, body) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                ar.append_data(&mut h, name, body.as_bytes()).unwrap();
            }
            ar.finish().unwrap();
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap()
    }

    /// Build a tar by hand.
    ///
    /// `tar::Builder` refuses to write an entry whose path contains `..`,
    /// which means it cannot produce the archive this needs to defend
    /// against. Writing the header directly is the only way to actually test
    /// the extractor against a hostile input rather than assume it is safe.
    fn hostile_tarball(files: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in files {
            let mut header = [0u8; 512];
            let name_bytes = name.as_bytes();
            header[..name_bytes.len()].copy_from_slice(name_bytes);
            header[100..107].copy_from_slice(b"000644 ");        // mode
            header[108..115].copy_from_slice(b"000000 ");        // uid
            header[116..123].copy_from_slice(b"000000 ");        // gid
            let size = format!("{:011o} ", body.len());
            header[124..136].copy_from_slice(size.as_bytes());
            header[136..148].copy_from_slice(b"00000000000 ");   // mtime
            header[156] = b'0';                                   // regular file
            header[257..263].copy_from_slice(b"ustar ");
            header[263..265].copy_from_slice(b"00");

            // Checksum is computed with the checksum field read as spaces.
            header[148..156].copy_from_slice(b"        ");
            let sum: u32 = header.iter().map(|&b| b as u32).sum();
            let chk = format!("{sum:06o}  ");
            header[148..156].copy_from_slice(chk.as_bytes());

            out.extend_from_slice(&header);
            out.extend_from_slice(body.as_bytes());
            let pad = (512 - body.len() % 512) % 512;
            out.extend(std::iter::repeat_n(0u8, pad));
        }
        out.extend(std::iter::repeat_n(0u8, 1024)); // end-of-archive

        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&out).unwrap();
        gz.finish().unwrap()
    }

    fn temp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir()
            .join(format!("redoubt-rulesupd-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn builds_the_codeload_url() {
        let s = &default_yara_sources()[0];
        assert_eq!(
            s.tarball_url().unwrap(),
            "https://codeload.github.com/elastic/protections-artifacts/tar.gz/refs/heads/main"
        );
    }

    #[test]
    fn parses_repo_urls_with_and_without_trailing_bits() {
        for repo in [
            "https://github.com/owner/name",
            "https://github.com/owner/name/",
            "https://github.com/owner/name.git",
        ] {
            let s = YaraSource {
                name: "x".into(),
                repo: repo.into(),
                branch: "main".into(),
                subdir: String::new(),
                enabled: true,
            };
            assert_eq!(
                s.tarball_url().unwrap(),
                "https://codeload.github.com/owner/name/tar.gz/refs/heads/main",
                "failed for {repo}"
            );
        }
    }

    #[test]
    fn rejects_a_url_that_is_not_a_github_repo() {
        let s = YaraSource {
            name: "x".into(),
            repo: "https://example.com/".into(),
            branch: "main".into(),
            subdir: String::new(),
            enabled: true,
        };
        assert!(s.tarball_url().is_err());
    }

    #[test]
    fn extracts_only_rule_files_under_the_subdir() {
        let dir = temp("subdir");
        let dest = dir.join("out");
        let tar = tarball(&[
            ("repo-main/yara/rules/Windows_Trojan.yar", "rule A { condition: true }"),
            ("repo-main/yara/rules/Linux_Backdoor.yara", "rule B { condition: true }"),
            // Outside the subdir - must be ignored.
            ("repo-main/docs/example.yar", "rule C { condition: true }"),
            // Right place, wrong type - must be ignored.
            ("repo-main/yara/rules/README.md", "not a rule"),
        ]);

        let (files, bytes) = extract_rules(&tar[..], "yara/rules", &dest).unwrap();
        assert_eq!(files, 2);
        assert!(bytes > 0);

        assert!(dest.join("Windows_Trojan.yar").is_file());
        assert!(dest.join("Linux_Backdoor.yara").is_file());
        assert!(!dest.join("example.yar").exists(), "a file outside the subdir was extracted");
        assert!(!dest.join("README.md").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_subdir_takes_every_rule_file() {
        let dir = temp("allsub");
        let dest = dir.join("out");
        let tar = tarball(&[
            ("repo-main/a/one.yar", "rule A { condition: true }"),
            ("repo-main/b/two.yar", "rule B { condition: true }"),
        ]);
        let (files, _) = extract_rules(&tar[..], "", &dest).unwrap();
        assert_eq!(files, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_traversal_in_the_archive_cannot_escape_the_destination() {
        // The security property: whatever the entry claims, the file lands in
        // `dest` under its base name and nowhere else.
        let dir = temp("traversal");
        let dest = dir.join("out");
        let canary = dir.join("evil.yar");

        let tar = hostile_tarball(&[
            ("repo-main/../../../../evil.yar", "rule Evil { condition: true }"),
            ("repo-main/rules/../../../also-evil.yar", "rule Evil2 { condition: true }"),
        ]);
        let (files, _) = extract_rules(&tar[..], "", &dest).unwrap();

        assert!(!canary.exists(), "an archive entry escaped the destination directory");
        // They are still extracted, but flattened into dest.
        assert_eq!(files, 2);
        assert!(dest.join("evil.yar").is_file());
        assert!(dest.join("also-evil.yar").is_file());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recognises_rule_extensions() {
        assert!(is_rule_file("a.yar"));
        assert!(is_rule_file("a.yara"));
        assert!(is_rule_file("A.YAR"));
        assert!(!is_rule_file("a.yarn"));
        assert!(!is_rule_file("a.txt"));
        assert!(!is_rule_file("yar"));
    }
}
