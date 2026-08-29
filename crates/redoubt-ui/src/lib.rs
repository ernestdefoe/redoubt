//! Redoubt's local interface.
//!
//! A small HTTP server bound to loopback, serving the embedded UI assets and a
//! JSON API over the scanning engine. The page is plain HTML/CSS/JS talking to
//! this API, which means the same interface works whether it is opened in a
//! browser or wrapped in a desktop window later - there is no second transport
//! to keep in sync.
//!
//! Binding is **127.0.0.1 only**. This exposes scan control and configuration,
//! so it must never be reachable off the machine.

pub mod jobs;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use redoubt_core::config::{Config, Mode};
use redoubt_core::scanner::{ScanEngine, ScanOutcome};
use redoubt_core::verdict::Severity;
use serde::Serialize;
use serde_json::json;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use jobs::{JobKind, JobState, Jobs};

// UI assets are compiled in, so the binary is self-contained and cannot be
// served a tampered page from a writable directory next to it.
const INDEX_HTML: &str = include_str!("../../../ui/src/index.html");
const APP_JS: &str = include_str!("../../../ui/src/app.js");
const APP_CSS: &str = include_str!("../../../ui/dist/app.css");

/// Shared application state.
pub struct App {
    cfg: RwLock<Config>,
    config_path: PathBuf,
    /// `None` until an index exists. The UI stays usable without one so the
    /// user can press "Update signatures" rather than meeting a dead page.
    engine: RwLock<Option<Arc<ScanEngine>>>,
    jobs: Jobs,
}

impl App {
    pub fn new(cfg: Config, config_path: PathBuf) -> Self {
        let engine = ScanEngine::load(cfg.clone()).ok().map(Arc::new);
        Self {
            cfg: RwLock::new(cfg),
            config_path,
            engine: RwLock::new(engine),
            jobs: Jobs::new(),
        }
    }

    fn config(&self) -> Config {
        self.cfg.read().clone()
    }

    /// Rebuild the engine from the current config and signature files.
    fn reload_engine(&self) -> Result<()> {
        let engine = ScanEngine::load(self.config())?;
        *self.engine.write() = Some(Arc::new(engine));
        Ok(())
    }

    fn engine(&self) -> Option<Arc<ScanEngine>> {
        self.engine.read().clone()
    }
}

/* ────────────────────────────  status payload  ──────────────────────────── */

#[derive(Serialize)]
struct SourceRow {
    name: String,
    kind: &'static str,
    signatures: Option<u64>,
    detail: Option<String>,
}

#[derive(Serialize)]
struct GapRow {
    extension: String,
    files: usize,
    bytes: usize,
    note: String,
}

/// Coverage gaps from the last compile.
///
/// These are read from the report sidecar the compiler writes beside the
/// index. They cannot be derived by listing the signature directory: the
/// unindexed formats live *inside* the `.cvd` containers, so a directory
/// listing reports no gaps at all, which is the opposite of the truth.
fn gaps_for(index_path: &Path) -> Vec<GapRow> {
    let Some(summary) = redoubt_core::compile::CompileSummary::load_beside(index_path) else {
        return Vec::new();
    };
    summary
        .skipped
        .into_iter()
        .map(|s| GapRow {
            extension: s.extension,
            files: s.files,
            bytes: s.bytes,
            note: s.note,
        })
        .collect()
}

fn sources_for(cfg: &Config) -> Vec<SourceRow> {
    let dir = &cfg.paths.signatures;
    let mut rows = Vec::new();

    for name in ["main.cvd", "main.cld", "daily.cvd", "daily.cld"] {
        let path = dir.join(name);
        if let Ok(header) = redoubt_core::cvd::read_header(&path) {
            rows.push(SourceRow {
                name: name.to_string(),
                kind: "freshclam",
                signatures: Some(header.signature_count as u64),
                detail: Some(format!("v{}", header.version)),
            });
        }
    }

    for src in &cfg.updates.direct_sources {
        let path = dir.join(&src.name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        rows.push(SourceRow {
            name: src.name.clone(),
            kind: "direct",
            signatures: None,
            detail: Some(format!("{:.0} KiB", meta.len() as f64 / 1024.0)),
        });
    }

    for src in cfg.updates.yara_sources.iter().filter(|s| s.enabled) {
        let dir = cfg.paths.rules.join(&src.name);
        let count = walkdir::WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count();
        if count > 0 {
            rows.push(SourceRow {
                name: src.name.clone(),
                kind: "yara",
                signatures: None,
                detail: Some(format!("{count} rule files")),
            });
        }
    }

    rows
}

fn presets() -> Vec<serde_json::Value> {
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let mut out = Vec::new();
    if let Some(home) = &home {
        for (label, sub) in [
            ("Downloads", "Downloads"),
            ("Desktop", "Desktop"),
            ("Documents", "Documents"),
        ] {
            let p = home.join(sub);
            if p.is_dir() {
                out.push(json!({ "label": label, "path": p.to_string_lossy() }));
            }
        }
    }
    if let Some(tmp) = std::env::var_os("TEMP") {
        out.push(json!({ "label": "Temp", "path": PathBuf::from(tmp).to_string_lossy() }));
    }
    out.push(json!({ "label": "Windows", "path": "C:\\Windows\\System32" }));
    out
}

fn status_json(app: &App) -> serde_json::Value {
    let cfg = app.config();
    let index_path = cfg.paths.signatures.join("redoubt.sigidx");
    let index_bytes = std::fs::metadata(&index_path).map(|m| m.len()).unwrap_or(0);

    let engine = match app.engine() {
        Some(e) => {
            let s = e.stats();
            json!({
                "loaded": true,
                "db_version": s.db_version,
                "file_hashes": s.file_hashes,
                "section_hashes": s.section_hashes,
                "body_patterns": s.body_patterns,
                "allowlisted": s.allowlisted,
                "yara_rules": s.yara_rules,
                "index_bytes": index_bytes,
                "built_epoch": s.built_epoch,
            })
        }
        None => json!({
            "loaded": false,
            "db_version": 0, "file_hashes": 0, "section_hashes": 0,
            "body_patterns": 0, "allowlisted": 0, "yara_rules": 0,
            "index_bytes": 0, "built_epoch": 0,
        }),
    };

    json!({
        "version": redoubt_core::VERSION,
        "mode": cfg.mode.as_str(),
        "engine": engine,
        // Stated plainly rather than showing a green light for something that
        // is not running.
        "realtime": {
            "running": false,
            "note": "On-demand scanning only. The resident service is not installed yet.",
        },
        "gaps": gaps_for(&index_path),
        "sources": sources_for(&cfg),
        "presets": presets(),
        "active_job": app.jobs.active_id(),
    })
}

/* ────────────────────────────  workers  ──────────────────────────── */

fn spawn_scan(app: Arc<App>, id: u64, handle: jobs::JobHandle, root: PathBuf) {
    std::thread::spawn(move || {
        let Some(engine) = app.engine() else {
            let mut job = handle.lock();
            job.error = Some("No signature index loaded. Update signatures first.".into());
            drop(job);
            app.jobs.finish(id, JobState::Error);
            return;
        };

        // Enumerate first so the progress bar has a denominator.
        let mut files = Vec::new();
        if root.is_file() {
            files.push(root.clone());
        } else {
            for entry in walkdir::WalkDir::new(&root).into_iter().flatten() {
                if entry.file_type().is_file() {
                    files.push(entry.into_path());
                }
                if handle.lock().is_cancelled() {
                    break;
                }
            }
        }
        handle.lock().total = files.len() as u64;

        let cancel = handle.lock().cancel.clone();
        {
            use rayon::prelude::*;
            files.par_iter().for_each_init(
                || engine.session(),
                |session, path| {
                    if cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    match session.scan_path(path) {
                        ScanOutcome::Skipped(_) => {
                            handle.lock().skipped += 1;
                        }
                        ScanOutcome::Scanned(v) => {
                            let mut job = handle.lock();
                            job.done += 1;
                            job.current = path.to_string_lossy().into_owned();
                            match v.severity {
                                Severity::Malicious => job.malicious += 1,
                                Severity::Suspicious => job.suspicious += 1,
                                Severity::Clean => {}
                            }
                            if !v.is_clean() {
                                job.findings.push(*v);
                            }
                        }
                    }
                },
            );
        }

        {
            let mut job = handle.lock();
            job.current.clear();
            job.summary = Some(format!(
                "{} scanned, {} malicious, {} suspicious",
                job.done, job.malicious, job.suspicious
            ));
        }
        app.jobs.finish(id, JobState::Done);
    });
}

fn spawn_db_update(app: Arc<App>, id: u64, handle: jobs::JobHandle) {
    std::thread::spawn(move || {
        let cfg = app.config();
        let index_path = cfg.paths.signatures.join("redoubt.sigidx");

        let result = redoubt_core::update::update(&cfg, &index_path, false, |line| {
            handle.lock().current = line.to_string();
        });

        let state = match result {
            Ok(report) => {
                let mut job = handle.lock();
                job.summary = Some(match &report.recompiled {
                    Some(c) => c.summary(),
                    None => "Signatures already up to date".to_string(),
                });
                let warnings = report.warnings();
                if !warnings.is_empty() {
                    job.error = Some(warnings.join("; "));
                }
                drop(job);
                if let Err(e) = app.reload_engine() {
                    handle.lock().error = Some(format!("index compiled but would not load: {e:#}"));
                }
                JobState::Done
            }
            Err(e) => {
                handle.lock().error = Some(format!("{e:#}"));
                JobState::Error
            }
        };
        app.jobs.finish(id, state);
    });
}

fn spawn_rules_update(app: Arc<App>, id: u64, handle: jobs::JobHandle) {
    std::thread::spawn(move || {
        let cfg = app.config();
        let result = redoubt_core::rulesupdate::update_rules(&cfg, |line| {
            handle.lock().current = line.to_string();
        });

        let state = match result {
            Ok(report) => {
                let mut job = handle.lock();
                job.summary = Some(format!(
                    "{} rules compiled from {} file(s)",
                    report.compiled_rules,
                    report.total_files()
                ));
                let errs = report.errors();
                if !errs.is_empty() {
                    job.error = Some(errs.join("; "));
                }
                drop(job);
                if let Err(e) = app.reload_engine() {
                    handle.lock().error = Some(format!("rules compiled but would not load: {e:#}"));
                }
                JobState::Done
            }
            Err(e) => {
                handle.lock().error = Some(format!("{e:#}"));
                JobState::Error
            }
        };
        app.jobs.finish(id, state);
    });
}

/* ────────────────────────────  HTTP  ──────────────────────────── */

fn json_response(value: serde_json::Value, status: u16) -> tiny_http::Response<Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    tiny_http::Response::from_data(body)
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        )
}

fn asset(body: &str, mime: &str) -> tiny_http::Response<Cursor<Vec<u8>>> {
    tiny_http::Response::from_data(body.as_bytes().to_vec()).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap(),
    )
}

fn read_body(request: &mut tiny_http::Request) -> serde_json::Value {
    let mut s = String::new();
    if request.as_reader().read_to_string(&mut s).is_err() {
        return json!({});
    }
    serde_json::from_str(&s).unwrap_or_else(|_| json!({}))
}

/// Route one request. Split out from the accept loop so it is testable.
fn handle(app: &Arc<App>, request: &mut tiny_http::Request) -> tiny_http::Response<Cursor<Vec<u8>>> {
    let url = request.url().split('?').next().unwrap_or("/").to_string();
    let method = request.method().clone();
    use tiny_http::Method;

    match (&method, url.as_str()) {
        (Method::Get, "/") | (Method::Get, "/index.html") => asset(INDEX_HTML, "text/html; charset=utf-8"),
        (Method::Get, "/app.js") => asset(APP_JS, "text/javascript; charset=utf-8"),
        (Method::Get, "/app.css") => asset(APP_CSS, "text/css; charset=utf-8"),

        (Method::Get, "/api/status") => json_response(status_json(app), 200),
        (Method::Get, "/api/config") => {
            json_response(serde_json::to_value(app.config()).unwrap_or(json!({})), 200)
        }

        (Method::Post, "/api/config") => {
            let patch = read_body(request);
            let mut cfg = app.cfg.write();
            if let Some(mode) = patch.get("mode").and_then(|m| m.as_str()) {
                cfg.mode = if mode == "enforce" { Mode::Enforce } else { Mode::Observe };
            }
            if let Some(engines) = patch.get("engines") {
                if let Ok(e) = serde_json::from_value(engines.clone()) {
                    cfg.engines = e;
                }
            }
            if let Some(h) = patch.get("heuristics") {
                if let Ok(h) = serde_json::from_value(h.clone()) {
                    cfg.heuristics = h;
                }
            }
            let saved = cfg.save(&app.config_path);
            let cfg = cfg.clone();
            drop(app.cfg.write());
            match saved {
                Ok(()) => {
                    // Engine switches change what runs, so rebuild.
                    let _ = app.reload_engine();
                    json_response(serde_json::to_value(cfg).unwrap_or(json!({})), 200)
                }
                Err(e) => json_response(json!({ "error": format!("{e:#}") }), 500),
            }
        }

        (Method::Post, "/api/scan") => {
            let body = read_body(request);
            let Some(path) = body.get("path").and_then(|p| p.as_str()) else {
                return json_response(json!({ "error": "no path given" }), 400);
            };
            let root = PathBuf::from(path);
            if !root.exists() {
                return json_response(
                    json!({ "error": format!("{} does not exist", root.display()) }),
                    400,
                );
            }
            match app.jobs.start(JobKind::Scan, "Scanning") {
                Some((id, handle)) => {
                    spawn_scan(app.clone(), id, handle, root);
                    json_response(json!({ "id": id }), 200)
                }
                None => json_response(json!({ "error": "another job is running" }), 409),
            }
        }

        (Method::Post, "/api/db/update") => match app.jobs.start(JobKind::Db, "Updating signatures") {
            Some((id, handle)) => {
                spawn_db_update(app.clone(), id, handle);
                json_response(json!({ "id": id }), 200)
            }
            None => json_response(json!({ "error": "another job is running" }), 409),
        },

        (Method::Post, "/api/rules/update") => {
            match app.jobs.start(JobKind::Rules, "Updating rules") {
                Some((id, handle)) => {
                    spawn_rules_update(app.clone(), id, handle);
                    json_response(json!({ "id": id }), 200)
                }
                None => json_response(json!({ "error": "another job is running" }), 409),
            }
        }

        (Method::Get, path) if path.starts_with("/api/job/") => {
            let id: u64 = path.trim_start_matches("/api/job/").parse().unwrap_or(0);
            match app.jobs.view(id) {
                Some(v) => json_response(serde_json::to_value(v).unwrap_or(json!({})), 200),
                None => json_response(json!({ "error": "no such job" }), 404),
            }
        }

        (Method::Post, path) if path.starts_with("/api/job/") && path.ends_with("/cancel") => {
            let id: u64 = path
                .trim_start_matches("/api/job/")
                .trim_end_matches("/cancel")
                .parse()
                .unwrap_or(0);
            json_response(json!({ "cancelled": app.jobs.cancel(id) }), 200)
        }

        _ => json_response(json!({ "error": "not found" }), 404),
    }
}

/// Start the server and block. Returns the bound port via `on_ready`.
pub fn serve(cfg: Config, config_path: PathBuf, port: u16, on_ready: impl FnOnce(u16)) -> Result<()> {
    let app = Arc::new(App::new(cfg, config_path));

    // Loopback only. This API can start scans and change enforcement mode.
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let server = tiny_http::Server::http(addr)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("binding {addr}"))?;
    let bound = server.server_addr().to_ip().map(|a| a.port()).unwrap_or(port);
    on_ready(bound);

    let server = Arc::new(server);
    let workers = 4;
    let mut handles = Vec::new();
    for _ in 0..workers {
        let server = server.clone();
        let app = app.clone();
        handles.push(std::thread::spawn(move || loop {
            let Ok(mut request) = server.recv() else {
                break;
            };
            let response = handle(&app, &mut request);
            let _ = request.respond(response);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assets_are_embedded_and_non_empty() {
        assert!(INDEX_HTML.contains("<title>Redoubt</title>"));
        assert!(APP_JS.contains("api"));
        // If the stylesheet was not built, the page renders as unstyled HTML
        // and nothing else in the UI is worth looking at.
        assert!(APP_CSS.len() > 10_000, "app.css looks unbuilt ({} bytes)", APP_CSS.len());
        assert!(APP_CSS.contains("--color-base-100"), "the Redoubt theme is missing");
    }

    #[test]
    fn presets_are_absolute_paths() {
        for p in presets() {
            let path = p["path"].as_str().unwrap();
            assert!(
                path.len() > 2 && path.as_bytes()[1] == b':',
                "preset {path:?} is not an absolute Windows path"
            );
        }
    }

    #[test]
    fn gaps_come_from_the_compile_sidecar_not_a_directory_listing() {
        // The formats we cannot evaluate live INSIDE the .cvd containers, so
        // listing the signature directory reports zero gaps - which reads as
        // "full coverage" when the opposite is true. This is the regression
        // that check exists to prevent.
        use redoubt_core::compile::{CompileSummary, SkippedFormat};

        let dir = std::env::temp_dir().join(format!("redoubt-gaps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("redoubt.sigidx");

        // A directory that looks fully covered: only containers, no loose
        // files in any unsupported format.
        std::fs::write(dir.join("daily.cvd"), b"x").unwrap();
        std::fs::write(&index, b"x").unwrap();
        assert!(gaps_for(&index).is_empty(), "no sidecar yet");

        let summary = CompileSummary {
            skipped: vec![SkippedFormat {
                extension: "ldb".into(),
                files: 2,
                bytes: 88_000_000,
                note: "logical signatures - the largest gap".into(),
            }],
            ..Default::default()
        };
        std::fs::write(
            CompileSummary::path_for(&index),
            serde_json::to_string(&summary).unwrap(),
        )
        .unwrap();

        let rows = gaps_for(&index);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extension, "ldb");
        assert_eq!(rows[0].bytes, 88_000_000);
        assert!(
            rows[0].note.contains("logical"),
            "a gap must say what it is, not just name an extension"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gaps_of_a_missing_index_is_empty_not_a_panic() {
        assert!(gaps_for(Path::new("Z:/definitely/not/here.sigidx")).is_empty());
    }
}
