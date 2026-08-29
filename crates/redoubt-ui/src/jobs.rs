//! Background jobs.
//!
//! Scans and database updates take seconds to minutes, so they run on their
//! own thread and the page polls for progress. Each job owns a cancel flag
//! that the worker checks between files - cancelling has to be cooperative,
//! because killing a thread mid-scan would leak the mapped index.

use parking_lot::Mutex;
use redoubt_core::verdict::Verdict;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// What a job is doing. The UI renders scans differently from updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobKind {
    Scan,
    Db,
    Rules,
    /// Something that needs administrator rights, done by a separate elevated
    /// process. These finish when a person answers the consent dialog, which
    /// may be never, so the page shows them differently from work with a
    /// measurable amount of progress in it.
    Elevate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Running,
    Done,
    Error,
    Cancelled,
}

/// A job's public shape, serialised straight to the page.
#[derive(Debug, Clone, Serialize)]
pub struct JobView {
    pub id: u64,
    pub kind: JobKind,
    pub state: JobState,
    pub label: String,
    pub total: u64,
    pub done: u64,
    pub skipped: u64,
    pub malicious: u64,
    pub suspicious: u64,
    /// Path currently being worked on, for the ticker line.
    pub current: String,
    /// Files per second, averaged over the run so far.
    pub rate: f64,
    pub elapsed_secs: f64,
    pub findings: Vec<Verdict>,
    pub summary: Option<String>,
    pub error: Option<String>,
}

/// A job's mutable interior.
pub struct Job {
    pub kind: JobKind,
    pub state: JobState,
    pub label: String,
    pub total: u64,
    pub done: u64,
    pub skipped: u64,
    pub malicious: u64,
    pub suspicious: u64,
    pub current: String,
    pub started: Instant,
    pub findings: Vec<Verdict>,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub cancel: Arc<AtomicBool>,
}

impl Job {
    fn new(kind: JobKind, label: String) -> Self {
        Self {
            kind,
            state: JobState::Running,
            label,
            total: 0,
            done: 0,
            skipped: 0,
            malicious: 0,
            suspicious: 0,
            current: String::new(),
            started: Instant::now(),
            findings: Vec::new(),
            summary: None,
            error: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Findings sent to the page, worst first.
    ///
    /// Capped: a scan of a badly infected directory could otherwise try to
    /// serialise tens of thousands of verdicts into every poll response.
    fn visible_findings(&self) -> Vec<Verdict> {
        const MAX: usize = 500;
        let mut v = self.findings.clone();
        v.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.scan_micros.cmp(&a.scan_micros))
        });
        v.truncate(MAX);
        v
    }

    fn view(&self, id: u64) -> JobView {
        let elapsed = self.started.elapsed().as_secs_f64().max(1e-6);
        JobView {
            id,
            kind: self.kind,
            state: self.state,
            label: self.label.clone(),
            total: self.total,
            done: self.done,
            skipped: self.skipped,
            malicious: self.malicious,
            suspicious: self.suspicious,
            current: self.current.clone(),
            rate: self.done as f64 / elapsed,
            elapsed_secs: elapsed,
            findings: self.visible_findings(),
            summary: self.summary.clone(),
            error: self.error.clone(),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// Handle to one job, shared between the worker thread and the HTTP handlers.
pub type JobHandle = Arc<Mutex<Job>>;

/// Registry of every job this process has run.
#[derive(Default)]
pub struct Jobs {
    inner: Mutex<HashMap<u64, JobHandle>>,
    next_id: AtomicU64,
    /// Only one job at a time: scans and database recompiles both want the
    /// whole machine, and running two at once just makes both slower while
    /// making the progress display incoherent.
    active: Mutex<Option<u64>>,
}

impl Jobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new job, or return `None` if one is already running.
    pub fn start(&self, kind: JobKind, label: impl Into<String>) -> Option<(u64, JobHandle)> {
        let mut active = self.active.lock();
        if active.is_some() {
            return None;
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let handle: JobHandle = Arc::new(Mutex::new(Job::new(kind, label.into())));
        self.inner.lock().insert(id, handle.clone());
        *active = Some(id);
        Some((id, handle))
    }

    /// Mark a job finished and release the single-job slot.
    pub fn finish(&self, id: u64, state: JobState) {
        if let Some(handle) = self.inner.lock().get(&id) {
            let mut job = handle.lock();
            // A cancelled job stays cancelled even if the worker ran to
            // completion in the meantime.
            if job.state == JobState::Running {
                job.state = state;
            }
        }
        let mut active = self.active.lock();
        if *active == Some(id) {
            *active = None;
        }
    }

    pub fn get(&self, id: u64) -> Option<JobHandle> {
        self.inner.lock().get(&id).cloned()
    }

    pub fn view(&self, id: u64) -> Option<JobView> {
        self.get(id).map(|h| h.lock().view(id))
    }

    pub fn cancel(&self, id: u64) -> bool {
        match self.get(id) {
            Some(handle) => {
                let mut job = handle.lock();
                job.cancel.store(true, Ordering::Relaxed);
                job.state = JobState::Cancelled;
                true
            }
            None => false,
        }
    }

    pub fn active_id(&self) -> Option<u64> {
        *self.active.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_job_runs_at_a_time() {
        let jobs = Jobs::new();
        let (id, _h) = jobs.start(JobKind::Scan, "scan").expect("first should start");
        assert!(
            jobs.start(JobKind::Db, "update").is_none(),
            "a second job must be refused while one is running"
        );

        jobs.finish(id, JobState::Done);
        assert!(jobs.start(JobKind::Db, "update").is_some(), "slot should free up");
    }

    #[test]
    fn ids_are_unique_and_increasing() {
        let jobs = Jobs::new();
        let (a, _) = jobs.start(JobKind::Scan, "a").unwrap();
        jobs.finish(a, JobState::Done);
        let (b, _) = jobs.start(JobKind::Scan, "b").unwrap();
        assert!(b > a);
    }

    #[test]
    fn cancelling_sets_the_flag_the_worker_watches() {
        let jobs = Jobs::new();
        let (id, handle) = jobs.start(JobKind::Scan, "scan").unwrap();
        assert!(!handle.lock().is_cancelled());

        assert!(jobs.cancel(id));
        assert!(handle.lock().is_cancelled());
        assert_eq!(jobs.view(id).unwrap().state, JobState::Cancelled);
    }

    #[test]
    fn finishing_does_not_overwrite_a_cancellation() {
        // The worker calls finish() after it notices the cancel flag; that
        // must not relabel the job as a clean completion.
        let jobs = Jobs::new();
        let (id, _) = jobs.start(JobKind::Scan, "scan").unwrap();
        jobs.cancel(id);
        jobs.finish(id, JobState::Done);
        assert_eq!(jobs.view(id).unwrap().state, JobState::Cancelled);
    }

    #[test]
    fn unknown_ids_are_handled() {
        let jobs = Jobs::new();
        assert!(jobs.view(999).is_none());
        assert!(!jobs.cancel(999));
    }

    #[test]
    fn view_reports_progress_and_rate() {
        let jobs = Jobs::new();
        let (id, handle) = jobs.start(JobKind::Scan, "scan").unwrap();
        {
            let mut j = handle.lock();
            j.total = 100;
            j.done = 40;
            j.malicious = 2;
        }
        let v = jobs.view(id).unwrap();
        assert_eq!(v.total, 100);
        assert_eq!(v.done, 40);
        assert_eq!(v.malicious, 2);
        assert!(v.rate > 0.0, "rate should be derived from elapsed time");
        assert_eq!(v.state, JobState::Running);
    }

    #[test]
    fn findings_are_capped_and_sorted_worst_first() {
        use redoubt_core::verdict::{Detection, Engine, FileIdentity, Severity};
        use std::path::PathBuf;

        let jobs = Jobs::new();
        let (id, handle) = jobs.start(JobKind::Scan, "scan").unwrap();
        {
            let mut j = handle.lock();
            for i in 0..600 {
                let sev = if i == 599 { Severity::Malicious } else { Severity::Suspicious };
                let mut v = Verdict::clean(
                    PathBuf::from(format!("C:/f{i}.bin")),
                    FileIdentity::default(),
                    1,
                );
                v.detections.push(Detection::new("X", Engine::Heuristic, sev));
                v.recompute_severity();
                j.findings.push(v);
            }
        }
        let v = jobs.view(id).unwrap();
        assert_eq!(v.findings.len(), 500, "the response must stay bounded");
        assert_eq!(
            v.findings[0].severity,
            Severity::Malicious,
            "the worst finding must survive truncation"
        );
    }
}
