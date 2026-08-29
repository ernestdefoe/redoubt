//! Redoubt scanning engine.
//!
//! This crate is deliberately free of Windows-specific event plumbing: it
//! takes bytes and paths and returns [`verdict::Verdict`]s. The service crate
//! owns ETW, AMSI and the rest of the OS integration and calls in here.
//!
//! The pieces:
//!
//! - [`config`]   - on-disk settings, with observe-mode as the default
//! - [`cvd`]      - reader for ClamAV `.cvd`/`.cld` database containers
//! - [`sigs`]     - parsers for the signature text formats inside them
//! - [`sigindex`] - the compiled, memory-mapped index those parsers feed

pub mod archive;
pub mod bodyscan;
pub mod blocklist;
pub mod blocklistupdate;
pub mod cache;
pub mod compile;
pub mod config;
pub mod cvd;
pub mod hashing;
pub mod heuristics;
pub mod ldb;
pub mod pe;
pub mod quarantine;
pub mod rules;
pub mod rulesupdate;
pub mod scanner;
pub mod sigindex;
pub mod sigs;
pub mod update;
pub mod textform;
pub mod verdict;

pub use config::{Config, Mode};
pub use verdict::{Detection, Engine, FileIdentity, Severity, Verdict};

/// Version of this build, from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
