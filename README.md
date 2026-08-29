# Redoubt

A Windows antivirus engine, built from scratch in Rust.

Redoubt compiles ClamAV-format signature databases and YARA rule sets into a
single memory-mapped index, then scans against them with five independent
engines. It runs **observe-first**: it detects, logs and reports, and does not
quarantine anything until you explicitly turn enforcement on.

---

## Status

| Component | State |
|---|---|
| Signature engine (hashes, sections, body patterns) | **Working** |
| YARA engine | **Working** — 3,021 rules |
| Heuristics | **Working** — 6 checks, tuned against a real System32 sweep |
| Signature + rule updating | **Working** |
| On-demand scanning (`redoubt scan`) | **Working** |
| Verdict cache | **Built**, not yet wired into a live service |
| Real-time service (`redoubtd`) | **Not built yet** |
| AMSI provider | **Not built yet** |
| Filesystem minifilter | **Not built yet** |
| GUI | **Not built yet** |
| PC optimizer | **Not built yet** |

The engine everything else plugs into is finished and proven against real data.
The parts that make it *resident* are the next chunk of work.

---

## What it detects with

Five engines, each independently switchable in `config.toml`:

1. **Whole-file hashes** — MD5 / SHA-1 / SHA-256, from ClamAV `.hdb`/`.hsb` and
   third-party sources. One binary search, definitive.
2. **PE section hashes** — ClamAV `.mdb`/`.msb`. These survive the repacking
   that defeats a whole-file hash.
3. **Body patterns** — literal byte signatures from ClamAV `.ndb`, compiled into
   a single Aho-Corasick automaton, filtered by target type and offset.
4. **YARA** — via `yara-x`, VirusTotal's Rust implementation.
5. **Heuristics** — entropy, writable+executable sections, minimal imports,
   filename tricks. These **only ever produce `suspicious`**, never `malicious`,
   and are structurally barred from triggering enforcement.

Signatures from ClamAV's `PUA.` namespace (packers, adware bundlers) are mapped
to `suspicious` rather than `malicious` — Windows' own `MRT.exe` trips two of
them, and reporting that as malware on a stock install destroys trust in the
tool.

## Where signatures come from

**ClamAV main/daily — via real `freshclam`.** ClamAV's CDN answers only to their
own client (`ClamAV/*` user agent; everything else gets a 403). Rather than
impersonate it, Redoubt drives the genuine binary with its own generated config.
That is also better engineering: freshclam does incremental `.cdiff` updates —
kilobytes rather than a 200 MB container — plus mirror failover and version
checks.

```bash
winget install Cisco.ClamAV
```

**Third-party ClamAV-format databases — fetched directly.** Sanesecurity and
abuse.ch URLhaus publish plain `.ndb`/`.hdb`/`.hsb` files and permit direct
download, so those Redoubt fetches itself, with conditional requests so a poll
that finds nothing new costs one 304.

**YARA rules** — Elastic's `protections-artifacts`, pulled as a GitHub tarball.

## Why the index is memory-mapped

A `HashMap` of ~3.3 million signatures costs well over a gigabyte resident.
That is why ClamAV itself is known for RAM use, and it is unacceptable for
something that sits running all day on a desktop.

Redoubt instead compiles the databases into sorted, fixed-stride records in a
single file and `mmap`s it. Lookups are a binary search over borrowed bytes: no
heap allocation, no deserialisation, and the OS page cache keeps only the pages
actually touched resident.

Compilation happens in the updater, never on the scan path.

---

## Usage

```bash
redoubt db update          # freshclam + third-party sources, then recompile
redoubt rules update       # fetch and compile YARA rules
redoubt db status          # what is loaded
redoubt scan C:\Users\me\Downloads
```

Useful flags on `scan`:

- `--show-clean` — list files that came back clean too
- `--show-skipped` — list files that were *not* scanned, and why
- `--json` — one JSON verdict per line
- `-j N` — worker threads

Configuration lives at `%ProgramData%\Redoubt\config.toml` and is created with
full defaults on first run. `redoubt config` prints the resolved settings.

### Observe vs enforce

`mode = "observe"` is the default and means exactly what it says: nothing is
quarantined, nothing is killed. Switch to `enforce` only once you have reviewed
what it finds on your own machine. Heuristic and PUA findings are never
enforceable regardless of mode.

---

## Known gaps

Stated plainly, because a scanner that quietly covers less than it claims is
worse than one that admits what it misses.

- **ClamAV `.ldb` logical signatures are not evaluated.** That is ~86 MB of
  signature data across `daily.ldb` and `main.ldb`, and it is the single
  largest detection gap. They are multi-pattern boolean rules and need a
  matcher this engine does not yet have.
- **`.ndb` patterns using wildcards are skipped.** Nibble wildcards, gaps,
  ranges and alternation are all unsupported; only literal patterns of 16+
  bytes are indexed. `redoubt db update` reports exactly how many were refused.
- **`.cbc` bytecode is out of scope permanently** — it needs ClamAV's VM.
- **CVD digital signatures are not verified.** Integrity currently rests on
  fetching over HTTPS from the official mirror.
- **No archive expansion yet.** `scan.archive_depth` exists in the config but
  is not wired up.
- **The verdict cache is not yet used** by anything, because there is no
  resident service to use it.

`redoubt db update` prints a per-format breakdown of everything it could not
index, with an explanation of each.

---

## Building

Needs Rust (MSVC toolchain) and VS Build Tools.

```bash
cargo build --release
```

`.cargo/config.toml` forces the build directory outside OneDrive — a Rust
`target/` directory is tens of thousands of small files, and letting OneDrive
sync it will bring the machine to its knees.

```bash
cargo test
```

## Layout

```
crates/
  redoubt-core/     engine: containers, signature parsing, index, scanning
  redoubt-cli/      the `redoubt` binary
  redoubt-service/  Windows service host (skeleton)
```

`redoubt-core` has no Windows event plumbing in it — it takes bytes and paths
and returns verdicts. The service crate owns ETW, AMSI and the rest of the OS
integration and calls into it.
