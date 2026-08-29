# Redoubt

A Windows antivirus and system maintenance tool, built from scratch in Rust.

Redoubt compiles ClamAV-format signature databases and YARA rule sets into a
single memory-mapped index, scans against them with five independent engines,
and watches the places files actually arrive.

It runs **observe-first**: it detects, logs and reports, and does not quarantine
anything until you explicitly turn enforcement on.

---

## Status

| Component | State |
|---|---|
| Signature engine (hashes, sections, body patterns) | **Working** |
| YARA engine | **Working** — 3,021 rules |
| Heuristics | **Working** — tuned against a real System32 sweep |
| Signature + rule updating | **Working** |
| On-demand scanning | **Working** |
| Real-time protection | **Working** — file watching, detect-and-react |
| Quarantine + restore | **Working** |
| Desktop interface | **Working** |
| Disk cleanup | **Working** |
| Startup manager | **Working** |
| AMSI provider (script blocking) | Not built |
| Filesystem minifilter (pre-execution blocking) | Not built |
| Windows service registration | Not built |

194 tests.

---

## What it detects with

Five engines, each independently switchable:

1. **Whole-file hashes** — MD5 / SHA-1 / SHA-256. One binary search, definitive.
2. **PE section hashes** — these survive the repacking that defeats a file hash.
3. **Body patterns** — literal byte signatures compiled into a single
   Aho-Corasick automaton, filtered by target type and offset.
4. **YARA** — via `yara-x`, VirusTotal's Rust implementation.
5. **Heuristics** — entropy, writable+executable sections, minimal imports,
   filename tricks. These **only ever produce `suspicious`**, and
   `Severity::is_actionable()` structurally bars them from enforcement.

Signatures in ClamAV's `PUA.` namespace map to `suspicious` rather than
`malicious` — Windows' own `MRT.exe` trips two packer signatures, and reporting
that as malware on a stock install destroys trust in the tool.

## Real-time protection

Watches Downloads, Desktop, Documents, `%TEMP%` and `%LOCALAPPDATA%`, and scans
what changes. No driver, no elevation.

This is **detect-and-react**, not pre-execution blocking: a file is scanned
shortly after it lands, not before it can be opened. That is honest and useful
for how malware usually arrives on a desktop, and the UI says exactly this
rather than implying more.

A single file copy produces a burst of change notifications, so paths are held
for a settle period and coalesced — one copy costs one scan. Verdicts are cached
on path + size + mtime + signature generation, so repeat events are nearly free.

### Quarantine

Stored payloads are XOR-neutralised so a quarantined sample cannot be executed
by accident or matched by another scanner on the same machine. This is
tamper-resistance, not encryption, and the key sits in the manifest — because
restore has to work.

The payload is written and fsynced, and the manifest updated, *before* the
original is removed. A crash leaves either the original or a complete
quarantine entry, never neither. Restore is byte-exact and refuses to overwrite
a file that reappeared in the meantime.

## Where signatures come from

**ClamAV main/daily — via real `freshclam`.** ClamAV's CDN answers only to their
own client (everything else gets a 403). Rather than impersonate it, Redoubt
drives the genuine binary with its own generated config. That is also better
engineering: freshclam does incremental `.cdiff` updates — kilobytes rather than
a 200 MB container.

```bash
winget install Cisco.ClamAV
```

**Third-party ClamAV-format databases — fetched directly**, from Sanesecurity
and abuse.ch URLhaus, with conditional requests so an idle poll costs one 304.

**YARA rules** — Elastic's `protections-artifacts`.

Sources known to be broken are refused even when a stale `config.toml` still
lists them. `malware.expert.ndb`, for instance, is a body pattern over the text
"buy subscription from malware expert" — any file quoting that phrase would be
reported as malware.

## Why the index is memory-mapped

A `HashMap` of ~3.3 million signatures costs well over a gigabyte resident.
That is why ClamAV itself is known for RAM use, and it is unacceptable for
something running all day on a desktop.

Redoubt compiles the databases into sorted, fixed-stride records in a single
file and `mmap`s it. Lookups are a binary search over borrowed bytes: no heap
allocation, no deserialisation, and the OS page cache keeps only the pages
actually touched resident.

## Maintenance

Measured, not estimated, and nothing is removed without confirmation.

Every path considered for deletion must live under one of a small set of
hardcoded roots, and the containment check runs immediately before each delete
rather than being trusted from wherever the path came from.

**Deliberately not offered:** Prefetch (Windows uses it to speed up launch and
rebuilds it — clearing it makes the machine slower for a while and faster
never), and the WinSxS component store (only `DISM /StartComponentCleanup` may
touch it). Both are staples of bad optimizers because they look like big
numbers.

Startup entries are disabled by *moving* them — a registry value into a
Redoubt-owned backup key, or a shortcut to a `.disabled` name — so re-enabling
restores the exact original.

---

## Usage

```bash
redoubt ui                 # the interface, at http://127.0.0.1:7311
```

```bash
redoubt db update          # freshclam + third-party sources, then recompile
redoubt rules update       # fetch and compile YARA rules
redoubt db status          # what is loaded
redoubt scan C:\Users\me\Downloads
redoubt optimize analyze   # measure reclaimable space
redoubt optimize startup   # what starts with Windows
redoubtd                   # resident protection, headless
```

Useful flags on `scan`: `--show-clean`, `--show-skipped` (what was *not*
scanned and why), `--json`, `-j N`.

Configuration lives at `%ProgramData%\Redoubt\config.toml`, created with full
defaults on first run.

### Observe vs enforce

`mode = "observe"` is the default and means what it says: nothing is
quarantined, nothing is killed. Switch to `enforce` only once you have reviewed
what it finds on your own machine. Heuristic and PUA findings are never
enforceable regardless of mode.

---

## Known gaps

Stated plainly, because a scanner that quietly covers less than it claims is
worse than one that admits what it misses.

- **ClamAV `.ldb` logical signatures are not evaluated** — ~86 MB of signature
  data, and the single largest detection gap. They are multi-pattern boolean
  rules needing a matcher this engine does not have.
- **`.ndb` patterns using wildcards are skipped.** Only literal patterns of 16+
  bytes are indexed; `redoubt db update` reports how many were refused.
- **No pre-execution blocking.** That needs a filesystem minifilter. Script
  blocking needs an AMSI provider. Neither is built.
- **`.cbc` bytecode is out of scope permanently** — it needs ClamAV's VM.
- **CVD digital signatures are not verified.** Integrity rests on HTTPS from the
  official mirror.
- **No archive expansion yet.** `scan.archive_depth` exists but is not wired up.
- **Not registered as a Windows service.** `redoubtd` runs in the foreground.

`redoubt db update` prints a per-format breakdown of everything it could not
index, with an explanation of each. The interface shows the same thing under
Signatures → Not indexed.

---

## Building

Needs Rust (MSVC toolchain), VS Build Tools, and Node (for the UI stylesheet).

```bash
cd ui && npm install && npm run build && cd ..
cargo build --release
cargo test --workspace
```

`.cargo/config.toml` forces the build directory outside OneDrive — a Rust
`target/` directory is tens of thousands of small files, and letting OneDrive
sync it will bring the machine to its knees.

### Visual QA

```bash
node tools/shots.mjs --out shots
```

Drives headless Chrome over every page, both themes and a narrow window, and
fails on any console error or failed request. Looking at the rendered output is
the only way to catch the layout problems a DOM assertion sails past — it has
already caught three.

## Layout

```
crates/
  redoubt-core/      engine: containers, signature parsing, index, scanning,
                     quarantine, verdict cache
  redoubt-optimize/  disk cleanup and startup entries
  redoubt-service/   resident protection; the `redoubtd` binary
  redoubt-ui/        local HTTP server and JSON API
  redoubt-cli/       the `redoubt` binary
ui/                  the interface (Tailwind 4 + daisyUI 5)
tools/shots.mjs      screenshot harness
```

`redoubt-core` has no Windows event plumbing in it — it takes bytes and paths
and returns verdicts. The service crate owns the OS integration and calls in.
