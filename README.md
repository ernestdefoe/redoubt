# Redoubt

A Windows antivirus and system maintenance tool, built from scratch in Rust.

Redoubt compiles ClamAV-format signature databases and YARA rule sets into a
single memory-mapped index, scans against them with five independent engines,
and watches the places files actually arrive.

It runs **observe-first**: it detects, logs and reports, and does not quarantine
anything until you explicitly turn enforcement on.

Free and MIT-licensed.
**[Download the installer](https://github.com/ernestdefoe/redoubt/releases/latest)**
or build it yourself.

## What this is, and what it is not

Worth knowing before you install it, so nothing here is a surprise:

- **It runs alongside Microsoft Defender, not instead of it.** Redoubt is not
  registered with the Windows Security Center — that needs membership of the
  Microsoft Virus Initiative and certification by an independent lab. Defender
  keeps running and keeps protecting you. Redoubt adds to it.
- **It is not code-signed.** SmartScreen will warn you when you run the
  installer. That is a certificate I have not bought, not a comment on the code.
- **It cannot stop a malicious executable at the moment you launch it.** That
  needs a filesystem minifilter, which is a kernel driver, which Microsoft has
  to sign. Redoubt catches such a file when it is *written* — which for
  something downloaded or dropped is usually first — but not at launch.
- **It can stop a malicious script before it runs.** That path does not need a
  driver, and it is built and working.
- **It tells you what it does not cover.** The interface reports how much of
  each signature format is actually evaluated, rather than implying all of it.
  Where this document says something is not built, it is not built.

---

## Status

| Component | State |
|---|---|
| Signature engine (hashes, sections, body patterns) | **Working** |
| Logical signatures (ClamAV `.ldb`) | **Working** — 48,931 rules |
| YARA engine | **Working** — 3,021 rules |
| Archive scanning (zip, gzip, nested) | **Working** |
| Heuristics | **Working** — tuned against a real System32 sweep |
| Signature + rule updating | **Working** |
| On-demand scanning | **Working** |
| Real-time protection | **Working** — file watching, detect-and-react |
| Ransomware detection | **Working** — behavioural, five signals |
| Process attribution + termination | **Working** — opt-in, two switches |
| Quarantine + restore | **Working** — on demand, from any finding |
| Desktop interface | **Working** |
| Disk cleanup + startup manager | **Working** |
| Windows service registration | **Working** — installer, or `redoubtd install` |
| Named-pipe scan channel | **Working** — one engine, many hosts |
| AMSI provider (script blocking) | **Working** — verified end to end on a real machine |
| UTF-16 script content | **Working** — PowerShell's own encoding |
| Windows installer (MSI) | **Working** — `installer/build.ps1` |
| Filesystem minifilter (pre-execution blocking) | Not built |
| Network C2 blocking | **Working** — WFP, no driver needed |

372 tests.

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

## Ransomware

Signatures cannot catch ransomware: by the time a sample is known the family
has rebuilt, and the damaging step is not a file arriving but thousands of
*existing* files being rewritten. Five behavioural signals run off the same
event stream:

1. **Decoy files** planted in the watched folders. Nothing legitimate touches
   them, so this is the strongest signal available and alerts on its own.
   They are deliberately **not hidden** — a great deal of ransomware skips
   hidden files, which would have silently disabled the whole mechanism.
2. **Ransom-note filenames** appearing next to your documents.
3. **Known extensions** — `.locky`, `.wncry` and friends.
4. **Modification bursts** — many files rewritten quickly.
5. **Entropy rise** — a `.txt` whose contents are now indistinguishable from
   random.

Bursts and entropy never alert alone: builds and sync clients produce both all
day, and an alert that fires during an `npm install` is an alert nobody reads.

### Attribution

The file watcher reports paths, not who touched them. Redoubt closes that by
sampling per-process write volume continuously and reporting whatever is
writing far above *its own* normal rate.

That is **context, not proof**, and it is described that way because testing
proved it needs to be. Ranking by absolute write rate confidently named the
browser and editor — simply the busiest processes present.

Automatic termination therefore ignores that list. It uses a *decisive*
candidate: one process clearly ahead of the runner-up on both anomaly and
volume. If two are plausible, nothing is terminated and the alert says so.
It also requires enforce mode **and** an explicitly enabled setting that is off
by default — two switches, because being wrong here is destructive.

## Script scanning (AMSI)

Windows' Antimalware Scan Interface hands a security product the *deobfuscated*
text of a script immediately before it runs — PowerShell (including
`Invoke-Expression` and every layer of an encoded command), VBScript, JScript,
Office VBA macros, WMI, and .NET assemblies loaded from memory. It is the one
pre-execution hook available without a kernel driver, and it is the only place
Redoubt can stop something *before* it happens rather than after.

`crates/redoubt-amsi` is a COM in-process server that Windows loads into every
script host. Three properties follow from living inside somebody else's process:

- **It holds no engine.** The index is hundreds of megabytes; a copy in every
  PowerShell window would be ruinous. Content goes down a named pipe
  (`\\.\pipe\Redoubt.Scan`) to the service, which owns the one engine on the
  machine.
- **It never panics.** Unwinding into a foreign C++ frame is undefined
  behaviour, so every COM entry point is wrapped in `catch_unwind`.
- **It fails open.** No service, a timeout, a reply it does not understand — all
  yield `AMSI_RESULT_NOT_DETECTED` and the content runs. A provider that blocks
  every script when its own service is down does not fail safe; it breaks the
  machine and gets itself uninstalled. The whole exchange is bounded at 2s.

`suspicious` deliberately does not block. Heuristics are wrong often enough that
blocking on them would stop legitimate scripts, so only a signature match does.

Registering it needs administrator rights, because it writes two `HKLM` keys —
the COM class, and the class id listed under `SOFTWARE\Microsoft\AMSI\Providers`.
Writing only the first produces a provider that exists and is never called,
which is indistinguishable from one that does not work, so the interface reports
the two halves separately.

```
redoubtd amsi-install      # from an elevated prompt
redoubtd amsi-status
redoubtd amsi-uninstall
```

AMSI hosts load providers at start-up, so PowerShell windows and Office
applications already open keep running without it until they are restarted.

---

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

**Redoubt ships no signatures.** The installer is binaries only; every database
is fetched onto your machine from its publisher, under that publisher's terms:

| Source | What | Terms |
|---|---|---|
| ClamAV main/daily/bytecode | Hashes, patterns, logical signatures | GPL-2.0, via Cisco Talos |
| Sanesecurity | Additional ClamAV-format databases | [sanesecurity.com](https://sanesecurity.com/usage/) |
| abuse.ch URLhaus | Malicious URL patterns | [abuse.ch](https://urlhaus.abuse.ch/) |
| abuse.ch ThreatFox | Botnet C2 addresses | [threatfox.abuse.ch/faq/#tos](https://threatfox.abuse.ch/faq/#tos) |
| Elastic protections-artifacts | YARA rules | Elastic License 2.0 |

Redoubt's own code is MIT. The data is not Redoubt's to relicense, and anyone
redistributing this — especially commercially — should read those terms rather
than assume this table settled it.


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
redoubtd install           # register as a Windows service (needs admin)
redoubtd status            # is the service installed and running?
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

- **Most logical signatures are still unusable.** 48,931 of ClamAV's 322,283
  `.ldb` rules are evaluated — 15%. The rest need PCRE subsignatures, byte
  ranges or match-count operators, or fall under the default length floor.
  Raise coverage with `scan.min_logical_pattern_bytes = 4` at a cost of
  ~200 MB resident. The interface states both numbers rather than only the
  one that flatters it.
- **`.ndb` patterns using wildcards are skipped.** Only literal patterns of 16+
  bytes are indexed; `redoubt db update` reports how many were refused.
- **No pre-execution blocking for files.** That needs a filesystem minifilter,
  which needs the WDK; a malicious *executable* is caught when it is written,
  not when it is launched. Scripts are a different matter — see the AMSI section above.
- **No network blocking.** C2 callbacks and exfiltration are not intercepted.
- **Ransomware attribution cannot see which process wrote which file.** It is
  inferred from I/O behaviour and can name nobody.
- **Resident memory is ~400 MB**, dominated by the pattern-matching automaton.
  `scan.min_logical_pattern_bytes` is the dial; the measured trade-off is in
  its doc comment.
- **`.cbc` bytecode is out of scope permanently** — it needs ClamAV's VM.
- **CVD digital signatures are not verified.** Integrity rests on HTTPS from the
  official mirror.
`redoubt db update` prints a per-format breakdown of everything it could not
index, with an explanation of each. The interface shows the same thing under
Signatures → Not indexed.

---

## Installing

`installer/out/Redoubt-<version>-x64.msi` is a normal Windows installer:
double-click it, or `msiexec /i Redoubt-0.1.0-x64.msi`. It needs
administrator rights, which Windows asks for itself.

It installs three binaries into `C:\Program Files\Redoubt`, registers the
background service, registers the AMSI script provider, and puts Redoubt in
the Start menu. Nothing else on the machine is touched.

Two things it deliberately does **not** do:

- **It does not turn on enforcement.** Redoubt installs in observe mode and
  reports what it finds. Quarantine stays off until you turn it on, because
  installing a security product should not silently start deleting files.
- **It does not remove your data when uninstalled.** The signature database,
  the logs and - above all - anything in quarantine stay under
  `%ProgramData%\Redoubt`. Deleting somebody's quarantined files on the way
  out is unforgivable.

Building the installer needs [WiX](https://wixtoolset.org) v5 and Python:

```
dotnet tool install --global wix --version 5.0.2
wix extension add -g WixToolset.UI.wixext/5.0.2
wix extension add -g WixToolset.Util.wixext/5.0.2
pwsh installer/build.ps1
```

`installer/inspect.ps1 <msi>` prints what a package will actually do -
files, service, registry, shortcuts - read from the package's own tables
rather than from the source that produced it. A registry key that quietly
failed to make it into the build looks, from the `.wxs`, exactly like one
that did.

The mark is generated, not drawn by hand: `python tools/brand.py` produces
the icon at every size Windows asks for, plus the installer artwork, from
the same colours the interface uses. The three binaries carry it along with
their version and publisher, because an unsigned tool with a blank icon and
no publisher in its properties is one nobody should grant administrator
rights to.

**The installer is not code-signed.** SmartScreen will warn about it until
it is signed with a certificate.

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
  redoubt-amsi/      the AMSI provider DLL loaded into script hosts
  redoubt-ui/        local HTTP server and JSON API
  redoubt-cli/       the `redoubt` binary
ui/                  the interface (Tailwind 4 + daisyUI 5)
tools/shots.mjs      screenshot harness
```

`redoubt-core` has no Windows event plumbing in it — it takes bytes and paths
and returns verdicts. The service crate owns the OS integration and calls in.
