/* Redoubt UI.
 *
 * Plain ES modules against a small JSON API on localhost - no framework, so
 * there is no build step for the JavaScript and nothing to go stale between
 * the Rust side and the page.
 */

const api = {
  async get(path) {
    const r = await fetch(path);
    if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
    return r.json();
  },
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const nf = new Intl.NumberFormat();
const num = (n) => (n === null || n === undefined ? "—" : nf.format(n));

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KiB", "MiB", "GiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}

/** Column widths for the findings table.
 *  Without these the browser gives Severity far more room than a badge needs
 *  and squeezes the path column until it is unreadable. */
const FINDING_COLS = `
  <colgroup>
    <col style="width:7.5rem" />
    <col />
    <col style="width:38%" />
    <col style="width:6rem" />
  </colgroup>`;
const FINDING_COLS_COMPACT = `
  <colgroup>
    <col style="width:7.5rem" />
    <col />
    <col style="width:45%" />
  </colgroup>`;

function ago(epochSeconds) {
  if (!epochSeconds) return "never";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - epochSeconds));
  if (s < 90) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} days ago`;
}

/** Escape text destined for innerHTML. Paths and signature names are
 *  attacker-influenced by definition here - a file can be named anything. */
function esc(s) {
  return String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

const SEVERITY = {
  malicious: { badge: "badge-error", label: "Malicious", rank: 3 },
  suspicious: { badge: "badge-warning", label: "Suspicious", rank: 2 },
  clean: { badge: "badge-success", label: "Clean", rank: 1 },
};

function severityBadge(sev) {
  const s = SEVERITY[sev] ?? SEVERITY.clean;
  return `<span class="badge badge-soft badge-sm ${s.badge}">${s.label}</span>`;
}

function toast(message, kind = "info") {
  const host = $("#toast-host");
  const el = document.createElement("div");
  el.className = `alert alert-soft alert-${kind} text-sm shadow-lg`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function busy(on, label = "Working…") {
  const el = $("#busy-indicator");
  $("#busy-label").textContent = label;
  el.classList.toggle("hidden", !on);
  el.classList.toggle("flex", on);
}

/* ─────────────────────────────  navigation  ───────────────────────────── */

const PAGES = {
  overview: ["Overview", "Protection status at a glance"],
  scan: ["Scan", "Check a folder or drive on demand"],
  findings: ["Findings", "Everything detected so far"],
  signatures: ["Signatures", "What is loaded, and what is not"],
  maintenance: ["Maintenance", "Reclaim space and control what starts with Windows"],
  settings: ["Settings", "Engines, heuristics and enforcement"],
};

function goto(page) {
  if (page === "maintenance" && !CLEANUP.length) {
    loadMaintenance();
  }
  $$("section[data-page]").forEach((s) =>
    s.classList.toggle("hidden", s.dataset.page !== page),
  );
  $$("#nav-menu button").forEach((b) =>
    b.classList.toggle("menu-active", b.dataset.goto === page),
  );
  const [title, sub] = PAGES[page] ?? PAGES.overview;
  $("#page-title").textContent = title;
  $("#page-subtitle").textContent = sub;
  // Close the drawer on narrow windows after choosing.
  $("#nav-drawer").checked = false;
  location.hash = page;
}

/* ─────────────────────────────  state  ───────────────────────────── */

let STATUS = null;
let CONFIG = null;
/// Findings from the last on-demand scan.
let SCAN_FINDINGS = [];
/// Findings the resident watcher has reported.
let RT_FINDINGS = [];
/// The union of both, which is what every view renders.
let FINDINGS = [];
let FILTER = "all";
let activeJob = null;
let pollTimer = null;

/* ─────────────────────────────  rendering  ───────────────────────────── */

function renderStatus(s) {
  STATUS = s;
  const e = s.engine;

  $("#app-version").textContent = `v${s.version}`;
  $("#stat-signatures").textContent = num(
    e.file_hashes + e.section_hashes + e.body_patterns,
  );
  $("#stat-signatures-desc").textContent =
    `${num(e.file_hashes)} file · ${num(e.section_hashes)} section · ${num(e.body_patterns)} pattern`;
  $("#stat-rules").textContent = num(e.yara_rules);
  $("#stat-rules-desc").textContent =
    e.yara_rules > 0 ? "behavioural detection" : "none installed yet";
  $("#stat-dbver").textContent = e.db_version ? `v${e.db_version}` : "—";
  $("#stat-dbage").textContent = `built ${ago(e.built_epoch)}`;
  $("#stat-index").textContent = bytes(e.index_bytes);

  $("#sig-file").textContent = num(e.file_hashes);
  $("#sig-section").textContent = num(e.section_hashes);
  $("#sig-body").textContent = num(e.body_patterns);
  $("#sig-allow").textContent = num(e.allowlisted);

  // Hero. It must never read "ready" while a critical alert is on screen -
  // a reassuring headline above an active incident is worse than no headline.
  const enforcing = s.mode === "enforce";
  const critical = (s.realtime?.ransomware?.alerts ?? []).some(
    (a) => a.confidence === "critical" && !dismissedAlerts.has(alertKey(a)),
  );

  $("#hero-mode").textContent = s.mode;
  $("#hero-mode").className = `badge badge-soft badge-sm ${enforcing ? "badge-success" : ""}`;

  const icon = $("#hero-icon");
  if (critical) {
    $("#hero-title").textContent = "Attack in progress";
    $("#hero-sub").textContent =
      "Files are being encrypted. See the alert above before doing anything else.";
    icon.className =
      "grid size-14 shrink-0 place-items-center rounded-box bg-error/15 text-error";
  } else {
    $("#hero-title").textContent = enforcing ? "Enforcing" : "Engine ready";
    $("#hero-sub").textContent = enforcing
      ? "Malicious files will be quarantined."
      : "Detections are reported only. Nothing is quarantined or removed.";
    icon.className =
      "grid size-14 shrink-0 place-items-center rounded-box bg-success/15 text-success";
  }

  renderRealtime(s.realtime);
  renderRansomBanner(s.realtime.ransomware?.alerts ?? []);

  // Presets
  $("#scan-presets").innerHTML = s.presets
    .map(
      (p) =>
        `<button class="btn btn-sm btn-soft" data-preset="${esc(p.path)}">${esc(p.label)}</button>`,
    )
    .join("");

  // Coverage list
  const covered = [
    ["File hashes", `${num(e.file_hashes)} signatures`, true],
    ["PE section hashes", `${num(e.section_hashes)} signatures`, true],
    ["Body patterns", `${num(e.body_patterns)} literals`, true],
    ["YARA rules", `${num(e.yara_rules)} rules`, e.yara_rules > 0],
    [
      "Logical signatures",
      // Say what is covered *and* what is not. Reporting only the rules that
      // compiled would imply the whole format is handled; PCRE, byte-range and
      // count subsignatures are not, and that is most of the remainder.
      e.logical_rules > 0
        ? e.logical_skipped > 0
          ? `${num(e.logical_rules)} rules · ${num(e.logical_skipped)} not evaluated`
          : `${num(e.logical_rules)} rules`
        : "not evaluated",
      e.logical_rules > 0,
    ],
  ];
  $("#coverage-list").innerHTML = covered
    .map(
      ([name, detail, ok]) => `
      <li class="list-row px-0 py-2 items-center">
        <span class="${ok ? "text-success" : "opacity-40"}">
          ${
            ok
              ? '<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 4.5 4.5L19 7"/></svg>'
              : '<svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>'
          }
        </span>
        <div>
          <div class="font-medium">${esc(name)}</div>
          <div class="text-xs opacity-60">${esc(detail)}</div>
        </div>
      </li>`,
    )
    .join("");

  renderSources(s);
  renderGaps(s.gaps);
}

/** The two things that need administrator rights, in Settings.
 *
 * Both are stated as what they do rather than what they are: nobody outside
 * this codebase should have to know what AMSI or a Windows service is to
 * decide whether they want protection on.
 */
function renderSetup(status, svc) {
  const ch = status?.realtime?.scan_channel;
  const registered = !!ch?.provider_registered;

  $("#setup-amsi-badge").textContent = registered ? "on" : "off";
  $("#setup-amsi-badge").className = `badge badge-sm ${registered ? "badge-success" : "badge-ghost"}`;
  $("#setup-amsi-label").textContent = registered ? "Turn off" : "Turn on";
  $("#setup-amsi-btn").className = `btn btn-sm shrink-0 gap-1.5 ${registered ? "" : "btn-primary"}`;
  $("#setup-amsi-note").textContent = registered
    ? ch?.listening
      ? "Checking PowerShell, Office macros and .NET before they run."
      : "Registered, but waiting on protection to start. Turn on Real-time."
    : "Checks PowerShell, Office macros and .NET before they run.";

  // `installed` is deliberately three-valued: null means we could not look,
  // and saying "not installed" then would invite installing a second one.
  const installed = svc?.installed;
  const running = !!svc?.running;
  const badge = $("#setup-svc-badge");

  if (installed === true) {
    badge.textContent = running ? "running" : "installed, stopped";
    badge.className = `badge badge-sm ${running ? "badge-success" : "badge-warning"}`;
    $("#setup-svc-label").textContent = "Remove";
    $("#setup-svc-btn").className = "btn btn-sm gap-1.5";
    $("#setup-svc-note").textContent = running
      ? "Protection runs in the background, before anyone signs in."
      : "Installed but not running.";
    $("#setup-svc-run").classList.remove("hidden");
    $("#setup-svc-run").textContent = running ? "Stop" : "Start";
    $("#setup-svc-run").dataset.task = running ? "service-stop" : "service-start";
  } else if (installed === false) {
    badge.textContent = "not installed";
    badge.className = "badge badge-ghost badge-sm";
    $("#setup-svc-label").textContent = "Install";
    $("#setup-svc-btn").className = "btn btn-sm btn-primary gap-1.5";
    $("#setup-svc-note").textContent =
      "Runs protection in the background, before anyone signs in.";
    $("#setup-svc-run").classList.add("hidden");
  } else {
    badge.textContent = "unknown";
    badge.className = "badge badge-ghost badge-sm";
    $("#setup-svc-label").textContent = "Install";
    $("#setup-svc-btn").className = "btn btn-sm gap-1.5";
    $("#setup-svc-note").textContent =
      svc?.error ?? "Could not read the service state on this machine.";
    $("#setup-svc-run").classList.add("hidden");
  }

  SETUP = { registered, installed, running };

  renderNetwork(status?.realtime?.network);
}

/** Outbound connection blocking.
 *
 * The counters only appear when filters are actually installed. Showing
 * "0 addresses blocked" next to an on switch reads as working-but-quiet, when
 * it in fact means nothing is being blocked at all.
 */
function renderNetwork(net) {
  const enabled = !!net?.enabled;
  const enforcing = !!net?.enforcing;

  $("#toggle-network").checked = enabled;
  const badge = $("#net-badge");
  badge.textContent = enforcing ? "blocking" : enabled ? "not active" : "off";
  badge.className = `badge badge-sm ${
    enforcing ? "badge-success" : enabled ? "badge-warning" : "badge-ghost"
  }`;

  $("#net-note").textContent =
    net?.note ||
    "Outbound connections to known command-and-control addresses are blocked.";

  const counters = $("#net-counters");
  counters.classList.toggle("hidden", !enforcing);
  counters.classList.toggle("grid", enforcing);
  if (enforcing) {
    $("#net-ranges").textContent = num(net.ranges ?? 0);
    $("#net-filters").textContent = num(net.filters ?? 0);
    $("#net-sources").textContent = (net.sources ?? []).join(", ") || "—";
  }
}

/** What the setup buttons should do next. Set by renderSetup. */
let SETUP = { registered: false, installed: false, running: false };

/** Ask for elevation. Windows shows its own dialog; we only report the answer. */
function elevate(task, label) {
  startJob(`/api/elevate/${task}`, null, label);
}

/** Script scanning: the AMSI provider plus the pipe it talks to.
 *
 * Two independent halves, and either one missing means scripts are not being
 * scanned. They are reported separately because "registered but no service"
 * and "service but not registered" both look like nothing happening, and the
 * fix is different for each.
 */
function renderScriptScanning(ch) {
  const registered = !!ch?.provider_registered;
  const listening = !!ch?.listening;
  const active = registered && listening;

  const dot = $("#amsi-dot");
  const state = $("#amsi-state");
  const note = $("#amsi-note");

  if (active) {
    dot.className = "status status-success";
    state.textContent = "on";
    state.className = "badge badge-success badge-xs ml-auto";
    note.textContent =
      "PowerShell, Office macros and .NET are checked before they run.";
  } else if (registered && !listening) {
    dot.className = "status status-warning";
    state.textContent = "no service";
    state.className = "badge badge-warning badge-xs ml-auto";
    note.textContent =
      "The provider is registered but has nothing to ask. Start real-time protection.";
  } else if (!registered && listening) {
    dot.className = "status status-warning";
    state.textContent = "not registered";
    state.className = "badge badge-warning badge-xs ml-auto";
    note.textContent =
      "Windows has not been told about the provider, so it is never called. " +
      "From an elevated prompt: redoubtd amsi-install";
  } else {
    dot.className = "status status-warning";
    state.textContent = "off";
    state.className = "badge badge-ghost badge-xs ml-auto";
    note.textContent =
      "PowerShell, Office macros and .NET are not being checked.";
  }

  // Offer the fix only when registering is actually the missing piece.
  // "No service" is fixed by the real-time toggle, not by another UAC prompt.
  $("#amsi-enable").classList.toggle("hidden", registered);

  const counters = $("#amsi-counters");
  counters.classList.toggle("hidden", !active);
  counters.classList.toggle("grid", active);
  if (active) {
    $("#amsi-requests").textContent = num(ch.requests ?? 0);
    const blocked = ch.malicious ?? 0;
    $("#amsi-blocked").textContent = num(blocked);
    $("#amsi-blocked").className = `tnum text-right${blocked > 0 ? " text-error" : ""}`;
  }
}

/** The ransomware banner.
 *
 *  Shows the most serious outstanding alert across the whole app. Dismissal is
 *  per-alert and remembered only for the session: a fresh alert always
 *  reappears, because suppressing this one permanently would be the single
 *  worst thing this interface could do. */
let dismissedAlerts = new Set();

function alertKey(a) {
  return `${a.at_epoch}:${a.confidence}:${a.signals.length}`;
}

function renderRansomBanner(alerts) {
  const live = alerts.filter((a) => !dismissedAlerts.has(alertKey(a)));
  const banner = $("#ransom-banner");
  if (!live.length) {
    banner.classList.add("hidden");
    return;
  }

  // Worst first; ties broken by recency.
  const rank = { critical: 3, high: 2, low: 1 };
  live.sort(
    (a, b) => (rank[b.confidence] ?? 0) - (rank[a.confidence] ?? 0) || b.at_epoch - a.at_epoch,
  );
  const worst = live[0];

  $("#ransom-title").textContent = worst.summary;
  $("#ransom-signals").innerHTML = worst.signals
    .map((s) => `<li>&bull; ${esc(describeSignal(s))}</li>`)
    .join("");

  const suspects = worst.suspects ?? [];
  const attribution = suspects.length
    ? `Most unusual write activity: ${suspects
        .slice(0, 2)
        .map((s) => `${esc(s.name)} (${bytes(s.bytes_in_window)})`)
        .join(", ")}. `
    : "";
  $("#ransom-limitation").textContent = attribution + worst.limitation;

  banner.classList.remove("hidden");
  banner.dataset.key = alertKey(worst);
}

/** Turn a signal into a sentence. The server sends structured data; the
 *  wording lives here so the page never shows a bare enum name. */
function describeSignal(s) {
  const [kind, v] = Object.entries(s)[0] ?? [];
  const file = (p) => String(p ?? "").split(/[\\/]/).pop();
  switch (kind) {
    case "canary_touched":
      return `A decoy file was modified or deleted: ${file(v.path)}`;
    case "ransom_note":
      return `A file named like a ransom note appeared: ${file(v.path)}`;
    case "known_extension":
      return `A file was renamed to .${v.extension}, used by known ransomware: ${file(v.path)}`;
    case "modification_burst":
      return `${nf.format(v.files)} files changed in ${v.seconds.toFixed(0)} seconds`;
    case "entropy_rise":
      return `A .${v.extension} file now looks random (entropy ${v.entropy.toFixed(2)}): ${file(v.path)}`;
    default:
      return kind ?? "unknown signal";
  }
}

/** Sidebar real-time panel.
 *
 *  The dot is green only when protection is genuinely running, and the note is
 *  whatever the service says about its own limits - the page never invents a
 *  reassuring message of its own. */
function renderRealtime(rt) {
  const running = !!rt.running;
  $("#rt-toggle").checked = running;
  $("#rt-dot").className = `status ${running ? "status-success" : "status-warning"}`;
  $("#rt-note").textContent = rt.note ?? "";

  const counters = $("#rt-counters");
  counters.classList.toggle("hidden", !running);
  counters.classList.toggle("grid", running);
  if (running) {
    const c = rt.counters ?? {};
    $("#rt-watching").textContent = num((rt.watching ?? []).length);
    $("#rt-scanned").textContent = num(c.scanned ?? 0);
    $("#rt-cache").textContent = num(c.cache_hits ?? 0);
    const detections = (c.malicious ?? 0) + (c.suspicious ?? 0);
    $("#rt-detections").textContent = num(detections);
    $("#rt-detections").className = `tnum text-right${detections > 0 ? " text-error" : ""}`;
  }

  renderScriptScanning(rt.scan_channel);

  // Poll while running so the counters move; stop entirely when it is off, so
  // an idle page makes no requests at all.
  clearTimeout(realtimeTimer);
  if (running) {
    realtimeTimer = setTimeout(refreshRealtime, 2000);
  }
}

let realtimeTimer = null;

async function refreshRealtime() {
  try {
    const [s, found] = await Promise.all([
      api.get("/api/status"),
      api.get("/api/realtime/findings"),
    ]);
    const before = RT_FINDINGS.length;
    RT_FINDINGS = found;
    renderRealtime(s.realtime);
    renderRansomBanner(s.realtime.ransomware?.alerts ?? []);
    if (STATUS) {
      STATUS.realtime = s.realtime;
      renderStatus(STATUS);
    }
    if (found.length !== before) {
      renderFindings();
      const fresh = found.length - before;
      if (fresh > 0) {
        const worst = found[0];
        toast(
          `Real-time: ${worst.severity} \u2014 ${worst.path.split(/[\\/]/).pop()}`,
          worst.severity === "malicious" ? "error" : "warning",
        );
      }
    }
  } catch {
    // A failed poll is not worth a toast; the next one will report it.
  }
}

function renderSources(s) {
  const rows = s.sources
    .map(
      (src) => `
      <tr>
        <td class="font-medium">${esc(src.name)}</td>
        <td class="text-xs opacity-70">${esc(src.kind)}</td>
        <td class="tnum text-right">${src.signatures ? num(src.signatures) : "—"}</td>
        <td class="text-right text-xs opacity-70">${esc(src.detail ?? "")}</td>
      </tr>`,
    )
    .join("");
  $("#sources-table").innerHTML = `
    <table class="table table-sm">
      <thead><tr>
        <th>Source</th><th>Via</th><th class="text-right">Signatures</th><th class="text-right">Detail</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderGaps(gaps) {
  if (!gaps.length) {
    $("#gaps-table").innerHTML =
      '<p class="py-4 text-sm opacity-60">Everything in the database was indexed.</p>';
    return;
  }
  const rows = gaps
    .map(
      (g) => `
      <tr>
        <td class="font-mono text-xs">.${esc(g.extension)}</td>
        <td class="tnum text-right">${g.files}</td>
        <td class="tnum text-right">${bytes(g.bytes)}</td>
        <td class="text-xs opacity-70">${esc(g.note)}</td>
      </tr>`,
    )
    .join("");
  $("#gaps-table").innerHTML = `
    <table class="table table-sm">
      <thead><tr>
        <th>Format</th><th class="text-right">Files</th><th class="text-right">Size</th><th>What it is</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function findingsTable(list, { compact = false } = {}) {
  if (!list.length) {
    return '<p class="py-6 text-center text-sm opacity-60">Nothing found.</p>';
  }
  const rows = list
    .map((v, i) => {
      const name = v.detections.length
        ? v.detections
            .slice()
            .sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0))[0]
            .name
        : "—";
      const file = v.path.split(/[\\/]/).pop();
      return `
      <tr class="hover:bg-base-200 cursor-pointer" data-finding="${i}">
        <td>${severityBadge(v.severity)}</td>
        <td class="max-w-0">
          <div class="truncate font-medium">${esc(file)}</div>
          ${compact ? "" : `<div class="truncate text-xs opacity-55">${esc(v.path)}</div>`}
        </td>
        <td class="max-w-0"><div class="truncate font-mono text-xs">${esc(name)}</div></td>
        ${compact ? "" : `<td class="tnum text-right text-xs opacity-60">${(v.scan_micros / 1000).toFixed(1)} ms</td>`}
      </tr>`;
    })
    .join("");
  return `
    <table class="table table-sm table-pin-rows">
      ${compact ? FINDING_COLS_COMPACT : FINDING_COLS}
      <thead><tr>
        <th>Severity</th><th>File</th><th>Detection</th>${compact ? "" : "<th class='text-right'>Time</th>"}
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

/** Merge the two sources of findings.
 *
 *  Real-time detections and on-demand scan results are separate streams, and
 *  showing only one of them is how the sidebar ends up reporting a detection
 *  while the findings list claims nothing was found. Deduplicated on path plus
 *  content hash, so rescanning the same file does not double up. */
function mergeFindings() {
  const seen = new Map();
  for (const v of [...RT_FINDINGS, ...SCAN_FINDINGS]) {
    seen.set(`${v.path}\u0000${v.identity?.sha256 ?? ""}`, v);
  }
  FINDINGS = [...seen.values()].sort(
    (a, b) =>
      (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0),
  );
}

function renderFindings() {
  mergeFindings();
  const list =
    FILTER === "all" ? FINDINGS : FINDINGS.filter((f) => f.severity === FILTER);
  $("#findings-table").innerHTML = findingsTable(list);
  $("#findings-count").textContent =
    `${list.length} of ${FINDINGS.length} finding${FINDINGS.length === 1 ? "" : "s"}`;

  const mal = FINDINGS.filter((f) => f.severity === "malicious").length;
  const badge = $("#nav-findings-badge");
  badge.textContent = mal;
  badge.classList.toggle("hidden", mal === 0);

  $("#overview-findings").innerHTML = findingsTable(FINDINGS.slice(0, 5), {
    compact: true,
  });
}

function showDetail(v) {
  $("#detail-title").textContent = v.path.split(/[\\/]/).pop();
  const rows = v.detections
    .map(
      (d) => `
      <div class="rounded-box border border-base-300 p-3">
        <div class="flex flex-wrap items-center gap-2">
          ${severityBadge(d.severity)}
          <span class="badge badge-ghost badge-sm font-mono">${esc(d.engine)}</span>
          <span class="font-mono text-sm">${esc(d.name)}</span>
        </div>
        ${d.detail ? `<p class="mt-2 text-xs opacity-70">${esc(d.detail)}</p>` : ""}
      </div>`,
    )
    .join("");

  $("#detail-body").innerHTML = `
    <div class="rounded-box bg-base-200 p-3">
      <p class="break-all font-mono text-xs">${esc(v.path)}</p>
    </div>
    ${
      v.allowlisted_as
        ? `<div role="alert" class="alert alert-soft alert-success text-sm">
             Allowlisted as <span class="font-mono">${esc(v.allowlisted_as)}</span>
           </div>`
        : ""
    }
    <div class="space-y-2">${rows || '<p class="opacity-60">No detections.</p>'}</div>
    <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
      <dt class="opacity-60">Size</dt><dd class="tnum">${num(v.identity.size)} bytes</dd>
      <dt class="opacity-60">Scan time</dt><dd class="tnum">${(v.scan_micros / 1000).toFixed(2)} ms</dd>
      <dt class="opacity-60">SHA-256</dt><dd class="break-all font-mono">${esc(v.identity.sha256 ?? "—")}</dd>
      <dt class="opacity-60">MD5</dt><dd class="break-all font-mono">${esc(v.identity.md5 ?? "—")}</dd>
    </dl>`;
  $("#detail-modal").showModal();
}

/* ─────────────────────────────  maintenance  ───────────────────────────── */

let CLEANUP = [];
let STARTUP = [];
const CLEAN_SELECTED = new Set();

function renderCleanup() {
  if (!CLEANUP.length) {
    $("#cleanup-list").innerHTML =
      '<p class="py-6 text-center text-sm opacity-60">Nothing reclaimable found.</p>';
    return;
  }

  const rows = CLEANUP.map((c) => {
    const blocked = c.needs_admin && c.bytes === 0 && c.unreadable > 0;
    return `
      <tr class="${blocked ? "opacity-50" : ""}">
        <td class="w-10">
          <input type="checkbox" class="checkbox checkbox-sm" data-clean="${esc(c.id)}"
                 ${CLEAN_SELECTED.has(c.id) ? "checked" : ""} ${blocked ? "disabled" : ""} />
        </td>
        <td>
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">${esc(c.name)}</span>
            ${c.safety === "caution" ? '<span class="badge badge-soft badge-warning badge-xs">has a cost</span>' : ""}
            ${c.needs_admin ? '<span class="badge badge-ghost badge-xs">needs admin</span>' : ""}
          </div>
          <p class="mt-0.5 text-xs opacity-60">${esc(c.description)}</p>
          ${
            c.unreadable > 0
              ? `<p class="mt-0.5 text-xs opacity-45">${num(c.unreadable)} item(s) could not be read${c.needs_admin ? " without elevation" : ""}</p>`
              : ""
          }
        </td>
        <td class="tnum text-right whitespace-nowrap">${bytes(c.bytes)}</td>
        <td class="tnum text-right whitespace-nowrap opacity-60">${num(c.files)}</td>
      </tr>`;
  }).join("");

  $("#cleanup-list").innerHTML = `
    <table class="table table-sm">
      <thead><tr>
        <th></th><th>Category</th><th class="text-right">Size</th><th class="text-right">Files</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  updateCleanTotal();
}

function updateCleanTotal() {
  const total = CLEANUP.filter((c) => CLEAN_SELECTED.has(c.id)).reduce(
    (a, c) => a + c.bytes,
    0,
  );
  $("#clean-selected-size").textContent = total ? bytes(total) : "—";
  $("#btn-clean").disabled = total === 0;
}

function renderStartup() {
  if (!STARTUP.length) {
    $("#startup-list").innerHTML =
      '<p class="py-6 text-center text-sm opacity-60">Nothing starts with Windows.</p>';
    $("#startup-count").textContent = "";
    return;
  }

  const enabled = STARTUP.filter((e) => e.enabled).length;
  $("#startup-count").textContent = `${enabled} of ${STARTUP.length} enabled`;

  const rows = STARTUP.map(
    (e) => `
      <tr>
        <td>
          <div class="font-medium">${esc(e.name)}</div>
          <div class="truncate font-mono text-xs opacity-55" title="${esc(e.command)}">${esc(e.image ?? e.command)}</div>
        </td>
        <td class="whitespace-nowrap text-xs opacity-70">${esc(e.source_label)}</td>
        <td class="w-16 text-right">
          <input type="checkbox" class="toggle toggle-sm" data-startup="${esc(e.id)}"
                 ${e.enabled ? "checked" : ""} aria-label="Toggle ${esc(e.name)}" />
        </td>
      </tr>`,
  ).join("");

  $("#startup-list").innerHTML = `
    <table class="table table-sm">
      <colgroup><col /><col style="width:14rem" /><col style="width:5rem" /></colgroup>
      <thead><tr><th>Program</th><th>Source</th><th class="text-right">On</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function loadMaintenance() {
  try {
    const [clean, startup] = await Promise.all([
      api.get("/api/optimize/analyze"),
      api.get("/api/startup"),
    ]);
    CLEANUP = clean;
    STARTUP = startup;
    // Preselect only what the engine marks safe and default.
    if (CLEAN_SELECTED.size === 0) {
      for (const c of CLEANUP) {
        if (c.default_selected && c.bytes > 0) CLEAN_SELECTED.add(c.id);
      }
    }
    renderCleanup();
    renderStartup();
  } catch (e) {
    toast(`Could not read maintenance data: ${e.message}`, "error");
  }
}

/* ─────────────────────────────  settings  ───────────────────────────── */

const ENGINE_LABELS = {
  hash: ["Whole-file hashes", "Exact matches against known malware. Definitive."],
  section_hash: ["PE section hashes", "Survives the repacking that defeats a file hash."],
  body_pattern: ["Body patterns", "Literal byte signatures matched in one pass."],
  yara: ["YARA rules", "Structural and behavioural rules."],
  heuristics: ["Heuristics", "Shape-based signals. Suspicious only, never enforced."],
};

const RANSOMWARE_LABELS = {
  enabled: ["Behavioural detection", "Watch for the pattern of files being encrypted."],
  canaries: ["Decoy files", "Place bait files in watched folders. Nothing legitimate touches them, which makes this the strongest signal available."],
  attribute_process: ["Identify the process", "Sample process write activity to work out what is responsible."],
  terminate_on_critical: ["Stop the process automatically", "Only acts when one process is unambiguously responsible, and only with enforcement on. Off by default."],
};

const HEURISTIC_LABELS = {
  high_entropy: ["High-entropy code", "Executable sections that look packed or encrypted."],
  writable_executable_section: ["Writable + executable section", "Normal for a packer stub, not for a compiler."],
  no_imports: ["Minimal imports", "Resolves APIs at runtime instead of importing them."],
  double_extension: ["Double extension", "invoice.pdf.exe and friends."],
  rtl_override: ["Bidi filename override", "Makes a displayed name differ from the real one."],
};

function toggleRow(key, label, desc, checked, onChange) {
  const row = document.createElement("div");
  row.className = "flex items-start justify-between gap-6 py-3";
  row.innerHTML = `
    <div>
      <p class="font-medium">${esc(label)}</p>
      <p class="mt-0.5 text-sm opacity-70">${esc(desc)}</p>
    </div>`;
  const input = document.createElement("input");
  input.type = "checkbox";
  input.className = "toggle toggle-sm mt-1 shrink-0";
  input.checked = checked;
  input.addEventListener("change", () => onChange(input.checked));
  row.appendChild(input);
  return row;
}

function renderConfig(cfg) {
  CONFIG = cfg;
  $("#toggle-enforce").checked = cfg.mode === "enforce";

  const engines = $("#engines-list");
  engines.innerHTML = "";
  for (const [key, [label, desc]] of Object.entries(ENGINE_LABELS)) {
    engines.appendChild(
      toggleRow(key, label, desc, cfg.engines[key], async (on) => {
        cfg.engines[key] = on;
        await saveConfig({ engines: cfg.engines });
      }),
    );
  }

  const heur = $("#heuristics-list");
  heur.innerHTML = "";
  for (const [key, [label, desc]] of Object.entries(HEURISTIC_LABELS)) {
    heur.appendChild(
      toggleRow(key, label, desc, cfg.heuristics[key], async (on) => {
        cfg.heuristics[key] = on;
        await saveConfig({ heuristics: cfg.heuristics });
      }),
    );
  }

  const ransom = $("#ransomware-list");
  ransom.innerHTML = "";
  for (const [key, [label, desc]] of Object.entries(RANSOMWARE_LABELS)) {
    ransom.appendChild(
      toggleRow(key, label, desc, cfg.ransomware[key], async (on) => {
        cfg.ransomware[key] = on;
        await saveConfig({ ransomware: cfg.ransomware });
      }),
    );
  }

  $("#paths-list").innerHTML = Object.entries(cfg.paths)
    .map(
      ([k, v]) => `
      <div class="flex flex-wrap items-baseline gap-2">
        <span class="w-24 shrink-0 font-sans text-xs opacity-60">${esc(k)}</span>
        <span class="break-all">${esc(v)}</span>
      </div>`,
    )
    .join("");
}

async function saveConfig(patch) {
  try {
    await api.post("/api/config", patch);
    toast("Settings saved", "success");
  } catch (e) {
    toast(`Could not save: ${e.message}`, "error");
  }
}

/* ─────────────────────────────  jobs  ───────────────────────────── */

function renderScanJob(job) {
  $("#scan-progress-card").classList.remove("hidden");

  const pct = job.total ? Math.round((job.done / job.total) * 100) : 0;
  const bar = $("#scan-progress");
  bar.value = pct;
  bar.className = `progress ${job.malicious > 0 ? "progress-error" : ""}`;

  $("#scan-state-label").textContent =
    job.state === "running"
      ? `Scanning — ${pct}%`
      : job.state === "cancelled"
        ? "Cancelled"
        : "Scan complete";
  $("#scan-rate").textContent = job.rate ? `${num(Math.round(job.rate))} files/s` : "";
  $("#scan-current").textContent = job.current || " ";
  $("#scan-count").textContent = num(job.done);
  $("#scan-malicious").textContent = num(job.malicious);
  $("#scan-suspicious").textContent = num(job.suspicious);
  $("#scan-skipped").textContent = num(job.skipped);

  const running = job.state === "running";
  $("#btn-scan").classList.toggle("hidden", running);
  $("#btn-scan-cancel").classList.toggle("hidden", !running);

  if (job.findings?.length) {
    $("#scan-results-card").classList.remove("hidden");
    $("#scan-results").innerHTML = findingsTable(job.findings);
  }
}

async function pollJob(id) {
  clearTimeout(pollTimer);
  let job;
  try {
    job = await api.get(`/api/job/${id}`);
  } catch (e) {
    busy(false);
    toast(e.message, "error");
    return;
  }

  if (job.kind === "scan") renderScanJob(job);
  else busy(job.state === "running", job.label ?? "Working…");

  if (job.state === "running") {
    pollTimer = setTimeout(() => pollJob(id), 400);
    return;
  }

  // Finished.
  activeJob = null;
  busy(false);

  if (job.kind === "scan") {
    SCAN_FINDINGS = job.findings ?? [];
    renderFindings();
    const n = job.malicious;
    toast(
      n > 0
        ? `${n} malicious file${n === 1 ? "" : "s"} found in ${num(job.done)} scanned`
        : `${num(job.done)} files scanned, nothing malicious`,
      n > 0 ? "error" : "success",
    );
  } else {
    // Declining a consent dialog changes nothing, so it must not be
    // coloured like a failure - that sends people hunting for a problem.
    if (job.state === "cancelled") toast(job.summary ?? "Cancelled", "warning");
    else if (job.error) toast(job.error, "error");
    else toast(job.summary ?? "Done", "success");
    await refresh();
  }
}

async function startJob(url, body, label) {
  if (activeJob) {
    toast("Something is already running", "warning");
    return;
  }
  try {
    const { id } = await api.post(url, body);
    activeJob = id;
    busy(true, label);
    pollJob(id);
  } catch (e) {
    toast(e.message, "error");
  }
}

/* ─────────────────────────────  boot  ───────────────────────────── */

async function refresh() {
  try {
    const [status, cfg, rtFindings, svc] = await Promise.all([
      api.get("/api/status"),
      api.get("/api/config"),
      api.get("/api/realtime/findings").catch(() => []),
      // Reading the service state can fail on a locked-down machine. That is
      // worth showing as "unknown", not worth failing the whole page over.
      api.get("/api/service").catch((e) => ({ installed: null, error: e.message })),
    ]);
    RT_FINDINGS = rtFindings;
    renderStatus(status);
    renderConfig(cfg);
    renderFindings();
    renderSetup(status, svc);
  } catch (e) {
    toast(`Cannot reach the Redoubt service: ${e.message}`, "error");
  }
}

function wire() {
  document.addEventListener("click", (ev) => {
    const nav = ev.target.closest("[data-goto]");
    if (nav) {
      goto(nav.dataset.goto);
      return;
    }
    const preset = ev.target.closest("[data-preset]");
    if (preset) {
      $("#scan-path").value = preset.dataset.preset;
      return;
    }
    const filter = ev.target.closest("[data-filter]");
    if (filter) {
      FILTER = filter.dataset.filter;
      $$("#findings-filter button").forEach((b) =>
        b.classList.toggle("btn-active", b === filter),
      );
      renderFindings();
      return;
    }
    const row = ev.target.closest("[data-finding]");
    if (row) {
      const list =
        FILTER === "all" ? FINDINGS : FINDINGS.filter((f) => f.severity === FILTER);
      const v = row.closest("#overview-findings")
        ? FINDINGS[+row.dataset.finding]
        : list[+row.dataset.finding];
      if (v) showDetail(v);
    }
  });

  $("#btn-scan").addEventListener("click", () => {
    const path = $("#scan-path").value.trim();
    if (!path) {
      toast("Choose a folder to scan", "warning");
      return;
    }
    $("#scan-results-card").classList.add("hidden");
    startJob("/api/scan", { path }, "Scanning…");
  });

  $("#btn-scan-cancel").addEventListener("click", async () => {
    if (activeJob) await api.post(`/api/job/${activeJob}/cancel`);
  });

  $("#btn-update-db").addEventListener("click", () =>
    startJob("/api/db/update", {}, "Updating signatures…"),
  );
  $("#btn-update-rules").addEventListener("click", () =>
    startJob("/api/rules/update", {}, "Updating rules…"),
  );
  $("#btn-update-all").addEventListener("click", () =>
    startJob("/api/db/update", {}, "Updating signatures…"),
  );

  // Cleanup selection
  document.addEventListener("change", (ev) => {
    const box = ev.target.closest("[data-clean]");
    if (!box) return;
    if (box.checked) CLEAN_SELECTED.add(box.dataset.clean);
    else CLEAN_SELECTED.delete(box.dataset.clean);
    updateCleanTotal();
  });

  $("#btn-clean").addEventListener("click", async () => {
    const ids = [...CLEAN_SELECTED];
    if (!ids.length) return;

    // Preview first, then confirm with the real number. The measurement can
    // have moved since the page loaded.
    let preview;
    try {
      preview = await api.post("/api/optimize/clean", { ids, dry_run: true });
    } catch (e) {
      toast(e.message, "error");
      return;
    }
    if (preview.files_removed === 0) {
      toast("Nothing left to remove", "info");
      await loadMaintenance();
      return;
    }
    if (
      !confirm(
        `Remove ${nf.format(preview.files_removed)} file(s), freeing ${bytes(preview.bytes_freed)}?\n\n` +
          ids.join(", "),
      )
    ) {
      return;
    }

    busy(true, "Cleaning up…");
    try {
      const r = await api.post("/api/optimize/clean", { ids, dry_run: false });
      toast(
        `Freed ${bytes(r.bytes_freed)} across ${nf.format(r.files_removed)} file(s)` +
          (r.files_skipped ? `; ${nf.format(r.files_skipped)} in use` : ""),
        "success",
      );
      CLEAN_SELECTED.clear();
      await loadMaintenance();
    } catch (e) {
      toast(e.message, "error");
    } finally {
      busy(false);
    }
  });

  // Startup toggles
  document.addEventListener("change", async (ev) => {
    const toggle = ev.target.closest("[data-startup]");
    if (!toggle) return;
    const id = toggle.dataset.startup;
    const enable = toggle.checked;
    try {
      STARTUP = await api.post("/api/startup/toggle", { id, enable });
      renderStartup();
      toast(enable ? "Enabled at startup" : "Disabled at startup", "success");
    } catch (e) {
      toggle.checked = !enable;
      toast(e.message, "error");
    }
  });

  $("#toggle-network").addEventListener("change", async (e) => {
    const on = e.currentTarget.checked;
    try {
      await saveConfig({ network: { enabled: on } });
      toast(
        on
          ? "Network blocking on. It takes effect when protection restarts."
          : "Network blocking off.",
        "success",
      );
      await refresh();
    } catch (err) {
      // Never leave the switch showing a state the service is not in.
      e.currentTarget.checked = !on;
      toast(err.message, "error");
    }
  });

  $("#amsi-enable").addEventListener("click", () =>
    elevate("amsi-install", "Enabling script scanning"),
  );

  $("#setup-amsi-btn").addEventListener("click", () =>
    SETUP.registered
      ? elevate("amsi-uninstall", "Disabling script scanning")
      : elevate("amsi-install", "Enabling script scanning"),
  );

  $("#setup-svc-btn").addEventListener("click", () =>
    SETUP.installed === true
      ? elevate("service-uninstall", "Removing the background service")
      : elevate("service-install", "Installing the background service"),
  );

  $("#setup-svc-run").addEventListener("click", (e) => {
    const task = e.currentTarget.dataset.task;
    if (task) elevate(task, task === "service-stop" ? "Stopping" : "Starting");
  });

  $("#ransom-dismiss").addEventListener("click", () => {
    const key = $("#ransom-banner").dataset.key;
    if (key) dismissedAlerts.add(key);
    $("#ransom-banner").classList.add("hidden");
  });

  $("#rt-toggle").addEventListener("change", async (ev) => {
    const on = ev.target.checked;
    try {
      const rt = await api.post(`/api/realtime/${on ? "start" : "stop"}`);
      renderRealtime(rt);
      toast(
        on ? `Real-time protection on, watching ${rt.watching.length} location(s)` : "Real-time protection off",
        on ? "success" : "info",
      );
    } catch (e) {
      // Put the switch back: it must never show a state the service is not in.
      ev.target.checked = !on;
      toast(e.message, "error");
    }
  });

  $("#toggle-enforce").addEventListener("change", async (ev) => {
    const mode = ev.target.checked ? "enforce" : "observe";
    await saveConfig({ mode });
    await refresh();
  });

  // Remember the theme across restarts; the theme-controller only sets the
  // attribute for the current page.
  const themeInput = $(".theme-controller");
  const saved = localStorage.getItem("redoubt-theme");
  if (saved === "redoubt-light") {
    themeInput.checked = true;
    document.documentElement.setAttribute("data-theme", "redoubt-light");
  }
  themeInput.addEventListener("change", () => {
    localStorage.setItem(
      "redoubt-theme",
      themeInput.checked ? "redoubt-light" : "redoubt",
    );
  });
}

wire();
goto(location.hash.slice(1) || "overview");
refresh();
