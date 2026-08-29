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
  settings: ["Settings", "Engines, heuristics and enforcement"],
};

function goto(page) {
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

  // Hero
  const enforcing = s.mode === "enforce";
  $("#hero-mode").textContent = s.mode;
  $("#hero-mode").className = `badge badge-soft badge-sm ${enforcing ? "badge-success" : ""}`;
  $("#hero-title").textContent = enforcing ? "Enforcing" : "Engine ready";
  $("#hero-sub").textContent = enforcing
    ? "Malicious files will be quarantined."
    : "Detections are reported only. Nothing is quarantined or removed.";

  // Real-time state in the sidebar. This is honest about not being built yet
  // rather than showing a green light for something that is not running.
  const rt = s.realtime;
  $("#rt-state").textContent = rt.running ? "on" : "off";
  $("#rt-dot").className = `status ${rt.running ? "status-success" : "status-warning"}`;
  $("#rt-note").textContent = rt.note;

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
      s.gaps.find((g) => g.extension === "ldb")
        ? `${bytes(s.gaps.filter((g) => g.extension.startsWith("ld")).reduce((a, g) => a + g.bytes, 0))} not evaluated`
        : "not evaluated",
      false,
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

function renderFindings() {
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

/* ─────────────────────────────  settings  ───────────────────────────── */

const ENGINE_LABELS = {
  hash: ["Whole-file hashes", "Exact matches against known malware. Definitive."],
  section_hash: ["PE section hashes", "Survives the repacking that defeats a file hash."],
  body_pattern: ["Body patterns", "Literal byte signatures matched in one pass."],
  yara: ["YARA rules", "Structural and behavioural rules."],
  heuristics: ["Heuristics", "Shape-based signals. Suspicious only, never enforced."],
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
    FINDINGS = job.findings ?? [];
    renderFindings();
    const n = job.malicious;
    toast(
      n > 0
        ? `${n} malicious file${n === 1 ? "" : "s"} found in ${num(job.done)} scanned`
        : `${num(job.done)} files scanned, nothing malicious`,
      n > 0 ? "error" : "success",
    );
  } else {
    if (job.error) toast(job.error, "error");
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
    const [status, cfg] = await Promise.all([
      api.get("/api/status"),
      api.get("/api/config"),
    ]);
    renderStatus(status);
    renderConfig(cfg);
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
