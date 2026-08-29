/* Screenshot harness for the Redoubt UI.
 *
 * Drives headless Chrome against a running `redoubt ui` server and captures
 * each page. Used as the visual QA pass - looking at the rendered output is
 * the only way to catch layout problems that a DOM assertion sails past.
 *
 *   node tools/shots.mjs [--url http://127.0.0.1:7311] [--out ./shots] [--scan <path>]
 */

import puppeteer from "../ui/node_modules/puppeteer-core/lib/puppeteer/puppeteer-core.js";
import { mkdir } from "node:fs/promises";
import path from "node:path";

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, arr) => {
    if (a.startsWith("--")) acc.push([a.slice(2), arr[i + 1]]);
    return acc;
  }, []),
);

const URL = args.url ?? "http://127.0.0.1:7311";
const OUT = path.resolve(args.out ?? "shots");
const SCAN_PATH = args.scan ?? null;
const WIDTH = Number(args.width ?? 1440);
const HEIGHT = Number(args.height ?? 960);

const CHROME =
  args.chrome ?? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

await mkdir(OUT, { recursive: true });

const browser = await puppeteer.launch({
  executablePath: CHROME,
  headless: "shell",
  defaultViewport: { width: WIDTH, height: HEIGHT, deviceScaleFactor: 2 },
  args: ["--force-color-profile=srgb", "--font-render-hinting=none"],
});

const page = await browser.newPage();
const problems = [];
page.on("console", (m) => {
  if (m.type() === "error") problems.push(`console: ${m.text()}`);
});
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
page.on("requestfailed", (r) =>
  problems.push(`requestfailed: ${r.url()} ${r.failure()?.errorText}`),
);

async function shot(name, note) {
  // Let fonts settle and any transition finish before capturing.
  await new Promise((r) => setTimeout(r, 350));
  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: false });
  console.log(`  ${name.padEnd(22)} ${note ?? ""}`);
  return file;
}

async function goto(hash) {
  await page.evaluate((h) => {
    document.querySelector(`[data-goto="${h}"]`)?.click();
  }, hash);
  await new Promise((r) => setTimeout(r, 250));
}

console.log(`capturing ${URL} at ${WIDTH}x${HEIGHT}@2x -> ${OUT}`);

await page.goto(URL, { waitUntil: "networkidle0", timeout: 30000 });

// Wait for the API to populate the stats, so we never photograph em-dashes.
await page.waitForFunction(
  () => document.querySelector("#stat-signatures")?.textContent?.trim() !== "—",
  { timeout: 20000 },
);

await shot("01-overview", "dashboard, dark");

// --- a real scan, so the scan and findings pages have real content ---
if (SCAN_PATH) {
  await goto("scan");
  await page.type("#scan-path", SCAN_PATH);
  await shot("02-scan-ready", "scan page before starting");

  await page.click("#btn-scan");
  // Wait for the *label* to settle, not the button: the button un-hides on the
  // same poll that flips the state, so keying on it photographs the run one
  // tick before it finishes and the capture shows a part-done progress bar.
  await page.waitForFunction(
    () =>
      /complete|Cancelled/i.test(
        document.querySelector("#scan-state-label")?.textContent ?? "",
      ),
    { timeout: 120000 },
  );
  await new Promise((r) => setTimeout(r, 600));
  await shot("03-scan-results", "scan complete with findings");

  await goto("findings");
  await shot("04-findings", "findings list");

  // Open the detail modal on the worst finding.
  const opened = await page.evaluate(() => {
    const row = document.querySelector("#findings-table [data-finding]");
    if (!row) return false;
    row.click();
    return true;
  });
  if (opened) {
    await new Promise((r) => setTimeout(r, 300));
    await shot("05-detection-detail", "detection detail modal");
    await page.keyboard.press("Escape");
    await new Promise((r) => setTimeout(r, 250));
  } else {
    problems.push("no findings row to open - detail modal not captured");
  }
} else {
  await goto("scan");
  await shot("02-scan-ready", "scan page");
}

await goto("signatures");
await shot("06-signatures", "sources and coverage gaps");

await goto("settings");
await shot("07-settings", "engines, heuristics, enforcement");

// --- light theme ---
await goto("overview");
await page.evaluate(() => {
  const t = document.querySelector(".theme-controller");
  t.checked = true;
  t.dispatchEvent(new Event("change", { bubbles: true }));
});
await new Promise((r) => setTimeout(r, 400));
await shot("08-overview-light", "dashboard, light");

// --- narrow window, drawer collapsed ---
await page.setViewport({ width: 720, height: 900, deviceScaleFactor: 2 });
await page.evaluate(() => {
  const t = document.querySelector(".theme-controller");
  t.checked = false;
  t.dispatchEvent(new Event("change", { bubbles: true }));
  document.documentElement.setAttribute("data-theme", "redoubt");
});
await new Promise((r) => setTimeout(r, 400));
await shot("09-narrow", "narrow window, sidebar collapsed");

await browser.close();

if (problems.length) {
  console.log("\nPROBLEMS:");
  for (const p of problems) console.log(`  - ${p}`);
  process.exitCode = 1;
} else {
  console.log("\nno console errors or failed requests");
}
