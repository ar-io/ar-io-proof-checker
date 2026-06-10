// Real-browser big-file E2E: streams a 2.5 GB file (over the old 2 GB refusal
// cap) through the production build in headless Chromium — asserts the live
// progress line renders MID-hash (regression test for the macrotask-starvation
// freeze), the advisory shows, and the browser hash equals sha256sum.
// Same setup as browser-e2e.mjs (see its header); run with CHROME_BIN set.
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";

const EXE = process.env.CHROME_BIN;
const BIG = "/tmp/ario-big-2.5g.bin";
execFileSync("truncate", ["-s", "2560M", BIG]);

const browser = await chromium.launch({ executablePath: EXE });
const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
const failures = [];
const check = (n, c, d = "") => {
  console.log(`${c ? "PASS" : "FAIL"}  ${n}${d ? ` — ${d}` : ""}`);
  if (!c) failures.push(n);
};
page.on("pageerror", (e) => check("no page JS errors", false, String(e)));

await page.goto("http://localhost:4173/", { waitUntil: "load" });
const t0 = Date.now();
await page.setInputFiles("#file-input", BIG);

// Catch the progress line mid-hash (large-file advisory + percentage).
let sawProgress = false;
let progressText = "";
for (let i = 0; i < 200 && !sawProgress; i++) {
  const txt = (await page.textContent("#results").catch(() => "")) ?? "";
  if (/Hashed .* of .* \(\d+%\)/.test(txt)) {
    sawProgress = true;
    progressText = /Hashed [^\n]*/.exec(txt)?.[0] ?? "";
  }
  await new Promise((r) => setTimeout(r, 100));
}
check("live progress line rendered mid-hash", sawProgress, progressText);
const warn = (await page.textContent("#results").catch(() => "")) ?? "";
check("large-file advisory shown (no refusal)", /hashing locally|take a few minutes|Hashing/.test(warn));
await page.screenshot({ path: "/tmp/proof-checker-bigfile-progress.png" });

// Wait for completion — 2.5 GB of zeros, WASM SHA-256.
await page.waitForSelector(".verdict-title", { timeout: 300_000 });
const secs = ((Date.now() - t0) / 1000).toFixed(1);
const verdict = await page.textContent(".verdict-title");
check("2.5 GB completes with a verdict (old code refused it)", !!verdict, `${verdict} in ${secs}s`);
const hash = (await page.textContent(".report")) ?? "";
// sha256 of 2.5 GiB of zeros, cross-checked out-of-band below.
const expected = execFileSync("sha256sum", [BIG], { encoding: "utf8" }).slice(0, 64);
check("browser hash equals sha256sum", hash.includes(expected), expected.slice(0, 16) + "…");

await browser.close();
execFileSync("rm", ["-f", BIG]);
console.log(failures.length ? `\n${failures.length} FAILURE(S)` : "\nBIG-FILE BROWSER CHECKS PASSED");
process.exit(failures.length ? 1 : 0);
