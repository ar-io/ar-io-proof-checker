// Real-browser E2E: drives the production build in headless Chromium against
// LIVE gateways — the only check that exercises render.ts/main.ts in an
// actual browser (the hermetic suite uses happy-dom). Opt-in dev tool, not CI.
//
//   npm i --no-save playwright-core   # not a package dep; install ad hoc
//   npm run build && npm run preview &
//   CHROME_BIN=<chromium binary> node scripts/browser-e2e.mjs
//
// Needs a runnable Chromium (system package, or `npx playwright install
// --with-deps chromium`). Writes verdict screenshots to /tmp.
import { chromium } from "playwright-core";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url)).replace(/\/$/, "");
const EXE = process.env.CHROME_BIN ?? "/usr/bin/chromium-browser";
const APP_URL = "http://localhost:4173/";

const browser = await chromium.launch({ executablePath: EXE });
const page = await browser.newPage({ viewport: { width: 1100, height: 900 } });
const failures = [];
const check = (name, cond, detail = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!cond) failures.push(name);
};
page.on("pageerror", (e) => check("no page JS errors", false, String(e)));

await page.goto(APP_URL, { waitUntil: "load" });

// 1. Default gateway chain prefilled (localhost → static anchors only).
const gwValue = await page.inputValue("#gateway");
check(
  "gateway field prefilled with static anchors on localhost",
  gwValue === "https://turbo-gateway.com, https://arweave.net",
  gwValue,
);

// 2. Drop the verifiable sample → provenance-found, real verification in-browser.
await page.setInputFiles("#file-input", `${ROOT}/samples/sample-verifiable.txt`);
await page.waitForSelector(".verdict-title", { timeout: 90_000 });
const verdict1 = await page.textContent(".verdict-title");
check("verifiable sample → Provenance found", /provenance found/i.test(verdict1 ?? ""), verdict1);
const served = await page.textContent(".report");
check("result attribution rendered", /Result served by/.test(served ?? ""));
check("gateways-queried list rendered", /Gateways queried/.test(served ?? ""));
check("scope honesty line present", /does NOT confirm|verifiable history/i.test(served ?? ""));
await page.screenshot({ path: "/tmp/proof-checker-found.png", fullPage: true });

// 3. Tampered sample → tamper verdict.
await page.setInputFiles("#file-input", `${ROOT}/samples/sample-demo-tampered.txt`);
await page.waitForFunction(
  () => /tamper/i.test(document.querySelector(".verdict-title")?.textContent ?? ""),
  null,
  { timeout: 90_000 },
);
check("tampered sample → tamper verdict", true);
await page.screenshot({ path: "/tmp/proof-checker-tampered.png", fullPage: true });

// 4. Unregistered sample → no-match with honest copy (multi-gateway wording).
await page.setInputFiles("#file-input", `${ROOT}/samples/sample-no-provenance.txt`);
await page.waitForFunction(
  () => /no provenance/i.test(document.querySelector(".verdict-title")?.textContent ?? ""),
  null,
  { timeout: 90_000 },
);
const noMatchBody = await page.textContent(".report");
check("no-match copy says all queried gateways", /queried gateway/i.test(noMatchBody ?? ""));
check("no-match copy: absence ≠ tampering", /NOT proof of tampering/.test(noMatchBody ?? ""));

// 5. Export the JSON report from the no-match run, then re-import and verify.
const dl = page.waitForEvent("download", { timeout: 30_000 });
await page.click("text=Download report");
const file = await (await dl).path();
await page.click("text=Verify a saved report");
await page.setInputFiles("#report-input", file);
await page.waitForFunction(
  () => /re-verif|consistent/i.test(document.querySelector("#results")?.textContent ?? ""),
  null,
  { timeout: 30_000 },
);
const reimport = await page.textContent("#results");
check("report re-import verifies offline", /internally consistent|PASSED|ok/i.test(reimport ?? ""), reimport?.slice(0, 120));
await page.screenshot({ path: "/tmp/proof-checker-reimport.png", fullPage: true });

await browser.close();
console.log(failures.length ? `\n${failures.length} FAILURE(S)` : "\nALL BROWSER CHECKS PASSED");
process.exit(failures.length ? 1 : 0);
