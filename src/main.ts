// Entry point. Wires the drop zone / file picker / gateway field to the
// provenance check and renders the result. Everything runs in the browser; no
// network call is made until the user supplies a file.

import { checkProvenance } from "./provenance";
import { DEFAULT_GATEWAYS, normalizeGateways } from "./gateway";
import { fileSizeAdvisory } from "./hash";
import { renderReport, renderReimport } from "./render";
import { REPORT_SPEC, verifyReport, type ProofCheckReport } from "./report";
import "./styles.css";

const dropzone = byId("dropzone");
const fileInput = byId<HTMLInputElement>("file-input");
const gatewayInput = byId<HTMLInputElement>("gateway");
const reportInput = byId<HTMLInputElement>("report-input");
const results = byId("results");

gatewayInput.value = DEFAULT_GATEWAYS.join(", ");
gatewayInput.placeholder = DEFAULT_GATEWAYS.join(", ");

// Monotonic token so a slower earlier request can't overwrite a newer result
// (B2). Each run captures the token at start; on completion it only renders if
// it's still the latest. Shared across file-check and report-reimport.
let activeRun = 0;

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  // Keyboard parity with the click handler (B9) — the dropzone is a button.
  if (e.key === "Enter" || e.key === " ") {
    e.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  // Reset so selecting the SAME file again still fires `change` (B8).
  fileInput.value = "";
  if (file) void run(file);
});

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragging");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragging"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragging");
  const file = e.dataTransfer?.files?.[0];
  if (file) void run(file);
});

reportInput.addEventListener("change", () => {
  const file = reportInput.files?.[0];
  reportInput.value = ""; // B8
  if (file) void runReport(file);
});

async function runReport(file: File): Promise<void> {
  const token = ++activeRun;
  show(loadingMsg("Re-verifying saved report against its embedded envelopes (no network)…"));
  try {
    const parsed = JSON.parse(await file.text()) as ProofCheckReport;
    if (parsed?.spec !== REPORT_SPEC) {
      throw new Error("not an ar.io proof-checker report (spec mismatch)");
    }
    const verification = await verifyReport(parsed);
    if (token === activeRun) show(renderReimport(parsed, verification));
  } catch (e) {
    if (token === activeRun) show(explain(`Could not re-verify report: ${msg(e)}`));
  }
}

async function run(file: File): Promise<void> {
  const token = ++activeRun;

  // Each gateway must be a valid http(s) URL (B10); comma-separated list,
  // tried in order with fallback.
  let gateways: string[];
  try {
    gateways = normalizeGateways(gatewayInput.value);
    gatewayInput.value = gateways.join(", ");
  } catch (e) {
    show(explain(`Invalid gateway: ${msg(e)}`));
    return;
  }

  // Size guard before we read the whole file into memory (B11).
  const advisory = fileSizeAdvisory(file.size);
  if (advisory.level === "refuse") {
    show(explain(advisory.message));
    return;
  }

  show(loading(file.name, advisory.level === "warn" ? advisory.message : undefined));
  try {
    const report = await checkProvenance(file, gateways);
    if (token === activeRun) show(renderReport(report));
  } catch (e) {
    // checkProvenance handles its own errors into a report; this only fires on
    // an unexpected fault (e.g. hashing). Surface it rather than swallowing.
    if (token === activeRun) show(explain(`Unexpected error: ${msg(e)}`));
  }
}

function show(node: HTMLElement): void {
  results.replaceChildren(node);
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function explain(text: string): HTMLElement {
  const box = document.createElement("div");
  box.className = "explain";
  box.textContent = text;
  return box;
}

function loading(filename: string, warning?: string): HTMLElement {
  const base = `Hashing "${filename}" in your browser and querying the gateway…`;
  return loadingMsg(warning ? `${warning}\n${base}` : base);
}

function loadingMsg(message: string): HTMLElement {
  const box = document.createElement("div");
  box.className = "loading";
  box.textContent = message;
  return box;
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing #${id} in document`);
  return node as T;
}
