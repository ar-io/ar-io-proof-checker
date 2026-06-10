// Entry point. Wires the drop zone / file picker / gateway field to the
// provenance check and renders the result. Everything runs in the browser; no
// network call is made until the user supplies a file.

import { checkProvenance } from "./provenance";
import { DEFAULT_GATEWAYS, normalizeGateways } from "./gateway";
import { fileSizeAdvisory, formatBytes } from "./hash";
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

  // No file is refused on size — hashing streams with flat memory (the old
  // 2 GB refusal guarded the arrayBuffer() OOM that streaming removed). For
  // big files, set time expectations honestly before starting.
  const advisory = fileSizeAdvisory(file.size);

  const progress = loadingWithProgress(
    file.name,
    advisory.level === "warn" ? advisory.message : undefined,
  );
  show(progress.box);
  try {
    const report = await checkProvenance(file, gateways, (done, total) => {
      if (token === activeRun) progress.update(done, total);
    });
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

// Loading box with a live progress line. A multi-GB hash takes minutes;
// without visible progress it reads as a hang, with it it reads as the tool
// doing exactly what was asked. DOM writes are throttled.
function loadingWithProgress(
  filename: string,
  warning?: string,
): { box: HTMLElement; update: (done: number, total: number) => void } {
  const base = `Hashing "${filename}" in your browser — no upload, the bytes never leave this page…`;
  const box = document.createElement("div");
  box.className = "loading";
  const text = document.createElement("p");
  text.textContent = warning ? `${warning}\n${base}` : base;
  const prog = document.createElement("p");
  prog.className = "muted";
  box.append(text, prog);

  const startedAt = Date.now();
  let lastPaint = 0;
  return {
    box,
    update(done: number, total: number) {
      if (total > 0 && done >= total) {
        text.textContent = "Hash complete — querying gateways…";
        prog.textContent = "";
        return;
      }
      const now = Date.now();
      if (now - lastPaint < 100) return;
      lastPaint = now;
      const pct = total > 0 ? Math.floor((done / total) * 100) : 0;
      const elapsed = (now - startedAt) / 1000;
      const rate = elapsed > 0.5 ? `${formatBytes(done / elapsed)}/s — ` : "";
      prog.textContent = `Hashed ${formatBytes(done)} of ${formatBytes(total)} (${pct}%) — ${rate}locally, nothing uploaded`;
    },
  };
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
