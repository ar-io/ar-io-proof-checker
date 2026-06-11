// Entry point. Wires the drop zone / file picker / gateway field / tab toggle
// to the provenance check and renders the result. Everything runs in the browser;
// no network call is made until the user supplies a file.

import { checkProvenance } from "./provenance";
import type { ProvenanceReport, Verdict } from "./provenance";
import { defaultGatewayChain, fetchRegistryPeers, normalizeGateways } from "./gateway";
import { fileSizeAdvisory, formatBytes } from "./hash";
import { renderReport, renderReimport } from "./render";
import { REPORT_SPEC, verifyReport, type ProofCheckReport } from "./report";
import { iconCheckCircle, iconAlertTriangle, iconXCircle, iconAlertCircle } from "./icons";
import "./styles.css";

// --- DOM refs ----------------------------------------------------------------

const tabCheck = byId("tab-check");
const tabVerify = byId("tab-verify");
const panelCheck = byId("panel-check");
const panelVerify = byId("panel-verify");
const dropzone = byId("dropzone");
const fileInput = byId<HTMLInputElement>("file-input");
const gatewayInput = byId<HTMLInputElement>("gateway");
const reportInput = byId<HTMLInputElement>("report-input");
const results = byId("results");
const historyContainer = byId("history");

// The default chain adapts to where the app is served from: behind an ar.io
// gateway (ArNS / sandbox subdomain) that gateway heads the list — it just
// delivered this page, so it's up and CORS-reachable. On localhost or a
// non-gateway host this is a no-op and the static anchors stand alone.
const DEFAULT_CHAIN = defaultGatewayChain(window.location.hostname);
gatewayInput.value = DEFAULT_CHAIN.join(", ");
gatewayInput.placeholder = DEFAULT_CHAIN.join(", ");

// --- tab toggle (R1) ---------------------------------------------------------

tabCheck.addEventListener("click", () => switchTab("check"));
tabVerify.addEventListener("click", () => switchTab("verify"));

function switchTab(mode: "check" | "verify"): void {
  const isCheck = mode === "check";
  tabCheck.classList.toggle("tab-active", isCheck);
  tabVerify.classList.toggle("tab-active", !isCheck);
  tabCheck.setAttribute("aria-selected", String(isCheck));
  tabVerify.setAttribute("aria-selected", String(!isCheck));
  panelCheck.hidden = !isCheck;
  panelVerify.hidden = isCheck;
}

// --- run token (B2) ----------------------------------------------------------

// Monotonic token so a slower earlier request can't overwrite a newer result.
// Each run captures the token at start; on completion it only renders if it's
// still the latest. Shared across file-check and report-reimport.
let activeRun = 0;

// --- file check input --------------------------------------------------------

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

// --- sample demos ------------------------------------------------------------

for (const btn of document.querySelectorAll<HTMLButtonElement>(".sample-btn")) {
  btn.addEventListener("click", () => {
    const name = btn.dataset.sample;
    if (!name) return;
    void (async () => {
      try {
        const res = await fetch(`./samples/${name}`);
        if (!res.ok) throw new Error(`fetch sample: ${res.status}`);
        const blob = await res.blob();
        void run(new File([blob], name));
      } catch (e) {
        show(explain(`Could not load sample: ${msg(e)}`));
      }
    })();
  });
}

// --- report re-import --------------------------------------------------------

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

// --- provenance check --------------------------------------------------------

async function run(file: File): Promise<void> {
  const token = ++activeRun;

  // Each gateway must be a valid http(s) URL (B10); comma-separated list,
  // tried in order with fallback. Same list used for both search and data.
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
    // Registry-driven fallback discovery only applies to the untouched default
    // chain — a user-typed list is respected strictly (their gateways, no
    // silent additions).
    const isDefaultChain = gateways.join(", ") === DEFAULT_CHAIN.join(", ");
    const report = await checkProvenance(
      file,
      gateways,
      gateways,
      (done, total) => {
        if (token === activeRun) progress.update(done, total);
      },
      isDefaultChain ? { registryPeers: () => fetchRegistryPeers(gateways) } : undefined,
    );
    if (token === activeRun) {
      const retry = () => void run(file);
      show(renderReport(report, retry));
      addHistory(file.name, report);
    }
  } catch (e) {
    // checkProvenance handles its own errors into a report; this only fires on
    // an unexpected fault (e.g. hashing). Surface it rather than swallowing.
    if (token === activeRun) show(explain(`Unexpected error: ${msg(e)}`, () => void run(file)));
  }
}

// --- session history (R3) ----------------------------------------------------

const MAX_HISTORY = 50;

interface HistoryEntry {
  filename: string;
  fileHash: string;
  verdict: Verdict;
  timestamp: number;
  dom: HTMLElement; // the rendered result to re-display on click
}

const history: HistoryEntry[] = [];

function addHistory(filename: string, report: ProvenanceReport): void {
  history.unshift({
    filename,
    fileHash: report.fileHash,
    verdict: report.verdict,
    timestamp: Date.now(),
    dom: results.firstElementChild as HTMLElement,
  });
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
  renderSessionHistory();
}

function renderSessionHistory(): void {
  if (history.length === 0) {
    historyContainer.replaceChildren();
    return;
  }
  const title = document.createElement("p");
  title.className = "history-title";
  title.textContent = "Session history";

  const list = document.createElement("ul");
  list.className = "history-list";

  const toneMap: Record<Verdict, { icon: () => SVGElement; cls: string }> = {
    "provenance-found": { icon: () => iconCheckCircle("history-icon"), cls: "history-verdict-ok" },
    "tampered-bytes": { icon: () => iconAlertTriangle("history-icon"), cls: "history-verdict-warn" },
    "no-match": { icon: () => iconXCircle("history-icon"), cls: "history-verdict-none" },
    error: { icon: () => iconAlertCircle("history-icon"), cls: "history-verdict-err" },
  };

  for (const entry of history) {
    const li = document.createElement("li");
    li.className = "history-entry";
    if (results.firstElementChild === entry.dom) li.classList.add("history-entry-active");

    const tone = toneMap[entry.verdict];
    const icon = document.createElement("span");
    icon.className = `history-verdict ${tone.cls}`;
    icon.appendChild(tone.icon());

    const name = document.createElement("span");
    name.className = "history-name";
    name.textContent = entry.filename;

    const hash = document.createElement("span");
    hash.className = "history-hash";
    hash.textContent = entry.fileHash.slice(0, 8) + "…";

    const time = document.createElement("span");
    time.className = "history-time";
    time.textContent = new Date(entry.timestamp).toLocaleTimeString();

    li.append(icon, name, hash, time);
    li.addEventListener("click", () => {
      results.replaceChildren(entry.dom);
      renderSessionHistory();
    });
    list.appendChild(li);
  }

  historyContainer.replaceChildren(title, list);
}

// --- DOM helpers -------------------------------------------------------------

function show(node: HTMLElement): void {
  results.replaceChildren(node);
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function explain(text: string, onRetry?: () => void): HTMLElement {
  const box = document.createElement("div");
  box.className = "explain";
  box.textContent = text;
  if (onRetry) {
    const btn = document.createElement("button");
    btn.className = "btn btn-secondary";
    btn.style.marginTop = "0.6rem";
    btn.textContent = "Retry";
    btn.addEventListener("click", onRetry);
    box.appendChild(btn);
  }
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
