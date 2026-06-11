// Presentational layer. Renders a ProvenanceReport into DOM. No verification or
// network logic here. All on-chain-derived strings go through textContent (never
// innerHTML) — envelope fields are untrusted input from a gateway.
//
// The verdict copy is load-bearing and tracks proof-checker.md §8 precisely:
// the tool proves "this artifact has a verifiable history," never "this is the
// live production version" or "this is safe." Keep that line crisp.

import { MAX_CANDIDATES, type Match, type ProvenanceReport, type Verdict } from "./provenance";
import {
  buildReport,
  reportToHtml,
  reportToJson,
  type ProofCheckReport,
  type ReportVerification,
} from "./report";
import type { AssetEvent, AssetHistory, ContentRole } from "./types";
import {
  iconCheckCircle,
  iconAlertTriangle,
  iconXCircle,
  iconAlertCircle,
  iconShieldCheck,
  iconCheck,
  iconLink,
} from "./icons";

// --- human-readable labels ---------------------------------------------------

const VERDICT_ICON: Record<Verdict, () => SVGElement> = {
  "provenance-found": () => iconCheckCircle("verdict-icon"),
  "tampered-bytes": () => iconAlertTriangle("verdict-icon"),
  "no-match": () => iconXCircle("verdict-icon"),
  error: () => iconAlertCircle("verdict-icon"),
};

const VERDICT_COPY: Record<Verdict, { title: string; tone: string }> = {
  "provenance-found": { title: "Provenance found", tone: "ok" },
  "tampered-bytes": { title: "These bytes match a tamper record", tone: "warn" },
  "no-match": { title: "No provenance found", tone: "none" },
  error: { title: "Lookup failed — verdict unknown", tone: "err" },
};

function humanEventType(raw: string): string {
  const map: Record<string, string> = {
    asset_registered: "Asset registered",
    tamper_detected: "Tamper detected",
    asset_missing: "Asset missing",
    verification_checkpoint: "Verification checkpoint",
    key_retired: "Key retired",
    policy_changed: "Policy changed",
  };
  return map[raw] ?? raw;
}

const ROLE_LABEL: Record<ContentRole, string> = {
  asset: "Your file",
  baseline: "Your file (known-good)",
  observed: "Your file (flagged)",
};

const ROLE_TONE: Record<ContentRole, string> = {
  asset: "ok",
  baseline: "ok",
  observed: "warn",
};

// --- main report view --------------------------------------------------------

export function renderReport(report: ProvenanceReport, onRetry?: () => void): HTMLElement {
  const root = el("section", "report");
  const meta = VERDICT_COPY[report.verdict];

  // Single result card — verdict header, metadata, findings, actions
  const card = el("div", `result-card result-card-${meta.tone}`);

  // Card header: verdict
  const header = el("div", "result-header");
  header.appendChild(VERDICT_ICON[report.verdict]());
  header.appendChild(el("span", "verdict-title", meta.title));
  card.appendChild(header);

  // File hash
  card.appendChild(kv("File hash (SHA-256)", report.fileHash, "mono"));

  if (report.candidatesTruncated) {
    card.appendChild(
      el(
        "p",
        "muted",
        `More records were found than could be checked — only the first ${MAX_CANDIDATES} were verified.`,
      ),
    );
  }

  // Findings body
  switch (report.verdict) {
    case "provenance-found":
    case "tampered-bytes":
      if (report.histories.length > 0) {
        if (report.histories.length > 1) {
          card.appendChild(
            el(
              "p",
              "muted",
              `Matched ${report.histories.length} assets (newest first):`,
            ),
          );
        }
        for (const h of report.histories) card.appendChild(renderHistory(h, report.gateway));
      } else {
        for (const m of report.matches) card.appendChild(renderBareMatch(m, report.gateway));
      }
      break;
    case "no-match":
      card.appendChild(noMatchCopy(report));
      break;
    case "error":
      card.appendChild(errorCopy(report.error ?? "unknown error", onRetry));
      break;
  }

  if (report.rejected.length > 0) card.appendChild(renderRejected(report));

  // Card footer: export actions
  if (report.verdict !== "error") card.appendChild(renderActions(report));

  root.appendChild(card);

  // Disclaimer sits outside the card — it's a scope caveat, not a finding
  if (report.verdict === "provenance-found" || report.verdict === "tampered-bytes") {
    root.appendChild(disclaimer(report));
  }

  return root;
}

// --- report export actions -------------------------------------------------

function renderActions(report: ProvenanceReport): HTMLElement {
  const bar = el("div", "actions");

  const jsonBtn = document.createElement("button");
  jsonBtn.className = "btn";
  jsonBtn.textContent = "Download report (JSON)";
  jsonBtn.addEventListener("click", () => {
    const r = buildReport(report);
    downloadBlob(`provenance-${report.fileHash.slice(0, 12)}.json`, reportToJson(r), "application/json");
  });

  const printBtn = document.createElement("button");
  printBtn.className = "btn btn-secondary";
  printBtn.textContent = "Open printable report";
  printBtn.addEventListener("click", () => {
    const r = buildReport(report);
    const html = reportToHtml(r);
    const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
    const win = window.open(url, "_blank", "noopener");
    if (win === null) {
      // Popup blocked — fall back to downloading the HTML so the action never
      // silently no-ops (B17).
      URL.revokeObjectURL(url);
      downloadBlob(`provenance-${report.fileHash.slice(0, 12)}.html`, html, "text/html");
      return;
    }
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  });

  bar.append(jsonBtn, printBtn);
  if (report.matches.length > 0) bar.appendChild(goVerifyButton(report));
  return bar;
}

// The optional "verify with the Go reference implementation" toggle: a
// lazy-loaded WASM build of ar-io-agent's pkg/proof — the same kernel `ariod
// verify` runs — re-checks every matched envelope. The JS verifier remains
// the default and its verdict ALWAYS stands; this is a cross-implementation
// confirmation, never a replacement. The ~1 MB (compressed) binary is fetched
// on first use only, from this app's own assets — no external request.
function goVerifyButton(report: ProvenanceReport): HTMLElement {
  const wrap = el("div", "go-verify");
  const btn = document.createElement("button");
  btn.className = "btn btn-secondary";
  btn.textContent = "Verify with Go reference (WASM)";
  btn.addEventListener("click", () => {
    btn.disabled = true;
    void runGoVerify(report, wrap, btn);
  });
  wrap.appendChild(btn);
  return wrap;
}

async function runGoVerify(
  report: ProvenanceReport,
  wrap: HTMLElement,
  btn: HTMLButtonElement,
): Promise<void> {
  const status = el(
    "p",
    "muted",
    "Loading the Go reference verifier (~1 MB compressed, one-time, served from this app's own assets)\u2026",
  );
  wrap.appendChild(status);
  try {
    const { verifyEnvelopeWasm } = await import("./verifier-wasm");
    const box = el("div", "go-verify-results");
    let disagreements = 0;
    for (const m of report.matches) {
      const wasm = await verifyEnvelopeWasm(m.envelope, report.fileHash);
      const agrees = wasm.ok === m.verification.ok && wasm.contentHashOk === m.verification.contentHashOk;
      if (!agrees) disagreements++;
      const row = el("p", agrees ? "check-pass" : "check-fail");
      row.appendChild(agrees ? iconCheck("inline-icon") : iconXCircle("inline-icon"));
      row.appendChild(document.createTextNode(
        ` ${m.txId.slice(0, 12)}\u2026 Go kernel: ` +
          `${wasm.ok ? "verified" : `FAILED (${wasm.errors[0] ?? "unknown"})`}` +
          `${agrees ? " \u2014 agrees with the JS verifier" : " \u2014 DISAGREES with the JS verifier"}`,
      ));
      box.appendChild(row);
    }
    box.appendChild(
      el(
        "p",
        disagreements === 0 ? "muted" : "check-fail",
        disagreements === 0
          ? `The Go reference implementation agrees with the in-browser JS verifier on all ${report.matches.length} matched envelope(s).`
          : "The two implementations DISAGREE \u2014 this should never happen; please report it. The JS verdict above stands.",
      ),
    );
    status.replaceWith(box);
  } catch (e) {
    status.textContent =
      "The Go verifier could not be loaded (WASM unavailable or blocked in this browser). " +
      "The JS verdict above stands \u2014 it is the same algorithm, independently implemented and " +
      `conformance-tested. (${e instanceof Error ? e.message : String(e)})`;
    btn.disabled = false;
  }
}

function downloadBlob(filename: string, content: string, mime: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

// --- re-imported report verification ---------------------------------------

export function renderReimport(report: ProofCheckReport, v: ReportVerification): HTMLElement {
  const root = el("section", "report");

  const tone = v.ok ? "ok" : "err";
  const banner = el("div", `verdict verdict-${tone}`);
  banner.appendChild(v.ok ? iconCheckCircle("verdict-icon") : iconXCircle("verdict-icon"));
  banner.appendChild(
    el("span", "verdict-title", v.ok ? "Report re-verified" : "Report FAILED re-verification"),
  );
  root.appendChild(banner);

  const summary = el("div", "summary-card");
  summary.appendChild(kv("File SHA-256", report.file_sha256, "mono"));
  summary.appendChild(kv("Stated verdict", humanVerdict(report.verdict)));
  summary.appendChild(kv("Recomputed verdict", humanVerdict(v.recomputedVerdict)));
  root.appendChild(summary);

  if (!v.verdictMatches) {
    root.appendChild(
      el("div", "disclaimer disclaimer-alert", "The recomputed verdict does not match the report's stated verdict — treat this report as untrustworthy."),
    );
  }

  // Envelope verification table
  if (v.results.length > 0) {
    const table = el("table", "reimport-table");
    const thead = el("thead", "");
    const hr = el("tr", "");
    for (const h of ["Event", "Transaction", "Signature", "Content match", "Role"]) {
      hr.appendChild(el("th", "", h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody", "");
    for (const r of v.results) {
      const tr = el("tr", r.authentic ? "" : "reimport-row-fail");
      tr.appendChild(el("td", "", humanEventType(r.event_type)));
      tr.appendChild(el("td", "mono", r.tx_id.slice(0, 12) + "…"));
      tr.appendChild(el("td", r.authentic ? "check-pass" : "check-fail", r.authentic ? "Verified" : "Failed"));
      tr.appendChild(el("td", r.contentBound ? "check-pass" : "muted", r.contentBound ? "Yes" : "No"));
      tr.appendChild(el("td", "", r.role ?? "—"));
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    root.appendChild(table);
  }

  root.appendChild(
    el(
      "div",
      "disclaimer",
      "This re-verification ran entirely in your browser against the evidence embedded in the report — no network required. It confirms the report is internally consistent.",
    ),
  );
  return root;
}

function humanVerdict(v: string): string {
  const map: Record<string, string> = {
    "provenance-found": "Provenance found",
    "tampered-bytes": "Tamper record found",
    "no-match": "No match",
    error: "Error",
  };
  return map[v] ?? v;
}

// --- per-asset history (timeline) ------------------------------------------

function renderHistory(h: AssetHistory, gateway: string): HTMLElement {
  const card = el("div", "match");

  const head = el("div", "match-head");
  head.appendChild(el("span", "asset-id", h.assetId));
  head.appendChild(el("span", "match-meta", `${h.tenantId} · ${h.agentId}`));
  card.appendChild(head);

  const cont = el("div", h.continuity === "linked" ? "continuity continuity-linked" : "continuity");
  if (h.continuity === "linked") cont.appendChild(iconLink("continuity-icon"));
  cont.appendChild(document.createTextNode(
    `${h.events.length} event${h.events.length === 1 ? "" : "s"} — ${h.note}`,
  ));
  card.appendChild(cont);

  const timeline = el("ol", "timeline");
  for (const ev of h.events) timeline.appendChild(renderEvent(ev, gateway));
  card.appendChild(timeline);

  return card;
}

// Timeline dot color is driven by the user's relationship to the event, not
// the event type alone. This prevents a red dot on a tamper_detected event
// where the user holds the known-good baseline.
function eventTone(ev: AssetEvent): string {
  if (!ev.matchedRole) return "neutral";
  return ROLE_TONE[ev.matchedRole];
}

function renderEvent(ev: AssetEvent, gateway: string): HTMLElement {
  const li = el("li", `event event-${eventTone(ev)}`);

  // Line 1: event type, timestamp, verified badge, role badge — all inline
  const line = el("div", "event-line");
  line.appendChild(el("span", "event-label", humanEventType(ev.envelope.event_type)));
  line.appendChild(el("span", "event-when", formatWhen(ev)));
  const vbadge = el("span", "verified-badge");
  vbadge.appendChild(iconShieldCheck("verified-icon"));
  vbadge.appendChild(document.createTextNode("Verified"));
  line.appendChild(vbadge);
  if (ev.matchedRole) {
    const badge = el("span", `role-badge role-badge-${ROLE_TONE[ev.matchedRole]}`);
    badge.textContent = ROLE_LABEL[ev.matchedRole];
    line.appendChild(badge);
  }
  li.appendChild(line);

  // Line 2: tx link
  const link = document.createElement("a");
  link.className = "tx-link mono";
  link.href = `${trimSlash(gateway)}/${ev.txId}`;
  link.textContent = ev.txId.slice(0, 12) + "…";
  link.title = ev.txId;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  li.appendChild(link);

  return li;
}

function formatWhen(ev: AssetEvent): string {
  if (ev.blockTimestamp !== null) {
    return new Date(ev.blockTimestamp * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  }
  return `${ev.envelope.signed_at} (advisory)`;
}

// --- fallback bare match (timeline unavailable) ----------------------------

function renderBareMatch(m: Match, gateway: string): HTMLElement {
  const card = el("div", "match");
  const p = m.envelope;
  const head = el("div", "match-head");
  head.appendChild(el("span", "event-label", humanEventType(p.event_type)));
  head.appendChild(el("span", "match-meta", `${signerTenant(m)} · ${signerAgent(m)}`));
  card.appendChild(head);
  card.appendChild(kv("Signing key", p.public_key, "mono"));
  card.appendChild(kv("Signed at", `${p.signed_at} (advisory)`));

  const link = document.createElement("a");
  link.className = "tx-link mono";
  link.href = `${trimSlash(gateway)}/${m.txId}`;
  link.textContent = m.txId.slice(0, 12) + "…";
  link.title = m.txId;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  card.appendChild(kvNode("Transaction", link));
  return card;
}

// --- verdict prose ---------------------------------------------------------

function disclaimer(report: ProvenanceReport): HTMLElement {
  if (report.verdict === "tampered-bytes") {
    const box = el("div", "disclaimer disclaimer-alert");
    const flaggedBy = uniqueSigners(report.matches.filter((m) => m.role === "observed"));
    const alsoKnownGood = report.matches.some((m) => m.role !== "observed");
    box.textContent =
      `This file was flagged as tampered by ${flaggedBy}. ` +
      "Anyone can create a record for any file, so verify you recognize the signing key before acting on this. " +
      (alsoKnownGood
        ? "Note: this file also appears as known-good content in another record above. "
        : "") +
      "This does not indicate whether this copy is the version running in production.";
    return box;
  }
  const box = el("div", "disclaimer");
  box.textContent =
    "This confirms the file has an on-chain history. It does not confirm this " +
    "is the version currently deployed in production, nor that the file is safe or approved.";
  return box;
}

function signerTenant(m: Match): string {
  const s = m.envelope.subject as { tenant_id?: unknown } | undefined;
  return typeof s?.tenant_id === "string" ? s.tenant_id : "unknown";
}

function signerAgent(m: Match): string {
  const s = m.envelope.subject as { agent_id?: unknown } | undefined;
  return typeof s?.agent_id === "string" ? s.agent_id : "unknown";
}

function uniqueSigners(matches: Match[]): string {
  const set = new Set(matches.map((m) => `${signerTenant(m)} / ${signerAgent(m)}`));
  return [...set].join(", ") || "an agent";
}

function noMatchCopy(_report: ProvenanceReport): HTMLElement {
  const box = el("div", "explain");
  box.appendChild(
    el("p", "", "No provenance record was found for this file. This does not mean the file has been tampered with."),
  );
  const ul = el("ul", "");
  for (const reason of [
    "The file was never registered.",
    "It was registered before content-hash tagging was available.",
    "The record hasn't been indexed yet — try again in a few minutes.",
  ]) {
    ul.appendChild(el("li", "", reason));
  }
  box.appendChild(ul);
  return box;
}

function errorCopy(message: string, onRetry?: () => void): HTMLElement {
  const box = el("div", "explain");
  box.appendChild(el("p", "", "The check could not complete. The result is unknown."));
  box.appendChild(kv("Error", message, "mono"));
  if (onRetry) {
    const row = el("div", "error-actions");
    const btn = document.createElement("button");
    btn.className = "btn btn-secondary";
    btn.textContent = "Retry";
    btn.addEventListener("click", onRetry);
    row.appendChild(btn);
    row.appendChild(el("span", "muted", "or adjust gateway settings and try again."));
    box.appendChild(row);
  } else {
    box.appendChild(
      el("p", "muted", "All gateways failed. Try again, or adjust gateway settings."),
    );
  }
  return box;
}

function renderRejected(report: ProvenanceReport): HTMLElement {
  const box = el("details", "rejected");
  const summary = document.createElement("summary");
  summary.textContent = `${report.rejected.length} record(s) excluded`;
  box.appendChild(summary);
  box.appendChild(
    el(
      "p",
      "muted",
      "These records referenced your file's hash but failed cryptographic verification.",
    ),
  );
  for (const r of report.rejected) {
    const row = el("div", "rejected-row");
    row.appendChild(el("span", "mono", r.txId.slice(0, 12) + "…"));
    row.appendChild(el("span", "muted", r.reason));
    box.appendChild(row);
  }
  return box;
}

// --- small DOM helpers -----------------------------------------------------

function el(tag: string, className = "", text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function kv(label: string, value: string, valueClass = ""): HTMLElement {
  return kvNode(label, el("span", valueClass, value));
}

function kvNode(label: string, valueNode: Node): HTMLElement {
  const row = el("div", "kv");
  row.appendChild(el("span", "kv-label", label));
  const v = el("span", "kv-value");
  v.appendChild(valueNode);
  row.appendChild(v);
  return row;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}
