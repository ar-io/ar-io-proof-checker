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

const VERDICT_COPY: Record<Verdict, { icon: string; title: string; tone: string }> = {
  "provenance-found": { icon: "✓", title: "Provenance found", tone: "ok" },
  "tampered-bytes": { icon: "⚠", title: "These bytes match a TAMPER record", tone: "warn" },
  "no-match": { icon: "✗", title: "No provenance found", tone: "none" },
  error: { icon: "!", title: "Lookup failed — verdict unknown", tone: "err" },
};

export function renderReport(report: ProvenanceReport): HTMLElement {
  const root = el("section", "report");

  const meta = VERDICT_COPY[report.verdict];
  const banner = el("div", `verdict verdict-${meta.tone}`);
  banner.appendChild(el("span", "verdict-icon", meta.icon));
  banner.appendChild(el("span", "verdict-title", meta.title));
  root.appendChild(banner);

  root.appendChild(kv("Your file's SHA-256", report.fileHash, "mono"));
  root.appendChild(kv("Queried gateway", report.gateway));

  if (report.candidatesTruncated) {
    root.appendChild(
      el(
        "p",
        "muted",
        `The gateway returned more candidates than were checked; only the first ${MAX_CANDIDATES} were verified. ` +
          "Narrow the lookup or try another gateway for completeness.",
      ),
    );
  }

  // A check ran — let the user export it as evidence (any verdict, including
  // no-match: "we checked and found nothing" is itself a recordable result).
  if (report.verdict !== "error") root.appendChild(renderActions(report));

  switch (report.verdict) {
    case "provenance-found":
    case "tampered-bytes":
      if (report.histories.length > 0) {
        if (report.histories.length > 1) {
          root.appendChild(
            el(
              "p",
              "muted",
              `Matched ${report.histories.length} assets (grouped by tenant / agent, newest first):`,
            ),
          );
        }
        for (const h of report.histories) root.appendChild(renderHistory(h, report.gateway));
      } else {
        // Timeline query failed but the direct match stands — never show a found
        // verdict with no detail.
        for (const m of report.matches) root.appendChild(renderBareMatch(m, report.gateway));
      }
      root.appendChild(disclaimer(report));
      break;
    case "no-match":
      root.appendChild(noMatchCopy());
      break;
    case "error":
      root.appendChild(errorCopy(report.error ?? "unknown error"));
      break;
  }

  if (report.rejected.length > 0) root.appendChild(renderRejected(report));
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
  return bar;
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

// Renders the result of re-verifying a saved report against its own embedded
// envelopes (no network). This is the "drop a report back in" trust path.
export function renderReimport(report: ProofCheckReport, v: ReportVerification): HTMLElement {
  const root = el("section", "report");

  const tone = v.ok ? "ok" : "err";
  const banner = el("div", `verdict verdict-${tone}`);
  banner.appendChild(el("span", "verdict-icon", v.ok ? "✓" : "✗"));
  banner.appendChild(
    el("span", "verdict-title", v.ok ? "Report re-verified" : "Report FAILED re-verification"),
  );
  root.appendChild(banner);

  root.appendChild(kv("File SHA-256", report.file_sha256, "mono"));
  root.appendChild(kv("Stated verdict", report.verdict));
  root.appendChild(kv("Recomputed verdict", v.recomputedVerdict));
  if (!v.verdictMatches) {
    root.appendChild(
      el("div", "disclaimer", "⚠ The recomputed verdict does NOT match the report's stated verdict — treat this report as untrustworthy."),
    );
  }

  const list = el("ul", "checks");
  for (const r of v.results) {
    const okRow = r.authentic;
    const li = el("li", okRow ? "check-ok" : "check-fail");
    li.textContent = `${okRow ? "✓" : "✗"} ${r.event_type} ${r.tx_id.slice(0, 12)}… — authentic: ${r.authentic}, your bytes: ${r.contentBound}${r.role ? ` (${r.role})` : ""}`;
    list.appendChild(li);
  }
  root.appendChild(list);

  root.appendChild(
    el(
      "div",
      "disclaimer",
      "ⓘ Re-verification re-ran the signature + payload-hash + content checks on the report's embedded envelopes locally — no gateway, no network. It confirms the report is internally consistent, not that the bytes are the live production version.",
    ),
  );
  return root;
}

// --- per-asset history (timeline) ------------------------------------------

const ROLE_BADGE: Record<ContentRole, string> = {
  asset: "← your file (registered content)",
  baseline: "← your file (known-good baseline)",
  observed: "← your file (the TAMPERED content)",
};

const EVENT_TONE: Record<string, string> = {
  asset_registered: "ok",
  tamper_detected: "warn",
  asset_missing: "warn",
};

function renderHistory(h: AssetHistory, gateway: string): HTMLElement {
  const card = el("div", "match");

  const head = el("div", "match-head");
  head.appendChild(el("span", "event-type", h.assetId));
  head.appendChild(el("span", "match-role", `tenant ${h.tenantId} · agent ${h.agentId}`));
  card.appendChild(head);

  const cont = el("div", h.continuity === "linked" ? "continuity ok" : "continuity muted");
  cont.textContent =
    (h.continuity === "linked" ? "✓ " : "ⓘ ") +
    `${h.events.length} event${h.events.length === 1 ? "" : "s"} — ${h.note}`;
  card.appendChild(cont);

  const timeline = el("ol", "timeline");
  for (const ev of h.events) timeline.appendChild(renderEvent(ev, gateway));
  card.appendChild(timeline);

  return card;
}

function renderEvent(ev: AssetEvent, gateway: string): HTMLElement {
  const li = el("li", `event event-${EVENT_TONE[ev.envelope.event_type] ?? "none"}`);

  const line = el("div", "event-line");
  line.appendChild(el("span", "event-type-sm", ev.envelope.event_type));
  line.appendChild(el("span", "event-when", formatWhen(ev)));
  if (ev.matchedRole) {
    line.appendChild(el("span", "you-badge", ROLE_BADGE[ev.matchedRole]));
  }
  li.appendChild(line);

  const checks = el("span", "event-checks muted");
  checks.textContent = "✓ signature  ✓ payload hash";
  li.appendChild(checks);

  const link = document.createElement("a");
  link.className = "tx-link mono";
  link.href = `${trimSlash(gateway)}/${ev.txId}`;
  link.textContent = ev.txId;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  li.appendChild(link);

  return li;
}

// Trusted Arweave block time when available; otherwise the advisory signed_at.
function formatWhen(ev: AssetEvent): string {
  if (ev.blockTimestamp !== null) {
    return `${new Date(ev.blockTimestamp * 1000).toISOString()} (Arweave block time)`;
  }
  return `${ev.envelope.signed_at} (signed_at — advisory, agent clock)`;
}

// --- fallback bare match (timeline unavailable) ----------------------------

function renderBareMatch(m: Match, gateway: string): HTMLElement {
  const card = el("div", "match");
  const p = m.envelope;
  const head = el("div", "match-head");
  head.appendChild(el("span", "event-type", p.event_type));
  head.appendChild(el("span", "match-role", `tenant ${signerTenant(m)} · agent ${signerAgent(m)}`));
  card.appendChild(head);
  card.appendChild(kv("Signing key", p.public_key, "mono"));
  card.appendChild(kv("Signed at", `${p.signed_at} (advisory)`));

  const link = document.createElement("a");
  link.className = "tx-link mono";
  link.href = `${trimSlash(gateway)}/${m.txId}`;
  link.textContent = m.txId;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  card.appendChild(kvNode("Transaction", link));
  return card;
}

// --- verdict prose ---------------------------------------------------------

// The tamper disclaimer is attributed (B4): a tamper record is a CLAIM by whoever
// signed it, and anyone can anchor a record referencing any hash. Naming the
// signer(s) — and noting any co-existing known-good registration — stops a
// stranger's tamper claim from reading as an unqualified verdict about the file.
function disclaimer(report: ProvenanceReport): HTMLElement {
  const box = el("div", "disclaimer");
  if (report.verdict === "tampered-bytes") {
    const flaggedBy = uniqueSigners(report.matches.filter((m) => m.role === "observed"));
    const alsoKnownGood = report.matches.some((m) => m.role !== "observed");
    box.textContent =
      `⚠ These exact bytes were flagged as a tamper by ${flaggedBy}. That is a claim by ` +
      "that signer — anyone can anchor a record referencing any hash, so confirm you recognize " +
      "the signing key (shown above) before trusting it. " +
      (alsoKnownGood
        ? "Note: these same bytes also appear as known-good content in another record above. "
        : "") +
      "This does not indicate whether this copy is the version running in production.";
  } else {
    box.textContent =
      "ⓘ This confirms the artifact's on-chain history. It does NOT confirm this " +
      "copy is the version currently deployed in production, and it is not a " +
      "statement that the file is safe or approved.";
  }
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

function noMatchCopy(): HTMLElement {
  const box = el("div", "explain");
  box.appendChild(
    el(
      "p",
      "",
      "These bytes have no ar.io provenance record on the queried gateway. This is " +
        "NOT proof of tampering.",
    ),
  );
  const ul = el("ul", "");
  for (const reason of [
    "they were never registered, or",
    "they were registered by an agent predating content-hash tagging, or",
    "the gateway hasn't indexed the transaction yet (try again shortly), or",
    "a different gateway has it — point the tool elsewhere and retry.",
  ]) {
    ul.appendChild(el("li", "", reason));
  }
  box.appendChild(ul);
  return box;
}

function errorCopy(message: string): HTMLElement {
  const box = el("div", "explain");
  box.appendChild(el("p", "", "The lookup could not complete, so the verdict is unknown."));
  box.appendChild(kv("Detail", message, "mono"));
  box.appendChild(el("p", "muted", "Try again, or point the tool at a different gateway."));
  return box;
}

function renderRejected(report: ProvenanceReport): HTMLElement {
  const box = el("details", "rejected");
  const summary = document.createElement("summary");
  summary.textContent = `${report.rejected.length} candidate(s) the gateway returned did NOT verify`;
  box.appendChild(summary);
  box.appendChild(
    el(
      "p",
      "muted",
      "A gateway can return transactions whose tags reference your hash but whose " +
        "contents fail verification. These are correctly excluded from the verdict.",
    ),
  );
  for (const r of report.rejected) {
    const row = el("div", "rejected-row");
    row.appendChild(el("span", "mono", r.txId));
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
