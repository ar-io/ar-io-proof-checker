// Presentational layer. Renders a ProvenanceReport into DOM. No verification or
// network logic here. All on-chain-derived strings go through textContent (never
// innerHTML) — envelope fields are untrusted input from a gateway.
//
// The verdict copy is load-bearing and tracks proof-checker.md §8 precisely:
// the tool proves "this artifact has a verifiable history," never "this is the
// live production version" or "this is safe." Keep that line crisp.

import type { Match, ProvenanceReport, Verdict } from "./provenance";

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

  switch (report.verdict) {
    case "provenance-found":
    case "tampered-bytes":
      for (const m of report.matches) root.appendChild(renderMatch(m, report.gateway));
      root.appendChild(disclaimer(report.verdict));
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

const ROLE_COPY: Record<Match["role"], string> = {
  asset: "These bytes are the registered (known-good) content for this asset.",
  baseline: "These bytes are the known-good baseline this event refers to.",
  observed: "These bytes are the TAMPERED content that was flagged — not the known-good baseline.",
};

function renderMatch(m: Match, gateway: string): HTMLElement {
  const card = el("div", "match");
  const p = m.envelope;

  const head = el("div", "match-head");
  head.appendChild(el("span", "event-type", p.event_type));
  head.appendChild(el("span", "match-role", ROLE_COPY[m.role]));
  card.appendChild(head);

  card.appendChild(kv("Tenant", p.subject.tenant_id));
  card.appendChild(kv("Agent", p.subject.agent_id));
  card.appendChild(kv("Signing key", p.public_key, "mono"));
  card.appendChild(kv("Signed at", p.signed_at));

  // The three checks that produced this verdict, shown explicitly.
  const checks = el("ul", "checks");
  checks.appendChild(check("Signature valid (Ed25519)", m.verification.signatureOk));
  checks.appendChild(check("Payload hash matches", m.verification.payloadHashOk));
  checks.appendChild(check("Your bytes match this record", m.verification.contentHashOk === true));
  card.appendChild(checks);

  const link = document.createElement("a");
  link.className = "tx-link mono";
  link.href = `${trimSlash(gateway)}/${m.txId}`;
  link.textContent = m.txId;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  card.appendChild(kvNode("Transaction", link));

  return card;
}

function disclaimer(verdict: Verdict): HTMLElement {
  const box = el("div", "disclaimer");
  if (verdict === "tampered-bytes") {
    box.textContent =
      "ⓘ This content was flagged as a tamper of its asset by the agent above. " +
      "The known-good baseline has a different hash than what you provided.";
  } else {
    box.textContent =
      "ⓘ This confirms the artifact's on-chain history. It does NOT confirm this " +
      "copy is the version currently deployed in production, and it is not a " +
      "statement that the file is safe or approved.";
  }
  return box;
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

function check(label: string, ok: boolean): HTMLElement {
  const li = el("li", ok ? "check-ok" : "check-fail");
  li.textContent = `${ok ? "✓" : "✗"} ${label}`;
  return li;
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, "");
}
