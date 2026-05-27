// Exportable, self-verifiable provenance report. Mirrors the ar-io-verify stack
// convention (versioned + typed + capped lists) but with one deliberate
// difference: the proof-checker has no signing identity, so the report is
// UNSIGNED. Its integrity model is "re-verify it yourself" — it embeds the raw
// verified envelopes + the file hash, so anyone (or this tool, via re-import)
// can re-run the exact same verification offline. No ar.io service, no operator
// signature, in the trust path.

import type { Match, ProvenanceReport, Verdict } from "./provenance";
import type { ChainContinuity, ContentRole, Envelope } from "./types";
import { verifyEnvelope } from "./verifier";

export const REPORT_SPEC = "ario.proof-checker.report/v1" as const;
// Keep in sync with package.json. Surfaced in the report so an auditor knows
// which build produced it.
export const TOOL_VERSION = "0.1.0";

// Bound on embedded rejected candidates (cf. ar-io-verify's FAILURE_CAP). A
// spammed/very-popular hash could otherwise bloat the artifact; the count is
// always reported via rejected_truncated.
const REJECTED_CAP = 100;

// The §8 scope language travels WITH the artifact — a saved report is evidence
// that may be read out of context, so the honesty cannot be left behind in the UI.
export const SCOPE_DISCLAIMER: readonly string[] = [
  "This report proves these bytes have a verifiable on-chain history. It does NOT prove this copy is the version currently deployed in production, nor that the file is safe or approved.",
  "A provenance record is signed by some key. That a key belongs to the party you expect is an identity-binding question you must establish out-of-band — it is not part of this cryptographic result.",
  "Absence of a record is not evidence of tampering: bytes may never have been registered, or were registered by an agent predating content-hash tagging, or the queried gateway had not indexed the transaction.",
  "This report is unsigned by design. Its integrity comes from re-verification, not from trusting its issuer: re-run the embedded envelopes through any conformant verifier, or drop this report back into the proof-checker.",
];

export interface ReportMatch {
  tx_id: string;
  event_type: string;
  tenant_id: string;
  agent_id: string;
  signing_key: string;
  role: ContentRole;
  signed_at: string;
}

export interface ReportEvent {
  tx_id: string;
  event_type: string;
  signed_at: string;
  block_timestamp: number | null; // trusted Arweave block time, when mined
  matched_role: ContentRole | null;
}

export interface ReportHistory {
  tenant_id: string;
  agent_id: string;
  asset_id: string;
  continuity: ChainContinuity;
  note: string;
  events: ReportEvent[];
}

export interface ProofCheckReport {
  spec: typeof REPORT_SPEC;
  report_version: 1;
  tool: { name: "ar-io-proof-checker"; version: string };
  // Client wall-clock at generation. ADVISORY only — the trusted timestamps are
  // the per-event Arweave block times inside `histories`.
  generated_at: string;
  generated_at_note: string;
  gateway: string;
  file_sha256: string;
  verdict: Verdict;
  scope: readonly string[];
  matches: ReportMatch[];
  histories: ReportHistory[];
  rejected: { tx_id: string; reason: string }[];
  rejected_truncated: boolean;
  // Raw verified envelopes, keyed by tx id — the bytes that make this report
  // independently re-verifiable. Includes both the matched envelopes and the
  // asset-history context events.
  envelopes: Record<string, Envelope>;
}

// Build the exportable report from an in-memory ProvenanceReport. Pure and
// deterministic (modulo generated_at).
export function buildReport(report: ProvenanceReport): ProofCheckReport {
  const envelopes: Record<string, Envelope> = {};
  for (const m of report.matches) envelopes[m.txId] = m.envelope;
  for (const h of report.histories) {
    for (const e of h.events) envelopes[e.txId] = e.envelope;
  }

  const rejected = report.rejected
    .slice(0, REJECTED_CAP)
    .map((r) => ({ tx_id: r.txId, reason: r.reason }));

  return {
    spec: REPORT_SPEC,
    report_version: 1,
    tool: { name: "ar-io-proof-checker", version: TOOL_VERSION },
    generated_at: new Date().toISOString(),
    generated_at_note: "Client wall-clock; advisory only. Trusted times are the Arweave block times in histories.",
    gateway: report.gateway,
    file_sha256: report.fileHash,
    verdict: report.verdict,
    scope: SCOPE_DISCLAIMER,
    matches: report.matches.map(toReportMatch),
    histories: report.histories.map((h) => ({
      tenant_id: h.tenantId,
      agent_id: h.agentId,
      asset_id: h.assetId,
      continuity: h.continuity,
      note: h.note,
      events: h.events.map((e) => ({
        tx_id: e.txId,
        event_type: e.envelope.event_type,
        signed_at: e.envelope.signed_at,
        block_timestamp: e.blockTimestamp,
        matched_role: e.matchedRole,
      })),
    })),
    rejected,
    rejected_truncated: report.rejected.length > rejected.length,
    envelopes,
  };
}

function toReportMatch(m: Match): ReportMatch {
  return {
    tx_id: m.txId,
    event_type: m.envelope.event_type,
    tenant_id: m.envelope.subject.tenant_id,
    agent_id: m.envelope.subject.agent_id,
    signing_key: m.envelope.public_key,
    role: m.role,
    signed_at: m.envelope.signed_at,
  };
}

export function reportToJson(report: ProofCheckReport): string {
  return JSON.stringify(report, null, 2);
}

export interface ReportVerification {
  // Every embedded envelope is still cryptographically authentic AND the verdict
  // recomputed from re-binding equals the report's stated verdict.
  ok: boolean;
  recomputedVerdict: Verdict;
  verdictMatches: boolean;
  results: {
    tx_id: string;
    event_type: string;
    authentic: boolean; // spec + payload_hash + signature
    contentBound: boolean; // these exact bytes
    role: ContentRole | null;
  }[];
}

// Re-verify a report against its own embedded evidence — no network needed. This
// is what makes the artifact self-verifiable: it confirms (1) every embedded
// envelope is authentic, and (2) the stated verdict is reproduced by re-binding
// the file hash. Used by the re-import path and by tests.
export async function verifyReport(report: ProofCheckReport): Promise<ReportVerification> {
  const results: ReportVerification["results"] = [];
  for (const [txId, env] of Object.entries(report.envelopes)) {
    const v = await verifyEnvelope(env, report.file_sha256);
    results.push({
      tx_id: txId,
      event_type: env.event_type,
      authentic: v.ok,
      contentBound: v.contentHashOk === true,
      role: v.contentRole,
    });
  }

  const bound = results.filter((r) => r.authentic && r.contentBound);
  const recomputedVerdict: Verdict =
    bound.length === 0
      ? "no-match"
      : bound.some((r) => r.role === "observed")
        ? "tampered-bytes"
        : "provenance-found";

  const allAuthentic = results.length > 0 && results.every((r) => r.authentic);
  const verdictMatches = recomputedVerdict === report.verdict;

  return {
    ok: allAuthentic && verdictMatches,
    recomputedVerdict,
    verdictMatches,
    results,
  };
}

// Standalone printable HTML for the report (browser Print -> Save as PDF). All
// on-chain-derived strings are HTML-escaped — a report may embed attacker-chosen
// tenant/agent/key strings. The machine-verifiable JSON is the re-verifiable
// artifact; this is the human presentation.
export function reportToHtml(report: ProofCheckReport): string {
  const verdictLabel: Record<Verdict, string> = {
    "provenance-found": "✓ Provenance found",
    "tampered-bytes": "⚠ These bytes match a TAMPER record",
    "no-match": "✗ No provenance found",
    error: "! Lookup failed — verdict unknown",
  };

  const matchRows = report.matches
    .map(
      (m) => `<tr>
        <td>${esc(m.event_type)}</td>
        <td>${esc(m.tenant_id)}</td>
        <td>${esc(m.agent_id)}</td>
        <td class="mono">${esc(m.role)}</td>
        <td class="mono small">${esc(m.signing_key)}</td>
        <td class="mono small">${esc(m.tx_id)}</td>
      </tr>`,
    )
    .join("");

  const historyBlocks = report.histories
    .map(
      (h) => `<div class="history">
        <h3>${esc(h.asset_id)}</h3>
        <p class="muted">tenant ${esc(h.tenant_id)} · agent ${esc(h.agent_id)} · ${esc(h.continuity)} — ${esc(h.note)}</p>
        <table>
          <tr><th>event</th><th>when</th><th>your file?</th><th>tx</th></tr>
          ${h.events
            .map(
              (e) => `<tr>
                <td>${esc(e.event_type)}</td>
                <td class="small">${esc(formatWhen(e))}</td>
                <td>${e.matched_role ? esc(e.matched_role) : "—"}</td>
                <td class="mono small">${esc(e.tx_id)}</td>
              </tr>`,
            )
            .join("")}
        </table>
      </div>`,
    )
    .join("");

  const rejectedBlock =
    report.rejected.length > 0
      ? `<h2>Candidates that did NOT verify</h2>
         <p class="muted">Returned by the gateway's tag index but excluded from the verdict.${
           report.rejected_truncated ? " (list truncated)" : ""
         }</p>
         <ul>${report.rejected.map((r) => `<li class="mono small">${esc(r.tx_id)} — ${esc(r.reason)}</li>`).join("")}</ul>`
      : "";

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>ar.io provenance report — ${esc(report.file_sha256.slice(0, 12))}…</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; color: #111; max-width: 820px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 1.6rem; border-bottom: 1px solid #ddd; padding-bottom: .2rem; }
  .verdict { font-size: 1.2rem; font-weight: 700; padding: .6rem .8rem; border: 2px solid #888; border-radius: 6px; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0; } th, td { text-align: left; padding: .3rem .5rem; border-bottom: 1px solid #eee; vertical-align: top; }
  .mono { font-family: ui-monospace, Menlo, Consolas, monospace; } .small { font-size: .8rem; word-break: break-all; } .muted { color: #666; }
  .kv { margin: .2rem 0; } .kv b { display: inline-block; min-width: 150px; color: #666; font-weight: 400; }
  .scope li { color: #444; margin: .3rem 0; } footer { margin-top: 2rem; color: #888; font-size: .8rem; border-top: 1px solid #ddd; padding-top: .6rem; }
</style></head><body>
<h1>ar.io provenance report</h1>
<p class="verdict">${esc(verdictLabel[report.verdict])}</p>
<div class="kv"><b>File SHA-256</b><span class="mono small">${esc(report.file_sha256)}</span></div>
<div class="kv"><b>Gateway</b>${esc(report.gateway)}</div>
<div class="kv"><b>Generated</b>${esc(report.generated_at)} <span class="muted">(advisory client clock)</span></div>
<div class="kv"><b>Tool</b>${esc(report.tool.name)} ${esc(report.tool.version)} · ${esc(report.spec)}</div>
${report.matches.length ? `<h2>Matched records</h2><table><tr><th>event</th><th>tenant</th><th>agent</th><th>role</th><th>signing key</th><th>tx</th></tr>${matchRows}</table>` : ""}
${historyBlocks ? `<h2>Asset history</h2>${historyBlocks}` : ""}
${rejectedBlock}
<h2>Scope &amp; how to trust this report</h2>
<ul class="scope">${report.scope.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
<footer>Unsigned by design. The machine-verifiable JSON export embeds the raw signed envelopes; re-verify offline with any conformant verifier, or drop the JSON back into the proof-checker.</footer>
</body></html>`;
}

function formatWhen(e: ReportEvent): string {
  if (e.block_timestamp !== null) {
    return `${new Date(e.block_timestamp * 1000).toISOString()} (block time)`;
  }
  return `${e.signed_at} (signed_at — advisory)`;
}

function esc(s: string): string {
  return s.replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c,
  );
}
