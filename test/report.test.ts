// Report export tests. The load-bearing one is round-trip self-verification:
// a report built from a real check must re-verify against its OWN embedded
// envelopes (no network), and tampering with the embedded evidence must fail it.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { checkProvenanceForHash } from "../src/provenance";
import {
  REPORT_SPEC,
  buildReport,
  reportToHtml,
  reportToJson,
  verifyReport,
} from "../src/report";
import type { Envelope } from "../src/types";

interface Vector {
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: { payload_hash_hex: string; signature_hex: string };
}

function loadEnvelope(name: string): Envelope {
  const v = JSON.parse(
    readFileSync(fileURLToPath(new URL(`../test-vectors/${name}`, import.meta.url)), "utf8"),
  ) as Vector;
  return {
    ...(v.inputs.envelope_pre_signature as unknown as Envelope),
    payload_hash: v.expected_outputs.payload_hash_hex,
    public_key: v.fixed_keypair.ed25519_public_hex,
    signature: v.expected_outputs.signature_hex,
  };
}

const registered = loadEnvelope("envelope-asset-registered-01.json");
const REGISTERED_HASH = (registered.payload as { hash: string }).hash;
const GATEWAY = "https://gw.example";

// Minimal fetch stub returning `registered` for both the hash lookup and the
// asset-events query, so checkProvenanceForHash yields a real ProvenanceReport.
function stubGoodFetch(envelope: Envelope = registered): void {
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/graphql")) {
      return Response.json({
        data: { transactions: { edges: [{ node: { id: "TX1", tags: [], block: { height: 1, timestamp: 1_700_000_000 } } }] } },
      });
    }
    if (/\/raw\//.test(url)) return Response.json(envelope);
    throw new Error(`unexpected ${url}`);
  });
}

afterEach(() => vi.unstubAllGlobals());

async function goodProvenanceReport() {
  stubGoodFetch();
  return checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
}

describe("buildReport", () => {
  it("produces a versioned, typed, self-contained report", async () => {
    const report = buildReport(await goodProvenanceReport());
    expect(report.spec).toBe(REPORT_SPEC);
    expect(report.report_version).toBe(1);
    expect(report.tool.name).toBe("ar-io-proof-checker");
    expect(report.verdict).toBe("provenance-found");
    expect(report.file_sha256).toBe(REGISTERED_HASH);
    expect(report.gateway).toBe(GATEWAY);
    expect(report.gateways_queried).toEqual([GATEWAY]);
    expect(report.matches.length).toBeGreaterThan(0);
    expect(report.scope.length).toBeGreaterThan(0); // disclaimers travel with it
    // The embedded raw envelope is what makes it re-verifiable.
    expect(Object.keys(report.envelopes)).toContain("TX1");
    expect(report.envelopes.TX1.signature).toBe(registered.signature);
  });

  it("caps the embedded rejected list and flags truncation", async () => {
    const base = await goodProvenanceReport();
    base.rejected = Array.from({ length: 250 }, (_, i) => ({ txId: `R${i}`, reason: "nope" }));
    const report = buildReport(base);
    expect(report.rejected.length).toBe(100);
    expect(report.rejected_truncated).toBe(true);
  });

  it("serializes to valid JSON", async () => {
    const report = buildReport(await goodProvenanceReport());
    const parsed = JSON.parse(reportToJson(report));
    expect(parsed.spec).toBe(REPORT_SPEC);
  });
});

describe("verifyReport (round-trip self-verification)", () => {
  it("re-verifies a clean report against its embedded envelopes", async () => {
    const report = buildReport(await goodProvenanceReport());
    const v = await verifyReport(report);
    expect(v.ok).toBe(true);
    expect(v.verdictMatches).toBe(true);
    expect(v.recomputedVerdict).toBe("provenance-found");
    expect(v.results.every((r) => r.authentic)).toBe(true);
  });

  it("FAILS when an embedded envelope is tampered with", async () => {
    const report = buildReport(await goodProvenanceReport());
    // Flip a byte in the embedded payload — payload_hash no longer matches.
    (report.envelopes.TX1.payload as { size_bytes: number }).size_bytes = 999_999;
    const v = await verifyReport(report);
    expect(v.ok).toBe(false);
    expect(v.results.find((r) => r.tx_id === "TX1")?.authentic).toBe(false);
  });

  it("FAILS when the stated verdict is swapped to disagree with the evidence", async () => {
    const report = buildReport(await goodProvenanceReport());
    report.verdict = "tampered-bytes"; // evidence says provenance-found
    const v = await verifyReport(report);
    expect(v.verdictMatches).toBe(false);
    expect(v.ok).toBe(false);
  });
});

describe("reportToHtml", () => {
  it("renders the verdict and embeds the scope disclaimers", async () => {
    const html = reportToHtml(buildReport(await goodProvenanceReport()));
    expect(html).toContain("Provenance found");
    expect(html).toContain("verifiable on-chain history");
    expect(html).toContain(REGISTERED_HASH);
  });

  it("HTML-escapes on-chain-derived strings (no injection from a hostile envelope)", async () => {
    const evil = JSON.parse(JSON.stringify(registered)) as Envelope;
    evil.subject = { ...evil.subject, agent_id: "<script>alert(1)</script>" };
    // (signature won't match, but reportToHtml is pure presentation — we only
    // assert escaping here, not verification.)
    stubGoodFetch(evil);
    const report = buildReport(await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]));
    // Force the hostile string into the rendered surface even if it was rejected:
    report.histories.push({
      tenant_id: "t",
      agent_id: "<script>alert(1)</script>",
      asset_id: "a",
      continuity: "single",
      note: "n",
      events: [],
    });
    const html = reportToHtml(report);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("verifyReport edge cases", () => {
  it("a legitimate no-match report re-verifies as OK (B1 regression)", async () => {
    // No embedded envelopes. Previously results.length===0 forced ok=false,
    // mislabelling a valid no-match export as FAILED.
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/graphql")) return Response.json({ data: { transactions: { edges: [] } } });
      return new Response("nf", { status: 404 });
    });
    const report = buildReport(await checkProvenanceForHash("a".repeat(64), [GATEWAY]));
    expect(report.verdict).toBe("no-match");
    expect(Object.keys(report.envelopes)).toHaveLength(0);

    const v = await verifyReport(report);
    expect(v.recomputedVerdict).toBe("no-match");
    expect(v.verdictMatches).toBe(true);
    expect(v.ok).toBe(true);
  });

  it("a found report with its evidence stripped FAILS (verdict no longer reproduces)", async () => {
    const report = buildReport(await goodProvenanceReport());
    report.envelopes = {}; // strip the embedded evidence
    const v = await verifyReport(report);
    expect(v.recomputedVerdict).toBe("no-match");
    expect(v.verdictMatches).toBe(false);
    expect(v.ok).toBe(false);
  });

  it("one malformed embedded envelope marks only its row not-authentic, no throw (B6)", async () => {
    const report = buildReport(await goodProvenanceReport());
    // Inject a garbage embedded envelope alongside the good one.
    (report.envelopes as Record<string, unknown>).TX_BAD = null;
    const v = await verifyReport(report);
    expect(v.results.find((r) => r.tx_id === "TX_BAD")?.authentic).toBe(false);
    expect(v.results.find((r) => r.tx_id === "TX1")?.authentic).toBe(true);
    // overall ok is false (a bad row exists) but the call did not throw.
    expect(v.ok).toBe(false);
  });
});
