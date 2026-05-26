// Orchestration tests: drive the full lookup -> fetch -> verify -> verdict path
// with a stubbed fetch, so the gateway/provenance/verdict logic is covered
// without network access. Envelopes are reconstructed from the real vectors, so
// the verification inside is genuine — only the transport is faked.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { checkProvenanceForHash } from "../src/provenance";
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
const tampered = loadEnvelope("envelope-tamper-detected-01.json");

// Hash of the registered (known-good) bytes, and of the observed (tampered) bytes.
const REGISTERED_HASH = (registered.payload as { hash: string }).hash;
const OBSERVED_HASH = (tampered.payload as { observed: { hash: string } }).observed.hash;

const GATEWAY = "https://gw.example";

// Build a fetch stub: GraphQL returns the given tx ids; /raw/<id> returns the
// mapped envelope. A null graphqlEdges simulates a gateway/network failure.
function stubFetch(opts: {
  edges?: { id: string }[] | null;
  envelopes?: Record<string, Envelope>;
}): void {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/graphql")) {
      void init;
      if (opts.edges === null) return new Response("boom", { status: 502, statusText: "Bad Gateway" });
      const edges = (opts.edges ?? []).map((n) => ({ node: { id: n.id, tags: [] } }));
      return Response.json({ data: { transactions: { edges } } });
    }
    const m = /\/raw\/([^/]+)$/.exec(url);
    if (m) {
      const env = opts.envelopes?.[decodeURIComponent(m[1])];
      if (!env) return new Response("not found", { status: 404, statusText: "Not Found" });
      return Response.json(env);
    }
    throw new Error(`unexpected fetch ${url}`);
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("checkProvenanceForHash", () => {
  it("returns provenance-found for bytes matching a verified asset_registered", async () => {
    stubFetch({ edges: [{ id: "TX_REG" }], envelopes: { TX_REG: registered } });
    const report = await checkProvenanceForHash(REGISTERED_HASH, GATEWAY);
    expect(report.verdict).toBe("provenance-found");
    expect(report.matches).toHaveLength(1);
    expect(report.matches[0].role).toBe("asset");
    expect(report.matches[0].verification.ok).toBe(true);
    expect(report.rejected).toHaveLength(0);
  });

  it("returns tampered-bytes when the bytes match a tamper Observed-Hash", async () => {
    stubFetch({ edges: [{ id: "TX_TAMPER" }], envelopes: { TX_TAMPER: tampered } });
    const report = await checkProvenanceForHash(OBSERVED_HASH, GATEWAY);
    expect(report.verdict).toBe("tampered-bytes");
    expect(report.matches[0].role).toBe("observed");
  });

  it("returns no-match when nothing references the hash", async () => {
    stubFetch({ edges: [] });
    const report = await checkProvenanceForHash("a".repeat(64), GATEWAY);
    expect(report.verdict).toBe("no-match");
    expect(report.matches).toHaveLength(0);
  });

  it("returns error (not no-match) when the gateway lookup fails", async () => {
    stubFetch({ edges: null });
    const report = await checkProvenanceForHash(REGISTERED_HASH, GATEWAY);
    expect(report.verdict).toBe("error");
    expect(report.error).toBeTruthy();
  });

  it("rejects a tag-matched candidate whose bytes do not actually bind", async () => {
    // The gateway returns a tx (lying tag) whose envelope is about *other* bytes.
    // The post-fetch content check must exclude it from the verdict.
    stubFetch({ edges: [{ id: "TX_LIE" }], envelopes: { TX_LIE: registered } });
    const report = await checkProvenanceForHash("b".repeat(64), GATEWAY);
    expect(report.verdict).toBe("no-match");
    expect(report.rejected).toHaveLength(1);
    expect(report.rejected[0].txId).toBe("TX_LIE");
  });
});
