// Orchestration tests: drive the full lookup -> fetch -> verify -> history ->
// verdict path with a stubbed fetch, so the gateway/provenance/verdict/timeline
// logic is covered without network access. Envelopes are reconstructed from the
// real vectors, so the verification inside is genuine — only transport is faked.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MAX_CANDIDATES,
  assessContinuity,
  checkProvenance,
  checkProvenanceForHash,
} from "../src/provenance";
import type { AssetEvent, Envelope } from "../src/types";

interface Vector {
  inputs: { envelope_pre_signature: Record<string, unknown> };
  fixed_keypair: { ed25519_public_hex: string };
  expected_outputs: { payload_hash_hex: string; signature_hex: string };
}

function loadEnvelope(name: string): Envelope {
  const v = JSON.parse(
    readFileSync(fileURLToPath(new URL(`../packages/proof/test-vectors/${name}`, import.meta.url)), "utf8"),
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

const REGISTERED_HASH = (registered.payload as { hash: string }).hash;
const OBSERVED_HASH = (tampered.payload as { observed: { hash: string } }).observed.hash;

const GATEWAY = "https://gw.example";

interface Edge {
  id: string;
  block?: { height: number; timestamp: number } | null;
}

// Routes the two GraphQL query shapes apart by body content (the asset-events
// query references the Asset-Id tag; the hash-lookup query does not). hashEdges
// === null simulates a gateway failure on the initial lookup.
function stubFetch(opts: {
  hashEdges?: Edge[] | null;
  assetEdges?: Edge[];
  envelopes?: Record<string, Envelope>;
}): void {
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.endsWith("/graphql")) {
      const body = typeof init?.body === "string" ? init.body : "";
      const isAssetQuery = body.includes("Asset-Id");
      if (!isAssetQuery && opts.hashEdges === null) {
        return new Response("boom", { status: 502, statusText: "Bad Gateway" });
      }
      const list = isAssetQuery ? (opts.assetEdges ?? []) : (opts.hashEdges ?? []);
      const edges = list.map((n) => ({ node: { id: n.id, tags: [], block: n.block ?? null } }));
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
  it("returns provenance-found and builds the asset history", async () => {
    stubFetch({
      hashEdges: [{ id: "TX_REG" }],
      assetEdges: [{ id: "TX_REG", block: { height: 1, timestamp: 1_700_000_000 } }],
      envelopes: { TX_REG: registered },
    });
    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.verdict).toBe("provenance-found");
    expect(report.matches).toHaveLength(1);
    expect(report.matches[0].role).toBe("asset");
    expect(report.histories).toHaveLength(1);
    expect(report.histories[0].events).toHaveLength(1);
    expect(report.histories[0].events[0].matchedRole).toBe("asset");
    expect(report.histories[0].events[0].blockTimestamp).toBe(1_700_000_000);
    expect(report.rejected).toHaveLength(0);
  });

  it("orders a multi-event timeline newest-first and binds the user's bytes to both roles", async () => {
    // The user holds the known-good bytes: they are the registration content AND
    // the baseline referenced by the later tamper event.
    stubFetch({
      hashEdges: [{ id: "TX_REG" }],
      assetEdges: [
        { id: "TX_TAMPER", block: { height: 20, timestamp: 1_700_002_000 } },
        { id: "TX_REG", block: { height: 10, timestamp: 1_700_000_000 } },
      ],
      envelopes: { TX_REG: registered, TX_TAMPER: tampered },
    });
    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.verdict).toBe("provenance-found");
    expect(report.histories).toHaveLength(1);

    const events = report.histories[0].events;
    expect(events.map((e) => e.envelope.event_type)).toEqual(["tamper_detected", "asset_registered"]);
    expect(events.find((e) => e.envelope.event_type === "asset_registered")?.matchedRole).toBe("asset");
    expect(events.find((e) => e.envelope.event_type === "tamper_detected")?.matchedRole).toBe("baseline");
    // Each chain has a single event here, so the whole history reads as linked.
    expect(report.histories[0].continuity).toBe("linked");
  });

  it("returns tampered-bytes when the bytes match a tamper Observed-Hash", async () => {
    stubFetch({
      hashEdges: [{ id: "TX_TAMPER" }],
      assetEdges: [{ id: "TX_TAMPER", block: { height: 20, timestamp: 1_700_002_000 } }],
      envelopes: { TX_TAMPER: tampered },
    });
    const report = await checkProvenanceForHash(OBSERVED_HASH, [GATEWAY]);
    expect(report.verdict).toBe("tampered-bytes");
    expect(report.histories[0].events[0].matchedRole).toBe("observed");
  });

  it("returns no-match when nothing references the hash", async () => {
    stubFetch({ hashEdges: [] });
    const report = await checkProvenanceForHash("a".repeat(64), [GATEWAY]);
    expect(report.verdict).toBe("no-match");
    expect(report.histories).toHaveLength(0);
  });

  it("returns error (not no-match) when the gateway lookup fails", async () => {
    stubFetch({ hashEdges: null });
    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.verdict).toBe("error");
    expect(report.error).toBeTruthy();
  });

  it("rejects a tag-matched candidate whose bytes do not actually bind", async () => {
    stubFetch({ hashEdges: [{ id: "TX_LIE" }], envelopes: { TX_LIE: registered } });
    const report = await checkProvenanceForHash("b".repeat(64), [GATEWAY]);
    expect(report.verdict).toBe("no-match");
    expect(report.rejected).toHaveLength(1);
    expect(report.rejected[0].txId).toBe("TX_LIE");
  });
});

// Registry-driven extension: discovered peers are consulted ONLY when the
// configured chain is exhausted, and only ever appended after it.
describe("registry peer extension", () => {
  // Per-host stub: configured gateway behavior vs peer gateway behavior.
  function stubHostFetch(opts: {
    configured: "fail" | "empty";
    peerHasIt?: boolean;
    peerFails?: boolean;
  }): void {
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const origin = new URL(url).origin;
      const isPeer = origin === "https://peer.example";
      if (url.endsWith("/graphql")) {
        if (!isPeer && opts.configured === "fail") {
          return new Response("boom", { status: 502, statusText: "Bad Gateway" });
        }
        if (isPeer && opts.peerFails) {
          return new Response("boom", { status: 502, statusText: "Bad Gateway" });
        }
        const body = typeof init?.body === "string" ? init.body : "";
        const isAssetQuery = body.includes("Asset-Id");
        const list =
          isPeer && opts.peerHasIt && !isAssetQuery ? [{ node: { id: "TX_REG", tags: [], block: null } }] : [];
        return Response.json({ data: { transactions: { edges: list } } });
      }
      if (/\/raw\//.test(url)) return Response.json(registered);
      throw new Error(`unexpected fetch ${url}`);
    });
  }
  const PEERS = () => Promise.resolve(["https://peer.example"]);

  it("rescues an all-failed chain via a discovered peer (error → found)", async () => {
    stubHostFetch({ configured: "fail", peerHasIt: true });
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], { registryPeers: PEERS });
    expect(r.verdict).toBe("provenance-found");
    expect(r.gateway).toBe("https://peer.example");
    expect(r.gatewaysQueried).toEqual([GATEWAY, "https://peer.example"]);
    expect(r.registryPeersUsed).toEqual(["https://peer.example"]);
  });

  it("extends an all-empty chain (no-match → found on a peer)", async () => {
    stubHostFetch({ configured: "empty", peerHasIt: true });
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], { registryPeers: PEERS });
    expect(r.verdict).toBe("provenance-found");
    expect(r.gateway).toBe("https://peer.example");
  });

  it("upgrades error to an honest no-match when a peer is reachable but empty", async () => {
    stubHostFetch({ configured: "fail", peerHasIt: false });
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], { registryPeers: PEERS });
    expect(r.verdict).toBe("no-match");
    expect(r.gateway).toBe("https://peer.example");
  });

  it("keeps the original error when the peers also fail", async () => {
    stubHostFetch({ configured: "fail", peerFails: true });
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], { registryPeers: PEERS });
    expect(r.verdict).toBe("error");
    expect(r.registryPeersUsed).toEqual(["https://peer.example"]);
  });

  it("keeps the original outcome when peer discovery itself fails", async () => {
    stubHostFetch({ configured: "fail" });
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], {
      registryPeers: () => Promise.reject(new Error("registry down")),
    });
    expect(r.verdict).toBe("error");
    expect(r.registryPeersUsed).toBeUndefined();
  });

  it("never consults the registry when the configured chain finds the bytes", async () => {
    stubFetch({ hashEdges: [{ id: "TX_REG" }], assetEdges: [], envelopes: { TX_REG: registered } });
    const peersFn = vi.fn(PEERS);
    const r = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY], { registryPeers: peersFn });
    expect(r.verdict).toBe("provenance-found");
    expect(peersFn).not.toHaveBeenCalled();
    expect(r.registryPeersUsed).toBeUndefined();
  });

  it("checkProvenance (file path) threads opts: an exhausted chain consults the registry", async () => {
    // Unknown bytes → reachable-but-empty chain → extension consulted.
    stubHostFetch({ configured: "empty", peerHasIt: false });
    const peersFn = vi.fn(PEERS);
    const r = await checkProvenance(
      new Blob([new Uint8Array([1, 2, 3]) as unknown as BlobPart]),
      [GATEWAY],
      undefined,
      { registryPeers: peersFn },
    );
    expect(peersFn).toHaveBeenCalledTimes(1);
    expect(r.verdict).toBe("no-match");
    expect(r.registryPeersUsed).toEqual(["https://peer.example"]);
  });
});

// Continuity is the riskiest logic (a false "broken chain" would imply tampering
// where there is none), so test it directly and conservatively.
describe("assessContinuity", () => {
  function regEvent(payloadHash: string, previousHash: string): AssetEvent {
    return {
      txId: payloadHash.slice(0, 8),
      envelope: {
        event_type: "asset_registered",
        payload_hash: payloadHash,
        previous_hash: previousHash,
      } as unknown as Envelope,
      verification: {} as AssetEvent["verification"],
      blockTimestamp: null,
      blockHeight: null,
      matchedRole: null,
    };
  }

  it("reports 'single' for zero or one event", () => {
    expect(assessContinuity([]).continuity).toBe("single");
    expect(assessContinuity([regEvent("a".repeat(64), "GENESIS")]).continuity).toBe("single");
  });

  it("reports 'linked' for a fully-resolved GENESIS->A->B->C chain", () => {
    const a = "a".repeat(64);
    const b = "b".repeat(64);
    const c = "c".repeat(64);
    const events = [regEvent(a, "GENESIS"), regEvent(b, a), regEvent(c, b)];
    expect(assessContinuity(events).continuity).toBe("linked");
  });

  it("reports 'partial' when an event references a record not in the set", () => {
    const a = "a".repeat(64);
    const c = "c".repeat(64);
    const missingB = "b".repeat(64);
    // a is GENESIS root; c points at missing b -> unresolved -> partial.
    const events = [regEvent(a, "GENESIS"), regEvent(c, missingB)];
    expect(assessContinuity(events).continuity).toBe("partial");
  });

  it("reports 'partial' when there is no single GENESIS root", () => {
    const a = "a".repeat(64);
    const b = "b".repeat(64);
    // Two roots, neither GENESIS-anchored cleanly: a is GENESIS, b is GENESIS too.
    const events = [regEvent(a, "GENESIS"), regEvent(b, "GENESIS")];
    expect(assessContinuity(events).continuity).toBe("partial");
  });
});

describe("candidate cap + tie-break", () => {
  it("caps candidates fetched/verified and flags truncation (B5)", async () => {
    const many: Edge[] = Array.from({ length: MAX_CANDIDATES + 10 }, (_, i) => ({ id: `R${i}` }));
    const envelopes: Record<string, Envelope> = {};
    for (const e of many) envelopes[e.id] = registered;
    stubFetch({ hashEdges: many, assetEdges: [], envelopes });

    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.candidatesTruncated).toBe(true);
    // Only the first MAX_CANDIDATES are processed (all of which bind here).
    expect(report.matches.length).toBe(MAX_CANDIDATES);
  });

  it("does not flag truncation under the cap", async () => {
    stubFetch({
      hashEdges: [{ id: "TX_REG" }],
      assetEdges: [{ id: "TX_REG", block: { height: 1, timestamp: 1 } }],
      envelopes: { TX_REG: registered },
    });
    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.candidatesTruncated).toBe(false);
  });

  it("tie-breaks same-timestamp timeline events by block height, newest-first (B14)", async () => {
    stubFetch({
      hashEdges: [{ id: "TX_REG" }],
      assetEdges: [
        { id: "TX_REG", block: { height: 10, timestamp: 1000 } },
        { id: "TX_TAMP", block: { height: 20, timestamp: 1000 } }, // same ts, higher height
      ],
      envelopes: { TX_REG: registered, TX_TAMP: tampered },
    });
    const report = await checkProvenanceForHash(REGISTERED_HASH, [GATEWAY]);
    expect(report.histories[0].events.map((e) => e.envelope.event_type)).toEqual([
      "tamper_detected",
      "asset_registered",
    ]);
  });
});
