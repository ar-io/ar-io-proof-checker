import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DEFAULT_GATEWAYS,
  MAX_RESPONSE_BYTES,
  REGISTRY_PEER_LIMIT,
  defaultGatewayChain,
  fetchEnvelope,
  fetchRegistryPeers,
  findEnvelopeTxs,
  normalizeGateway,
  normalizeGateways,
  servingGatewayCandidate,
} from "../src/gateway";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("normalizeGateway (B10)", () => {
  it("assumes https for a bare host", () => {
    expect(normalizeGateway("turbo-gateway.com")).toBe("https://turbo-gateway.com");
  });
  it("preserves an explicit scheme and strips trailing slashes", () => {
    expect(normalizeGateway("https://gw.example/")).toBe("https://gw.example");
    expect(normalizeGateway("http://localhost:1984//")).toBe("http://localhost:1984");
  });
  it("rejects non-http(s) schemes (no javascript:/data: into fetch or href)", () => {
    expect(() => normalizeGateway("javascript:alert(1)")).toThrow();
    expect(() => normalizeGateway("data:text/html,x")).toThrow();
    expect(() => normalizeGateway("ftp://x")).toThrow(/http/);
  });
});

describe("normalizeGateways (multi-gateway)", () => {
  it("parses a comma-separated list in order, normalizing each entry", () => {
    expect(normalizeGateways("gw1.example, https://gw2.example/ ,gw3.example")).toEqual([
      "https://gw1.example",
      "https://gw2.example",
      "https://gw3.example",
    ]);
  });
  it("dedupes repeated entries, keeping first position", () => {
    expect(normalizeGateways("gw.example, https://gw.example/")).toEqual(["https://gw.example"]);
  });
  it("ignores empty segments from stray commas", () => {
    expect(normalizeGateways(",gw.example,,")).toEqual(["https://gw.example"]);
  });
  it("falls back to the defaults when empty/whitespace", () => {
    expect(normalizeGateways("   ")).toEqual(DEFAULT_GATEWAYS);
  });
  it("throws on any invalid entry rather than silently dropping it", () => {
    expect(() => normalizeGateways("gw.example, javascript:alert(1)")).toThrow();
  });
});

describe("servingGatewayCandidate / defaultGatewayChain", () => {
  it("derives the parent gateway from an ArNS-style subdomain", () => {
    expect(servingGatewayCandidate("proof-checker.turbo-gateway.com")).toBe(
      "https://turbo-gateway.com",
    );
    // Arweave sandbox subdomains work the same way.
    expect(servingGatewayCandidate("abc123def.arweave.net")).toBe("https://arweave.net");
  });
  it("returns null when there is nothing to derive (dev / apex / IP)", () => {
    expect(servingGatewayCandidate("localhost")).toBeNull();
    expect(servingGatewayCandidate("127.0.0.1")).toBeNull();
    expect(servingGatewayCandidate("[::1]")).toBeNull();
    expect(servingGatewayCandidate("ar.io")).toBeNull(); // apex: no ArNS label to strip
    expect(servingGatewayCandidate("")).toBeNull();
  });
  it("builds the chain serving-first, anchors after, deduped", () => {
    expect(defaultGatewayChain("proof-checker.gw.example")).toEqual([
      "https://gw.example",
      ...DEFAULT_GATEWAYS,
    ]);
    // Serving gateway that IS an anchor doesn't duplicate.
    expect(defaultGatewayChain("proof-checker.turbo-gateway.com")).toEqual(DEFAULT_GATEWAYS);
    // No hostname (or underivable) → anchors only.
    expect(defaultGatewayChain(undefined)).toEqual(DEFAULT_GATEWAYS);
    expect(defaultGatewayChain("localhost")).toEqual(DEFAULT_GATEWAYS);
  });
});

describe("fetchRegistryPeers", () => {
  function stubPeersFetch(byGateway: Record<string, Response | (() => Response)>): void {
    vi.stubGlobal("fetch", async (url: string) => {
      const origin = new URL(url).origin;
      expect(url).toBe(`${origin}/ar-io/peers`);
      const r = byGateway[origin];
      if (!r) throw new TypeError("network down");
      return typeof r === "function" ? r() : r;
    });
  }
  const peers = (entries: Record<string, { url?: string; dataWeight?: number }>) =>
    Response.json({ gateways: entries });

  it("returns peers from the first gateway that serves a list, best dataWeight first", async () => {
    stubPeersFetch({
      "https://gw1.example": new Response("boom", { status: 502 }),
      "https://gw2.example": peers({
        "a:443": { url: "https://peer-low.example", dataWeight: 1 },
        "b:443": { url: "https://peer-high.example", dataWeight: 50 },
      }),
    });
    expect(await fetchRegistryPeers(["https://gw1.example", "https://gw2.example"])).toEqual([
      "https://peer-high.example",
      "https://peer-low.example",
    ]);
  });

  it("filters non-https peers, dedupes against the chain, and caps at the limit", async () => {
    const entries: Record<string, { url?: string; dataWeight?: number }> = {
      insecure: { url: "http://plain.example", dataWeight: 99 },
      self: { url: "https://gw1.example", dataWeight: 98 }, // already in the chain
    };
    for (let i = 0; i < REGISTRY_PEER_LIMIT + 3; i++) {
      entries[`p${i}`] = { url: `https://peer${i}.example`, dataWeight: 10 - i };
    }
    stubPeersFetch({ "https://gw1.example": peers(entries) });
    const got = await fetchRegistryPeers(["https://gw1.example"]);
    expect(got).toHaveLength(REGISTRY_PEER_LIMIT);
    expect(got).not.toContain("http://plain.example");
    expect(got).not.toContain("https://gw1.example");
  });

  it("falls through when a served list yields no usable peer", async () => {
    stubPeersFetch({
      // Reachable, but everything in it is unusable (http-only / already known).
      "https://gw1.example": peers({
        a: { url: "http://plain.example", dataWeight: 9 },
        b: { url: "https://gw1.example", dataWeight: 8 },
      }),
      "https://gw2.example": peers({ c: { url: "https://peer.example", dataWeight: 1 } }),
    });
    expect(await fetchRegistryPeers(["https://gw1.example", "https://gw2.example"])).toEqual([
      "https://peer.example",
    ]);
  });

  it("returns [] when no gateway serves a list (best-effort, never throws)", async () => {
    stubPeersFetch({});
    expect(await fetchRegistryPeers(["https://gw1.example", "https://gw2.example"])).toEqual([]);
  });
});

describe("response-size cap (hostile/broken gateway DoS guard)", () => {
  // A body that streams `chunks` of `chunkSize` bytes, optionally declaring a
  // Content-Length. Models a gateway trying to OOM the tab.
  function hugeBodyResponse(opts: { declared?: number; chunks: number; chunkSize: number }): Response {
    let emitted = 0;
    const stream = new ReadableStream({
      pull(controller) {
        if (emitted >= opts.chunks) {
          controller.close();
          return;
        }
        emitted++;
        controller.enqueue(new Uint8Array(opts.chunkSize));
      },
    });
    const headers = new Headers({ "content-type": "application/json" });
    if (opts.declared !== undefined) headers.set("content-length", String(opts.declared));
    return new Response(stream, { status: 200, headers });
  }

  it("rejects early on a declared-too-large Content-Length", async () => {
    vi.stubGlobal("fetch", async () =>
      hugeBodyResponse({ declared: MAX_RESPONSE_BYTES + 1, chunks: 1, chunkSize: 8 }),
    );
    await expect(fetchEnvelope(["https://gw.example"], "TX")).rejects.toThrow(/too large/);
  });

  it("aborts mid-stream when no Content-Length is declared but the body blows past the cap", async () => {
    // 1 MB chunks; would be ~64 MB if uncapped. The reader must abort past 16 MB.
    let pulled = 0;
    vi.stubGlobal("fetch", async () => {
      const stream = new ReadableStream({
        pull(controller) {
          pulled++;
          if (pulled > 64) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(1024 * 1024));
        },
      });
      return new Response(stream, { status: 200, headers: { "content-type": "application/json" } });
    });
    await expect(fetchEnvelope(["https://gw.example"], "TX")).rejects.toThrow(/cap/);
    // Proves we stopped reading instead of draining all 64 MB.
    expect(pulled).toBeLessThan(40);
  });

  it("passes a normal small body through unharmed", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response(JSON.stringify({ event_type: "asset_registered" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const env = await fetchEnvelope(["https://gw.example"], "TX");
    expect(env.event_type).toBe("asset_registered");
  });
});

describe("fetchEnvelope", () => {
  it("aborts and throws a timeout error when the gateway never responds (B3)", async () => {
    vi.useFakeTimers();
    // A fetch that only rejects when its AbortSignal fires.
    vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    });
    const p = fetchEnvelope(["https://gw.example"], "TX");
    const assertion = expect(p).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(21_000);
    await assertion;
  });

  it("falls through to the next gateway on 404 (propagation lag)", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      urls.push(url);
      if (url.startsWith("https://gw1.example")) {
        return new Response("not found", { status: 404, statusText: "Not Found" });
      }
      return Response.json({ event_type: "asset_registered" });
    });
    const env = await fetchEnvelope(["https://gw1.example", "https://gw2.example"], "TX");
    expect(env.event_type).toBe("asset_registered");
    expect(urls).toEqual(["https://gw1.example/raw/TX", "https://gw2.example/raw/TX"]);
  });

  it("falls through on a network error and reports the last error when all fail", async () => {
    vi.stubGlobal("fetch", async (url: string) => {
      if (url.startsWith("https://gw1.example")) throw new TypeError("network down");
      return new Response("boom", { status: 502, statusText: "Bad Gateway" });
    });
    await expect(fetchEnvelope(["https://gw1.example", "https://gw2.example"], "TX")).rejects.toThrow(
      /502/,
    );
  });
});

// Routes stubbed responses by gateway host and hash-tag name.
function stubTagFetch(
  behavior: (gateway: string, tagName: string) => Response | Promise<Response>,
): void {
  vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
    const body = typeof init?.body === "string" ? init.body : "";
    const tagName = /"name":"(Asset-Hash|Observed-Hash|Baseline-Hash)"/.exec(body)?.[1] ?? "";
    const gateway = new URL(url).origin;
    return behavior(gateway, tagName);
  });
}

function edges(...ids: string[]): Response {
  return Response.json({
    data: { transactions: { edges: ids.map((id) => ({ node: { id, tags: [] } })) } },
  });
}

const HASH = "a".repeat(64);

describe("findEnvelopeTxs multi-gateway fallback", () => {
  it("first gateway 5xx → second gateway's view wins, attributed to it", async () => {
    stubTagFetch((gw) => {
      if (gw === "https://gw1.example") {
        return new Response("boom", { status: 502, statusText: "Bad Gateway" });
      }
      return edges("TX1");
    });
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw2.example");
  });

  it("first gateway reachable-but-empty → falls through; first non-empty view wins", async () => {
    stubTagFetch((gw) => (gw === "https://gw1.example" ? edges() : edges("TX2")));
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX2"]);
    expect(d.gateway).toBe("https://gw2.example");
  });

  it("all gateways reachable-but-empty → honest empty result, no error", async () => {
    stubTagFetch(() => edges());
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs).toEqual([]);
    expect(d.gateway).toBe("https://gw1.example");
  });

  it("every gateway fails → throws (error verdict upstream)", async () => {
    stubTagFetch(() => new Response("boom", { status: 502, statusText: "Bad Gateway" }));
    await expect(
      findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH),
    ).rejects.toThrow();
  });

  it("keeps per-gateway tag-query resilience: one tag 200, others 502 still serves (B12)", async () => {
    stubTagFetch((_gw, tag) => {
      if (tag === "Asset-Hash") return edges("TX1");
      return new Response("boom", { status: 502, statusText: "Bad Gateway" });
    });
    const d = await findEnvelopeTxs(["https://gw1.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw1.example");
  });

  it("does not union across gateways — the serving gateway's view is atomic", async () => {
    stubTagFetch((gw) => (gw === "https://gw1.example" ? edges("TX1") : edges("TX1", "TX2")));
    const d = await findEnvelopeTxs(["https://gw1.example", "https://gw2.example"], HASH);
    expect(d.txs.map((t) => t.id)).toEqual(["TX1"]);
    expect(d.gateway).toBe("https://gw1.example");
  });
});
