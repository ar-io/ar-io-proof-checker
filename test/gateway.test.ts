import { afterEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_GATEWAY, fetchEnvelope, findEnvelopeTxs, normalizeGateway } from "../src/gateway";

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
  it("falls back to the default when empty/whitespace", () => {
    expect(normalizeGateway("   ")).toBe(DEFAULT_GATEWAY);
  });
  it("rejects non-http(s) schemes (no javascript:/data: into fetch or href)", () => {
    expect(() => normalizeGateway("javascript:alert(1)")).toThrow();
    expect(() => normalizeGateway("data:text/html,x")).toThrow();
    expect(() => normalizeGateway("ftp://x")).toThrow(/http/);
  });
});

describe("fetchEnvelope timeout (B3)", () => {
  it("aborts and throws a timeout error when the gateway never responds", async () => {
    vi.useFakeTimers();
    // A fetch that only rejects when its AbortSignal fires.
    vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      });
    });
    const p = fetchEnvelope("https://gw.example", "TX");
    const assertion = expect(p).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(21_000);
    await assertion;
  });
});

describe("findEnvelopeTxs resilience (B12)", () => {
  function stubTagFetch(behavior: (tagName: string) => Response | Promise<Response>): void {
    vi.stubGlobal("fetch", async (_url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? init.body : "";
      const tagName = /"name":"(Asset-Hash|Observed-Hash|Baseline-Hash)"/.exec(body)?.[1] ?? "";
      return behavior(tagName);
    });
  }

  it("returns results even if some tag queries fail (only Asset-Hash succeeds)", async () => {
    stubTagFetch((tag) => {
      if (tag === "Asset-Hash") {
        return Response.json({ data: { transactions: { edges: [{ node: { id: "TX1", tags: [] } }] } } });
      }
      return new Response("boom", { status: 502, statusText: "Bad Gateway" });
    });
    const txs = await findEnvelopeTxs("https://gw.example", "a".repeat(64));
    expect(txs.map((t) => t.id)).toEqual(["TX1"]);
  });

  it("throws only when EVERY tag query fails", async () => {
    stubTagFetch(() => new Response("boom", { status: 502, statusText: "Bad Gateway" }));
    await expect(findEnvelopeTxs("https://gw.example", "a".repeat(64))).rejects.toThrow();
  });
});
