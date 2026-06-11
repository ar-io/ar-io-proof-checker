// @vitest-environment happy-dom
//
// Render-layer DOM tests. Construct ProvenanceReport objects directly (bypassing
// network/verification) and assert the rendered DOM — covers attribution copy
// (B4), the truncation note (B5), the missing-subject guard (B7), and the
// popup-blocked → download fallback (B17).

import { afterEach, describe, expect, it, vi } from "vitest";

import { renderReport } from "../src/render";
import type { Match, ProvenanceReport } from "../src/provenance";
import type { Envelope, VerificationResult } from "../src/types";

// The Go-verify toggle lazy-imports the WASM adapter; swap it for a settable
// stub so the toggle's three states (agree / disagree / load-failure) are
// testable without instantiating WASM in happy-dom.
const wasmStub = { impl: undefined as undefined | ((env: Envelope, hash?: string) => Promise<VerificationResult>) };
vi.mock("../src/verifier-wasm", () => ({
  verifyEnvelopeWasm: (env: Envelope, hash?: string) => {
    if (!wasmStub.impl) throw new Error("wasm load failure (stubbed)");
    return wasmStub.impl(env, hash);
  },
}));

const okVerification = (role: "asset" | "baseline" | "observed"): VerificationResult => ({
  ok: true,
  specVersionOk: true,
  payloadHashOk: true,
  signatureOk: true,
  contentHashOk: true,
  contentRole: role,
  errors: [],
});

function match(
  role: "asset" | "baseline" | "observed",
  subject: Envelope["subject"] | undefined,
  txId = `TX_${role}`,
): Match {
  return {
    txId,
    envelope: {
      event_type: role === "observed" ? "tamper_detected" : "asset_registered",
      subject,
      public_key: "deadbeef",
      signed_at: "2026-01-01T00:00:00.000Z",
    } as unknown as Envelope,
    verification: okVerification(role),
    role,
  };
}

function report(over: Partial<ProvenanceReport>): ProvenanceReport {
  return {
    fileHash: "a".repeat(64),
    gateway: "https://gw.example",
    graphqlGatewaysQueried: ["https://gw.example"],
    dataGatewaysQueried: ["https://gw.example"],
    verdict: "no-match",
    matches: [],
    histories: [],
    rejected: [],
    candidatesTruncated: false,
    ...over,
  };
}

afterEach(() => vi.restoreAllMocks());

describe("verdict attribution (B4)", () => {
  it("names the flagging signer and notes a co-existing known-good record", () => {
    const r = report({
      verdict: "tampered-bytes",
      matches: [
        match("observed", { type: "agent", tenant_id: "evil-co", agent_id: "rogue-1" }),
        match("asset", { type: "agent", tenant_id: "acme", agent_id: "prod-1" }, "TX_good"),
      ],
    });
    const text = renderReport(r).textContent ?? "";
    expect(text).toContain("flagged as tampered by");
    expect(text).toContain("evil-co / rogue-1"); // attribution
    expect(text).toContain("also appear as known-good"); // doesn't hide the clean record
    expect(text).toContain("anyone can anchor a record referencing any hash");
  });
});

describe("missing subject is guarded (B7)", () => {
  it("renders 'unknown' instead of throwing when subject is absent", () => {
    const r = report({
      verdict: "provenance-found",
      matches: [match("asset", undefined, "TX_nosub")],
    });
    let el: HTMLElement | undefined;
    expect(() => {
      el = renderReport(r);
    }).not.toThrow();
    expect(el?.textContent ?? "").toContain("unknown");
  });
});

describe("truncation note (B5)", () => {
  it("shows a note when candidatesTruncated is set", () => {
    const text = renderReport(report({ candidatesTruncated: true })).textContent ?? "";
    expect(text).toContain("more candidates than were checked");
  });
});

describe("multi-gateway surfacing", () => {
  it("shows both gateway chains in the summary", () => {
    const text =
      renderReport(
        report({
          graphqlGatewaysQueried: ["https://gql.example"],
          dataGatewaysQueried: ["https://data.example"],
        }),
      ).textContent ?? "";
    expect(text).toContain("GraphQL gateways");
    expect(text).toContain("https://gql.example");
    expect(text).toContain("Data gateways");
    expect(text).toContain("https://data.example");
  });

  it("discloses registry-discovered fallback gateways when they were queried", () => {
    const text =
      renderReport(
        report({
          graphqlGatewaysQueried: ["https://gw1.example", "https://peer.example"],
          dataGatewaysQueried: ["https://gw1.example", "https://peer.example"],
          registryPeersUsed: ["https://peer.example"],
        }),
      ).textContent ?? "";
    expect(text).toContain("discovered from the ar.io registry");
    expect(text).toContain("verified in your browser");
  });

  it("no-match copy reflects that every configured gateway was asked", () => {
    const text =
      renderReport(
        report({
          graphqlGatewaysQueried: ["https://gw1.example", "https://gw2.example"],
          dataGatewaysQueried: ["https://gw1.example", "https://gw2.example"],
        }),
      ).textContent ?? "";
    expect(text).toContain("any of the 2 queried gateways");
    expect(text).toContain("not proof of tampering");
  });
});

describe("error verdict", () => {
  it("renders the unknown-verdict copy with the failure detail", () => {
    const text =
      renderReport(
        report({ verdict: "error", error: "all 2 gateway(s) failed: …" }),
      ).textContent ?? "";
    expect(text).toContain("verdict is unknown");
    expect(text).toContain("all 2 gateway(s) failed");
    expect(text).toContain("Every configured gateway failed");
  });
});

describe("Go reference (WASM) verify toggle", () => {
  const tick = () => new Promise((r) => setTimeout(r, 0));
  const found = () =>
    report({
      verdict: "provenance-found",
      matches: [match("asset", { type: "agent", tenant_id: "t", agent_id: "a" })],
    });
  const goBtn = (el: HTMLElement) =>
    [...el.querySelectorAll("button")].find((b) => b.textContent?.includes("Go reference"));

  it("offers the toggle only when there are matched envelopes", () => {
    expect(goBtn(renderReport(found()))).toBeTruthy();
    expect(goBtn(renderReport(report({ verdict: "no-match" })))).toBeUndefined();
  });

  it("renders per-envelope agreement when the Go kernel agrees", async () => {
    wasmStub.impl = async () => ({ ...okVerification("asset"), errors: [] });
    const el = renderReport(found());
    goBtn(el)!.click();
    await tick();
    await tick();
    expect(el.textContent).toContain("agrees with the JS verifier");
    expect(el.textContent).toContain("Go reference implementation agrees");
  });

  it("flags a disagreement loudly and lets the JS verdict stand", async () => {
    wasmStub.impl = async () => ({
      ...okVerification("asset"),
      ok: false,
      signatureOk: false,
      errors: ["proof: signature invalid"],
    });
    const el = renderReport(found());
    goBtn(el)!.click();
    await tick();
    await tick();
    expect(el.textContent).toContain("DISAGREES");
    expect(el.textContent).toContain("The JS verdict above stands");
  });

  it("falls back gracefully when the WASM fails to load", async () => {
    wasmStub.impl = undefined;
    const el = renderReport(found());
    goBtn(el)!.click();
    await tick();
    await tick();
    expect(el.textContent).toContain("could not be loaded");
    expect(el.textContent).toContain("The JS verdict above stands");
    // Button re-enabled so the user can retry.
    expect(goBtn(el)!.disabled).toBe(false);
  });
});

describe("printable report popup fallback (B17)", () => {
  it("downloads the HTML when window.open is blocked (returns null)", () => {
    // Provide blob URL plumbing happy-dom doesn't implement.
    (URL as unknown as { createObjectURL: () => string }).createObjectURL = () => "blob:x";
    (URL as unknown as { revokeObjectURL: () => void }).revokeObjectURL = () => {};
    vi.spyOn(window, "open").mockReturnValue(null);
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const el = renderReport(report({ verdict: "provenance-found", matches: [match("asset", { type: "agent", tenant_id: "t", agent_id: "a" })] }));
    const printBtn = [...el.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("printable"),
    );
    expect(printBtn).toBeTruthy();
    printBtn!.click();

    // Fallback path created a download anchor and clicked it.
    expect(clickSpy).toHaveBeenCalled();
  });
});
