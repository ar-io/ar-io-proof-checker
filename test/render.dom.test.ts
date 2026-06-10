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
    gatewaysQueried: ["https://gw.example"],
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
    expect(text).toContain("flagged as a tamper by");
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
  it("attributes the result to the serving gateway and lists everything queried", () => {
    const text =
      renderReport(
        report({
          gateway: "https://gw2.example",
          gatewaysQueried: ["https://gw1.example", "https://gw2.example"],
        }),
      ).textContent ?? "";
    expect(text).toContain("Result served by");
    expect(text).toContain("https://gw2.example");
    expect(text).toContain("Gateways queried");
    expect(text).toContain("https://gw1.example, https://gw2.example");
  });

  it("omits the queried list for a single gateway", () => {
    const text = renderReport(report({})).textContent ?? "";
    expect(text).not.toContain("Gateways queried");
  });

  it("no-match copy reflects that every configured gateway was asked", () => {
    const text =
      renderReport(
        report({
          gatewaysQueried: ["https://gw1.example", "https://gw2.example"],
        }),
      ).textContent ?? "";
    expect(text).toContain("any of the 2 queried gateways");
    expect(text).toContain("NOT proof of tampering");
    // The old per-gateway "point the tool elsewhere" hint is redundant now.
    expect(text).not.toContain("point the tool elsewhere");
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
