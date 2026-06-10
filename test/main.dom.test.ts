// @vitest-environment happy-dom
//
// main.ts wiring tests: the run-token race guard (B2), file-input reset so the
// same file re-fires (B8), and keyboard activation of the dropzone (B9).
//
// checkProvenance is mocked (partial — real exports like MAX_CANDIDATES /
// verdictFromRoles are preserved) so we control async resolution timing and
// avoid real hashing/network in the DOM environment.

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { ProvenanceReport } from "../src/provenance";

const h = vi.hoisted(() => {
  const resolvers: Array<(r: ProvenanceReport) => void> = [];
  return {
    resolvers,
    checkProvenance: (..._args: unknown[]) =>
      new Promise<ProvenanceReport>((resolve) => {
        resolvers.push(resolve);
      }),
  };
});

vi.mock("../src/provenance", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/provenance")>();
  return { ...actual, checkProvenance: h.checkProvenance };
});

function noMatch(fileHash: string): ProvenanceReport {
  return {
    fileHash,
    gateway: "https://gw.example",
    gatewaysQueried: ["https://gw.example"],
    verdict: "no-match",
    matches: [],
    histories: [],
    rejected: [],
    candidatesTruncated: false,
  };
}

function setFiles(input: HTMLInputElement, files: File[]): void {
  Object.defineProperty(input, "files", { configurable: true, value: files });
}

const tick = () => new Promise((r) => setTimeout(r, 0));

beforeAll(async () => {
  document.body.innerHTML = `
    <div id="dropzone" tabindex="0" role="button"></div>
    <input id="file-input" type="file" />
    <input id="gateway" type="text" />
    <input id="report-input" type="file" />
    <div id="results"></div>`;
  await import("../src/main");
});

afterEach(() => {
  h.resolvers.length = 0;
});

describe("dropzone keyboard activation (B9)", () => {
  it("Enter opens the file picker", () => {
    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    const dropzone = document.getElementById("dropzone")!;
    const clickSpy = vi.spyOn(fileInput, "click").mockImplementation(() => {});
    dropzone.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(clickSpy).toHaveBeenCalledTimes(1);
    clickSpy.mockRestore();
  });
});

describe("file input reset (B8)", () => {
  it("clears input.value after a change so the same file re-fires", () => {
    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    setFiles(fileInput, [new File(["x"], "x.bin")]);
    fileInput.dispatchEvent(new Event("change"));
    expect(fileInput.value).toBe(""); // reset synchronously in the handler
  });
});

describe("run-token race guard (B2)", () => {
  it("a slower earlier run cannot overwrite a newer result", async () => {
    const fileInput = document.getElementById("file-input") as HTMLInputElement;
    const results = document.getElementById("results")!;

    // Drop file A (run 1), then file B (run 2) — both pending.
    setFiles(fileInput, [new File(["A"], "a.bin")]);
    fileInput.dispatchEvent(new Event("change"));
    await tick();
    setFiles(fileInput, [new File(["B"], "b.bin")]);
    fileInput.dispatchEvent(new Event("change"));
    await tick();

    expect(h.resolvers.length).toBe(2);
    const [resolveA, resolveB] = h.resolvers;

    // Newer run (B) finishes first and renders.
    resolveB(noMatch("b".repeat(64)));
    await tick();
    expect(results.textContent).toContain("b".repeat(64));

    // Older run (A) finishes LATER and must NOT clobber B's result.
    resolveA(noMatch("a".repeat(64)));
    await tick();
    expect(results.textContent).toContain("b".repeat(64));
    expect(results.textContent).not.toContain("a".repeat(64));
  });
});
