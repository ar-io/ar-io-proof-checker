import { describe, expect, it } from "vitest";

import { bytesToHex, hexToBytes, utf8 } from "../src/crypto";

describe("hexToBytes (strict)", () => {
  it("round-trips with bytesToHex", () => {
    expect(bytesToHex(hexToBytes("00ff10ab"))).toBe("00ff10ab");
  });

  it("rejects odd-length input", () => {
    expect(() => hexToBytes("abc")).toThrow(/odd-length/);
  });

  it("rejects non-hex characters — including partial-parse traps like '1g' (B13)", () => {
    // Number.parseInt('1g',16) === 1, so a non-strict impl would silently accept
    // this. The charset guard must reject it.
    expect(() => hexToBytes("1g")).toThrow(/non-hex/);
    expect(() => hexToBytes("zz")).toThrow(/non-hex/);
    expect(() => hexToBytes("00 1")).toThrow();
  });

  it("accepts empty string as empty bytes", () => {
    expect(hexToBytes("")).toEqual(new Uint8Array(0));
  });
});

describe("utf8", () => {
  it("encodes to UTF-8 bytes", () => {
    expect([...utf8("a")]).toEqual([0x61]);
    expect(utf8("€").length).toBe(3); // multi-byte
  });
});
