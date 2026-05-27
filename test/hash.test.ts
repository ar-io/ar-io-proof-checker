import { describe, expect, it } from "vitest";

import { MAX_FILE_BYTES, WARN_FILE_BYTES, fileSizeAdvisory, formatBytes } from "../src/hash";

describe("formatBytes", () => {
  it("renders human-readable sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(3 * 1024 * 1024 * 1024)).toBe("3.0 GB");
  });
});

describe("fileSizeAdvisory (B11)", () => {
  it("ok for small files", () => {
    expect(fileSizeAdvisory(1024).level).toBe("ok");
  });
  it("warns past the warn threshold", () => {
    expect(fileSizeAdvisory(WARN_FILE_BYTES + 1).level).toBe("warn");
  });
  it("refuses past the hard cap (avoids the OOM crash)", () => {
    const a = fileSizeAdvisory(MAX_FILE_BYTES + 1);
    expect(a.level).toBe("refuse");
    expect(a.message).toMatch(/can't be hashed in the browser yet/);
  });
});
