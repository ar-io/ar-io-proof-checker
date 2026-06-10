import { describe, expect, it } from "vitest";

import { WARN_FILE_BYTES, fileSizeAdvisory, formatBytes } from "../src/hash";

describe("formatBytes", () => {
  it("renders human-readable sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(3 * 1024 * 1024 * 1024)).toBe("3.0 GB");
  });
});

// The size guard's character changed with streaming (B11 superseded): from
// "refuse past 2 GB" to "advise honestly about time, refuse nothing". The
// streaming behavior itself is covered in hash.streaming.test.ts.
describe("fileSizeAdvisory", () => {
  it("ok for small files", () => {
    expect(fileSizeAdvisory(1024).level).toBe("ok");
  });
  it("warns honestly about time past the threshold", () => {
    const a = fileSizeAdvisory(WARN_FILE_BYTES + 1);
    expect(a.level).toBe("warn");
    expect(a.message).toMatch(/hashing locally/);
  });
});
