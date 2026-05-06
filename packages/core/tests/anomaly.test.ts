/**
 * SAN-406: unit tests for redactAttemptedField helper (com.sanna.anomaly redaction).
 * Cross-SDK parity with sanna-repo's tests/test_anomaly_redaction.py.
 */
import { describe, it, expect } from "vitest";
import { redactAttemptedField } from "../src/anomaly.js";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

describe("redactAttemptedField", () => {
  it("full returns raw", () => {
    expect(redactAttemptedField("rm", "full")).toBe("rm");
  });

  it("undefined returns raw", () => {
    expect(redactAttemptedField("rm", undefined)).toBe("rm");
  });

  it("null returns raw", () => {
    expect(redactAttemptedField("rm", null)).toBe("rm");
  });

  it("empty string returns raw (defensive permissive; sentinel-tolerant)", () => {
    expect(redactAttemptedField("rm", "")).toBe("rm");
  });

  it("redacted returns literal", () => {
    expect(redactAttemptedField("rm", "redacted")).toBe("<redacted>");
  });

  it("hashes_only returns 64-hex lowercase", () => {
    const out = redactAttemptedField("rm", "hashes_only");
    expect(SHA256_HEX_RE.test(out)).toBe(true);
  });

  it("hashes_only is deterministic", () => {
    const a = redactAttemptedField("rm", "hashes_only");
    const b = redactAttemptedField("rm", "hashes_only");
    expect(a).toBe(b);
  });

  it("hashes_only distinguishes inputs", () => {
    const a = redactAttemptedField("rm", "hashes_only");
    const b = redactAttemptedField("ls", "hashes_only");
    expect(a).not.toBe(b);
  });

  it("unknown mode raises", () => {
    expect(() => redactAttemptedField("rm", "definitely-not-a-mode")).toThrow(/unknown contentMode/);
  });

  it("redacted url endpoint", () => {
    expect(redactAttemptedField("https://internal.evil.com/*", "redacted")).toBe("<redacted>");
  });

  it("hashes_only url endpoint", () => {
    const out = redactAttemptedField("https://internal.evil.com/*", "hashes_only");
    expect(SHA256_HEX_RE.test(out)).toBe(true);
  });
});
