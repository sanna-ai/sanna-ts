/**
 * Cross-SDK NFC normalization scope tests (SAN-225, ADR-004).
 *
 * These tests assert the ADR-004 decision that NFC normalization applies
 * at the hashContent() boundary only. hashObj() does NOT recursively
 * NFC-walk string values or keys.
 *
 * If these tests ever fail, it means either:
 * 1. The ADR-004 decision has been silently overridden in code, OR
 * 2. The spec has been broadened without a coordinated SPEC_VERSION bump.
 *
 * Either outcome is a governance regression per sanna-ts/CLAUDE.md
 * Cross-Language Compatibility — stop and surface the change before
 * continuing.
 *
 * Cross-SDK parity: the equivalent test exists in sanna-repo at
 * tests/test_nfc_scope.py. Both SDKs must produce the same answers
 * to the same input vectors.
 *
 * References:
 * - ADR-004: NFC Normalization Scope in Canonical JSON (decided 2026-02-18)
 * - spec/spec/sanna-specification-v1.4.md Section 3.1, Section 13.1 item 8
 * - SAN-252: contingent upgrade path if real-world NFD strings surface
 */

import { describe, it, expect } from "vitest";
import { hashContent, hashObj } from "../src/hashing.js";

// Build strings from explicit code points to resist editor/clipboard
// NFC-normalization during source handling. These MUST be byte-different
// at runtime; the test_inputs_differ_byte_wise case asserts this.
//
// Composed (NFC): U+0063 U+0061 U+0066 U+00E9  ("café" as 4 code points)
const COMPOSED = String.fromCodePoint(0x63, 0x61, 0x66, 0xe9);
// Decomposed (NFD): U+0063 U+0061 U+0066 U+0065 U+0301  ("cafe" + combining acute)
const DECOMPOSED = String.fromCodePoint(0x63, 0x61, 0x66, 0x65, 0x0301);

describe("NFC scope (ADR-004, SAN-225)", () => {
  it("inputs differ byte-wise pre-normalization", () => {
    // Sanity check: composed and decomposed forms must be byte-different
    // even though they look identical. If this fails, the test fixture
    // was NFC-collapsed during source handling — rebuild from code
    // points and re-run.
    expect(COMPOSED).not.toBe(DECOMPOSED);
    const composedBytes = Buffer.from(COMPOSED, "utf-8");
    const decomposedBytes = Buffer.from(DECOMPOSED, "utf-8");
    expect(composedBytes.equals(decomposedBytes)).toBe(false);
    // But they are canonically equivalent under NFC:
    expect(DECOMPOSED.normalize("NFC")).toBe(COMPOSED);
  });

  it("hashContent normalizes NFC", () => {
    // hashContent() applies NFC — composed and decomposed strings
    // MUST produce identical hashes at the hashing boundary (spec v1.4
    // Section 3.1, ADR-004).
    expect(hashContent(COMPOSED)).toBe(hashContent(DECOMPOSED));
  });

  it("hashObj preserves encoding (top-level value)", () => {
    // hashObj() does NOT recursively NFC-normalize strings per ADR-004.
    // If this ever fails, the ADR-004 decision has been silently
    // overridden — stop and consult ADR-004 and SAN-252 before
    // continuing. Reverting the underlying code change is the governance
    // response; do NOT alter this test to pass.
    expect(hashObj({ val: COMPOSED })).not.toBe(hashObj({ val: DECOMPOSED }));
  });

  it("hashObj preserves encoding in nested dict", () => {
    expect(hashObj({ outer: { inner: COMPOSED } })).not.toBe(
      hashObj({ outer: { inner: DECOMPOSED } }),
    );
  });

  it("hashObj preserves encoding in array", () => {
    expect(hashObj([COMPOSED])).not.toBe(hashObj([DECOMPOSED]));
  });

  it("hashObj preserves encoding in dict key", () => {
    expect(hashObj({ [COMPOSED]: 1 })).not.toBe(hashObj({ [DECOMPOSED]: 1 }));
  });
});
