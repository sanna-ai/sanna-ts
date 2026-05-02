/**
 * SAN-369: MODIFY authority_decisions[i] recording infrastructure (TypeScript).
 *
 * Tests the buildModifyAuthorityDecision helper. Mirrors the Python test surface
 * at sanna-repo tests/test_san369_modify_recording.py (merged c2c6a39).
 */
import { describe, it, expect } from "vitest";
import { buildModifyAuthorityDecision } from "../src/authority.js";

const VALID_TRANSFORMATIONS = [
  { type: "redact_pii", target_field: "query", rationale: "PII per AUTH-PII-01" },
];

describe("SAN-369: buildModifyAuthorityDecision", () => {
  it("produces record with expected shape and key order", () => {
    const record = buildModifyAuthorityDecision(
      "search-api",
      { query: "find user@example.com records" },
      { query: "find <REDACTED-EMAIL> records" },
      VALID_TRANSFORMATIONS,
      { reason: "PII redacted from query parameter" },
    );
    expect(record.decision).toBe("modify_with_constraints");
    expect(record.boundary_type).toBe("can_execute");
    expect(record.tool_input_original).toEqual({ query: "find user@example.com records" });
    expect(record.tool_input_transformed).toEqual({ query: "find <REDACTED-EMAIL> records" });
    expect(record.transformations_applied).toHaveLength(1);

    // Key order must match Python helper output for cross-SDK byte-equal parity
    expect(Object.keys(record)).toEqual([
      "action",
      "decision",
      "reason",
      "boundary_type",
      "timestamp",
      "tool_input_original",
      "tool_input_transformed",
      "transformations_applied",
    ]);
  });

  it("rejects empty transformations array", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", "orig", "trans", []),
    ).toThrow(/non-empty array/);
  });

  it("rejects transformation missing rationale", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", "orig", "trans", [
        { type: "redact", target_field: "f" } as never,
      ]),
    ).toThrow(/missing required keys/);
  });

  it("rejects transformation with extra key", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", "orig", "trans", [
        { type: "redact", target_field: "f", rationale: "r", extra: "x" } as never,
      ]),
    ).toThrow(/unexpected keys/);
  });

  it("rejects non-string non-object original", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", 123 as never, "trans", VALID_TRANSFORMATIONS),
    ).toThrow(/string or object/);
  });

  it("rejects null original", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", null as never, "trans", VALID_TRANSFORMATIONS),
    ).toThrow(/string or object/);
  });

  it("rejects array original", () => {
    expect(() =>
      buildModifyAuthorityDecision("x", [] as never, "trans", VALID_TRANSFORMATIONS),
    ).toThrow(/string or object/);
  });

  it("produces byte-identical records for identical inputs (deterministic construction)", () => {
    const common = {
      action: "api-search",
      original: { q: "x" },
      transformed: { q: "y" },
      transformations: [{ type: "t1", target_field: "q", rationale: "r1" }],
      options: { reason: "deterministic test", timestamp: "2026-05-02T00:00:00+00:00" },
    };
    const record1 = buildModifyAuthorityDecision(
      common.action, common.original, common.transformed, common.transformations, common.options,
    );
    const record2 = buildModifyAuthorityDecision(
      common.action, common.original, common.transformed, common.transformations, common.options,
    );
    expect(record1).toEqual(record2);
    expect(JSON.stringify(record1)).toBe(JSON.stringify(record2));
  });

  it("matches Python helper output shape for fixed inputs (cross-SDK parity)", () => {
    // Reference output from Python build_modify_authority_decision (sanna-repo c2c6a39)
    // for the same fixed inputs. Cross-SDK byte-equal via JSON serialization.
    const expected = {
      action: "api-search",
      decision: "modify_with_constraints",
      reason: "deterministic test",
      boundary_type: "can_execute",
      timestamp: "2026-05-02T00:00:00+00:00",
      tool_input_original: { q: "x" },
      tool_input_transformed: { q: "y" },
      transformations_applied: [{ type: "t1", target_field: "q", rationale: "r1" }],
    };
    const record = buildModifyAuthorityDecision(
      "api-search",
      { q: "x" },
      { q: "y" },
      [{ type: "t1", target_field: "q", rationale: "r1" }],
      { reason: "deterministic test", timestamp: "2026-05-02T00:00:00+00:00" },
    );
    expect(record).toEqual(expected);
    expect(JSON.stringify(record)).toBe(JSON.stringify(expected));
  });
});
