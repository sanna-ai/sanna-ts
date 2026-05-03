import { describe, it, expect } from "vitest";
import { verifyReceipt } from "../src/verifier.js";

describe("SAN-394: conditional allOf schema rules now enforced", () => {
  const baseReceipt = {
    spec_version: "1.5",
    checks_version: "10",
    tool_name: "sanna",
    tool_version: "1.5.0",
    receipt_id: "12345678-1234-4234-a234-123456789abc",
    receipt_fingerprint: "a".repeat(16),
    full_fingerprint: "b".repeat(64),
    correlation_id: "test-001",
    timestamp: "2026-05-02T12:00:00Z",
    inputs: { query: "test" },
    outputs: { response: "" },
    context_hash: "c".repeat(64),
    output_hash: "d".repeat(64),
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "PASS",
    enforcement_surface: "gateway",
    invariants_scope: "none",
    agent_identity: { agent_session_id: "sess-001" },
  };

  it("B1: session_manifest with non-null enforcement FAILS", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "session_manifest",
      enforcement: { action: "allowed" },
      extensions: { "com.sanna.manifest": { version: "0.1", composition_basis: "static", surfaces: { mcp: { tools_delivered: [], tools_suppressed: [], suppression_reasons: {} } } } },
      constitution_ref: { policy_hash: "e".repeat(64) },
    };
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Schema validation failed"))).toBe(true);
  });

  it("B2: mixed enforcement_surface with 1 surface FAILS", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "session_manifest",
      enforcement: null,
      enforcement_surface: "mixed",
      extensions: { "com.sanna.manifest": { version: "0.1", composition_basis: "static", surfaces: { mcp: { tools_delivered: [], tools_suppressed: [], suppression_reasons: {} } } } },
      constitution_ref: { policy_hash: "e".repeat(64) },
    };
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Schema validation failed"))).toBe(true);
  });

  it("A3: com.sanna.manifest without session_manifest event_type FAILS", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "invocation_halted",
      extensions: { "com.sanna.manifest": { version: "0.1", composition_basis: "static", surfaces: { mcp: { tools_delivered: [], tools_suppressed: [], suppression_reasons: {} } } } },
    };
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Schema validation failed"))).toBe(true);
  });

  it("B3: com.sanna.anomaly without anomaly event_type FAILS", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "invocation_halted",
      extensions: { "com.sanna.anomaly": { attempted_tool: "x", suppression_basis: "session_manifest" } },
    };
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Schema validation failed"))).toBe(true);
  });

  it("B4: invocation_anomaly without com.sanna.anomaly extension FAILS", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "invocation_anomaly",
      enforcement: { action: "halted", halted: true, reason: "suppressed", failed_checks: [], enforcement_mode: "halt", timestamp: "2026-05-02T12:00:00Z" },
      invariants_scope: "authority_only",
      status: "FAIL",
      extensions: {},
      parent_receipts: ["f".repeat(64)],
    };
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Schema validation failed"))).toBe(true);
  });

  it("Valid session_manifest still PASSES (no false-FAIL from ajv)", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "session_manifest",
      enforcement: null,
      extensions: { "com.sanna.manifest": { version: "0.1", composition_basis: "static", surfaces: { mcp: { tools_delivered: [], tools_suppressed: [], suppression_reasons: {} } } } },
      constitution_ref: { policy_hash: "e".repeat(64) },
    };
    const result = verifyReceipt(receipt);
    const schemaErrors = result.errors.filter((e) => e.includes("Schema validation failed"));
    expect(schemaErrors).toEqual([]);
  });

  it("Valid invocation_anomaly still PASSES schema (no false-FAIL)", () => {
    const receipt = {
      ...baseReceipt,
      event_type: "invocation_anomaly",
      enforcement: { action: "halted", halted: true, reason: "suppressed", failed_checks: [], enforcement_mode: "halt", timestamp: "2026-05-02T12:00:00Z" },
      invariants_scope: "authority_only",
      status: "FAIL",
      extensions: { "com.sanna.anomaly": { attempted_tool: "x", suppression_basis: "session_manifest" } },
      parent_receipts: ["f".repeat(64)],
    };
    const result = verifyReceipt(receipt);
    const schemaErrors = result.errors.filter((e) => e.includes("Schema validation failed"));
    expect(schemaErrors).toEqual([]);
  });

  it("Existing cv=10 agent_identity check still produces byte-equal message", () => {
    const receipt = { ...baseReceipt, agent_identity: undefined };
    const result = verifyReceipt(receipt);
    expect(result.errors).toContain(
      "v1.5+ receipt (checks_version >= 10) is missing required field: agent_identity"
    );
  });
});
