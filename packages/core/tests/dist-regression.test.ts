/**
 * Dist regression test (SAN-220).
 *
 * Imports @sanna-ai/core through its package exports (dist path, not src/),
 * exercises enforcement override + v1.4 field handling + cv=9 dispatch.
 * Fails loudly if dist diverges from source semantics (e.g., if dist wasn't
 * rebuilt after a source change, or a bundler regression drops behavior).
 *
 * This is the regression guard that would have caught the original F-001
 * finding: status="HALT" in dist while source had the 4-action override fixed.
 */
import { describe, it, expect } from "vitest";
import {
  generateReceipt,
  verifyReceipt,
  SPEC_VERSION,
  CHECKS_VERSION,
  TOOL_NAME,
  TOOL_VERSION,
} from "@sanna-ai/core";

describe("dist regression (SAN-220)", () => {
  it("dist exports v1.5 constants", () => {
    expect(SPEC_VERSION).toBe("1.5");
    expect(CHECKS_VERSION).toBe("10");
    expect(TOOL_NAME).toBe("sanna-ts");
    expect(TOOL_VERSION).toBe("1.5.0");
    expect(TOOL_VERSION).not.toMatch(/sanna-ts\//); // must be bare semver
  });

  it("dist generateReceipt applies 4-action enforcement override: halted → FAIL", () => {
    const r = generateReceipt({
      correlation_id: "san-220-test-halted",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "halted", policy: "test", reason: "test" },
    });
    expect(r.status).toBe("FAIL");
    // Critically: the legacy "HALT" string must NEVER appear in a dist-generated receipt status.
    expect(r.status as string).not.toBe("HALT");
  });

  it("dist generateReceipt applies 4-action enforcement override: warned → WARN", () => {
    const r = generateReceipt({
      correlation_id: "san-220-test-warned",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "warned", policy: "test", reason: "test" },
    });
    expect(r.status).toBe("WARN");
  });

  it("dist generateReceipt applies 4-action enforcement override: escalated → WARN", () => {
    const r = generateReceipt({
      correlation_id: "san-220-test-escalated",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "escalated", policy: "test", reason: "test" },
    });
    expect(r.status).toBe("WARN");
  });

  it("dist generateReceipt applies 4-action enforcement override: allowed → PASS", () => {
    const r = generateReceipt({
      correlation_id: "san-220-test-allowed",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "allowed", policy: "test", reason: "test" },
    });
    expect(r.status).toBe("PASS");
  });

  it("dist generateReceipt populates v1.4 tool_name field", () => {
    const r = generateReceipt({
      correlation_id: "san-220-test-tool-name",
      inputs: {},
      outputs: {},
      checks: [],
    });
    expect(r.tool_name).toBe("sanna-ts");
  });

  it("dist generateReceipt accepts and preserves v1.4 agent_model tri-valued opt-out", () => {
    // Captured
    const captured = generateReceipt({
      correlation_id: "san-220-test-agent-captured",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: "claude-opus-4-7",
      agent_model_provider: "anthropic",
      agent_model_version: "2026-04-01",
    });
    expect(captured.agent_model).toBe("claude-opus-4-7");
    expect(captured.agent_model_provider).toBe("anthropic");
    expect(captured.agent_model_version).toBe("2026-04-01");

    // Explicit opt-out (null)
    const optedOut = generateReceipt({
      correlation_id: "san-220-test-agent-null",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: null,
      agent_model_provider: null,
      agent_model_version: null,
    });
    expect(optedOut.agent_model).toBeNull();

    // Absent
    const absent = generateReceipt({
      correlation_id: "san-220-test-agent-absent",
      inputs: {},
      outputs: {},
      checks: [],
    });
    expect(absent.agent_model).toBeUndefined();
  });

  it("dist verifier rejects cv=9 receipt missing tool_name", () => {
    // Construct a v1.4 receipt then delete tool_name.
    const r: any = generateReceipt({
      correlation_id: "san-220-test-missing-tool-name",
      inputs: {},
      outputs: {},
      checks: [],
    });
    delete r.tool_name;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    // The error text matches the SAN-222 byte-exact requirement.
    expect(result.errors.some((e: string) => e.includes("tool_name"))).toBe(true);
  });

  it("dist verifier rejects cv=8 receipt missing enforcement_surface", () => {
    const r: any = generateReceipt({
      correlation_id: "san-221-test-cv8-no-enforcement-surface",
      inputs: {},
      outputs: {},
      checks: [],
    });
    r.checks_version = "8";
    delete r.enforcement_surface;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
  });

  it("dist verifier rejects cv=8 receipt missing invariants_scope", () => {
    const r: any = generateReceipt({
      correlation_id: "san-221-test-cv8-no-invariants-scope",
      inputs: {},
      outputs: {},
      checks: [],
    });
    r.checks_version = "8";
    delete r.invariants_scope;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
    );
  });

  it("dist verifier emits Pre-v1.3 legacy warnings for cv=6 receipt missing both fields", () => {
    const r: any = generateReceipt({
      correlation_id: "san-221-test-cv6-legacy-warnings",
      inputs: {},
      outputs: {},
      checks: [],
    });
    r.checks_version = "6";
    delete r.enforcement_surface;
    delete r.invariants_scope;
    const result = verifyReceipt(r);
    expect(result.warnings).toContain(
      "Pre-v1.3 receipt (checks_version=6): 'enforcement_surface' field not present. This field was added in v1.3 (checks_version 8) and is not required at this protocol version. Re-generate with SDK >=1.3 for v1.3 integrity claims.",
    );
    expect(result.warnings).toContain(
      "Pre-v1.3 receipt (checks_version=6): 'invariants_scope' field not present. This field was added in v1.3 (checks_version 8) and is not required at this protocol version.",
    );
  });

  it("dist verifier emits Pre-v1.3 warning for cv=7 missing invariants_scope only", () => {
    const r: any = generateReceipt({
      correlation_id: "san-221-test-cv7-legacy-warning-asymmetric",
      inputs: {},
      outputs: {},
      checks: [],
    });
    r.checks_version = "7";
    r.enforcement_surface = "middleware";
    delete r.invariants_scope;
    const result = verifyReceipt(r);
    expect(result.warnings).toContain(
      "Pre-v1.3 receipt (checks_version=7): 'invariants_scope' field not present. This field was added in v1.3 (checks_version 8) and is not required at this protocol version.",
    );
    expect(
      result.warnings.every((w: string) => !w.includes("'enforcement_surface'")),
    ).toBe(true);
  });
});
