import { describe, it, expect, afterEach } from "vitest";
import {
  registerInvariantEvaluator,
  getEvaluator,
  listEvaluators,
  clearEvaluators,
} from "../src/evaluator-registry.js";
import { runInvariantCheck, runAllInvariantChecks } from "../src/invariants.js";
import type { Constitution, CheckResult, InvariantDefinition } from "../src/types.js";

afterEach(() => {
  clearEvaluators();
});

function makeConstitution(invariants: Constitution["invariants"]): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test boundary", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants,
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
  };
}

describe("evaluator registry", () => {
  it("should register and retrieve an evaluator", () => {
    const fn = () => ({
      check_id: "INV_CUSTOM",
      passed: true,
      severity: "info",
      evidence: null,
    }) as CheckResult;

    registerInvariantEvaluator("INV_CUSTOM", fn);
    expect(getEvaluator("INV_CUSTOM")).toBe(fn);
  });

  it("should reject duplicate registration", () => {
    const fn = () => ({
      check_id: "INV_DUP",
      passed: true,
      severity: "info",
      evidence: null,
    }) as CheckResult;

    registerInvariantEvaluator("INV_DUP", fn);
    expect(() => registerInvariantEvaluator("INV_DUP", fn)).toThrow(
      "Evaluator already registered for invariant 'INV_DUP'",
    );
  });

  it("should list registered evaluator IDs", () => {
    const fn = () => ({ check_id: "x", passed: true, severity: "info", evidence: null }) as CheckResult;
    registerInvariantEvaluator("INV_A", fn);
    registerInvariantEvaluator("INV_B", fn);
    registerInvariantEvaluator("INV_C", fn);

    const ids = listEvaluators();
    expect(ids).toHaveLength(3);
    expect(ids).toContain("INV_A");
    expect(ids).toContain("INV_B");
    expect(ids).toContain("INV_C");
  });

  it("should clear all evaluators", () => {
    const fn = () => ({ check_id: "x", passed: true, severity: "info", evidence: null }) as CheckResult;
    registerInvariantEvaluator("INV_CLEAR", fn);
    clearEvaluators();
    expect(getEvaluator("INV_CLEAR")).toBeUndefined();
    expect(listEvaluators()).toHaveLength(0);
  });

  it("should return undefined for unregistered invariant", () => {
    expect(getEvaluator("INV_NONEXISTENT")).toBeUndefined();
  });
});

describe("invariant check integration", () => {
  it("should invoke custom evaluator during invariant check", () => {
    registerInvariantEvaluator("INV_CUSTOM_TEST", (_ctx, output) => ({
      check_id: "INV_CUSTOM_TEST",
      name: "Custom Test",
      passed: !output.includes("forbidden"),
      severity: output.includes("forbidden") ? "critical" : "info",
      evidence: output.includes("forbidden") ? "Found forbidden content" : null,
    }));

    const constitution = makeConstitution([
      { id: "INV_CUSTOM_TEST", rule: "No forbidden content", enforcement: "halt", check: null },
    ]);

    const results = runAllInvariantChecks(constitution, "clean output");
    expect(results).toHaveLength(1);
    expect(results[0].passed).toBe(true);
    expect(results[0].check_impl).toBe("custom_evaluator");
    expect(results[0].replayable).toBe(false);

    const failResults = runAllInvariantChecks(constitution, "has forbidden word");
    expect(failResults[0].passed).toBe(false);
    expect(failResults[0].evidence).toContain("forbidden");
  });

  it("should handle evaluator that throws", () => {
    registerInvariantEvaluator("INV_THROWS", () => {
      throw new Error("evaluator crashed");
    });

    const inv: InvariantDefinition = {
      id: "INV_THROWS",
      rule: "Will throw",
      enforcement: "halt",
    };

    const result = runInvariantCheck(inv, "any output");
    expect(result.passed).toBe(true);
    expect(result.status).toBe("ERRORED");
    expect(result.evidence).toContain("evaluator crashed");
    expect(result.check_impl).toBe("custom_evaluator");
  });

  it("should prefer built-in type over registry", () => {
    let customCalled = false;
    registerInvariantEvaluator("INV_PII_OVERRIDE", () => {
      customCalled = true;
      return {
        check_id: "INV_PII_OVERRIDE",
        passed: true,
        severity: "info",
        evidence: null,
      };
    });

    // Rule text "No PII in output" auto-detects as pii_detection
    const constitution = makeConstitution([
      { id: "INV_PII_OVERRIDE", rule: "No PII in output", enforcement: "halt", check: null },
    ]);

    const results = runAllInvariantChecks(constitution, "Contact john@example.com");
    expect(customCalled).toBe(false);
    // Built-in pii_detection should run and detect the email
    expect(results[0].passed).toBe(false);
    expect(results[0].evidence).toContain("email");
  });

  it("should fall through to registry when type is unrecognized", () => {
    let receivedConfig: Record<string, unknown> = {};
    registerInvariantEvaluator("INV_DOMAIN", (_ctx, output, _constitution, config) => {
      receivedConfig = config;
      return {
        check_id: "INV_DOMAIN",
        name: "Domain Check",
        passed: output.length > 5,
        severity: output.length > 5 ? "info" : "critical",
        evidence: output.length <= 5 ? "Output too short for domain rule" : null,
      };
    });

    const inv: InvariantDefinition = {
      id: "INV_DOMAIN",
      rule: "Domain-specific validation",
      enforcement: "halt",
      type: "custom_domain_check",
    };

    const result = runInvariantCheck(inv, "this is long enough");
    expect(result.passed).toBe(true);
    expect(result.check_impl).toBe("custom_evaluator");
    expect(receivedConfig.type).toBe("custom_domain_check");

    const failResult = runInvariantCheck(inv, "short");
    expect(failResult.passed).toBe(false);
    expect(failResult.evidence).toContain("too short");
  });
});
