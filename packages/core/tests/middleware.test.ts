import { describe, it, expect } from "vitest";
import {
  sannaObserve,
  withSannaGovernance,
  SannaHaltError,
  buildTraceData,
} from "../src/middleware.js";
import type { Constitution, SannaResult } from "../src/types.js";

function makeConstitution(overrides: Partial<Constitution> = {}): Constitution {
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
    invariants: [
      { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

// Simple test function that echoes input
function echoAgent(input: { query: string; context?: string }): string {
  return `Response to: ${input.query}. Context mentions: ${input.context ?? "none"}`;
}

// Function that returns PII
function piiAgent(_input: { query: string }): string {
  return "Contact john@example.com for details.";
}

describe("sannaObserve", () => {
  it("should wrap a function and return SannaResult", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "What is the policy?", context: "The policy states rules" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
    expect(result.receipt.receipt_id).toBeTruthy();
    expect(result.receipt.status).toBeTruthy();
    expect(result.halted).toBe(false);
  });

  it("should generate a receipt with check results", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "Test query", context: "Test context" });
    expect(result.receipt.checks.length).toBeGreaterThan(0);
    expect(result.receipt.checks_passed).toBeGreaterThanOrEqual(0);
  });

  it("should include constitution_ref in receipt", () => {
    const constitution = makeConstitution();
    const governed = sannaObserve(echoAgent, { constitution });

    const result = governed({ query: "test" });
    expect(result.receipt.constitution_ref).toBeDefined();
    expect(result.receipt.constitution_ref!.document_id).toContain("test-agent");
  });

  it("should work without a constitution", () => {
    const governed = sannaObserve(echoAgent, {});
    const result = governed({ query: "test" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
    // Without constitution, C2 and C5 skip, all should pass
    const failedChecks = result.receipt.checks.filter((c) => !c.passed);
    expect(failedChecks).toHaveLength(0);
  });

  it("should resolve query and context from object argument", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "What is the refund policy?", context: "Refund policy information" });
    expect(result.receipt.inputs).toBeDefined();
    // The inputs should have query and context
    const inputs = result.receipt.inputs as Record<string, unknown>;
    expect(inputs.query).toBeTruthy();
    expect(inputs.context).toBeTruthy();
  });
});

describe("enforcement modes", () => {
  it("should halt in enforced mode on critical PII failure", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      ],
    });

    const governed = sannaObserve(piiAgent, {
      constitution,
      enforcementMode: "enforced",
    });

    expect(() => governed({ query: "test" })).toThrow(SannaHaltError);

    try {
      governed({ query: "test" });
    } catch (e) {
      const err = e as SannaHaltError;
      expect(err.receipt).toBeDefined();
      expect(err.failedChecks.length).toBeGreaterThan(0);
      expect(err.name).toBe("SannaHaltError");
    }
  });

  it("should NOT halt in advisory mode on check failure", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      ],
    });

    const governed = sannaObserve(piiAgent, {
      constitution,
      enforcementMode: "advisory",
    });

    // Should not throw
    const result = governed({ query: "test" });
    expect(result.output).toContain("john@example.com");
    expect(result.receipt).toBeDefined();
    // Receipt should note the failure
    const piiCheck = result.receipt.checks.find((c) => c.check_id === "INV_PII");
    expect(piiCheck?.passed).toBe(false);
  });

  it("should skip checks in permissive mode", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      ],
    });

    const governed = sannaObserve(piiAgent, {
      constitution,
      enforcementMode: "permissive",
    });

    const result = governed({ query: "test" });
    expect(result.output).toContain("john@example.com");
    expect(result.receipt.checks).toHaveLength(0);
    expect(result.halted).toBe(false);
  });

  it("should default to advisory mode", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      ],
    });

    const governed = sannaObserve(piiAgent, { constitution });

    // Should not throw in default (advisory) mode
    const result = governed({ query: "test" });
    expect(result.halted).toBe(false);
  });
});

describe("authority evaluation", () => {
  it("should halt on cannot_execute in enforced mode", () => {
    const constitution = makeConstitution({
      authority_boundaries: {
        cannot_execute: ["delete_database"],
        must_escalate: [],
        can_execute: [],
        default_escalation: "log",
      },
    });

    function deleteDb(): string { return "deleted"; }

    const governed = sannaObserve(deleteDb, {
      constitution,
      enforcementMode: "enforced",
      toolName: "delete_database",
    });

    expect(() => governed()).toThrow(SannaHaltError);
  });

  it("should not halt on cannot_execute in advisory mode", () => {
    const constitution = makeConstitution({
      authority_boundaries: {
        cannot_execute: ["delete_database"],
        must_escalate: [],
        can_execute: [],
        default_escalation: "log",
      },
    });

    function deleteDb(): string { return "deleted"; }

    const governed = sannaObserve(deleteDb, {
      constitution,
      enforcementMode: "advisory",
      toolName: "delete_database",
    });

    // Should not throw in advisory mode
    const result = governed();
    expect(result.output).toBe("deleted");
  });

  it("should pass with allowed tool", () => {
    const constitution = makeConstitution({
      invariants: [],
      authority_boundaries: {
        cannot_execute: ["delete_database"],
        must_escalate: [],
        can_execute: ["read_data"],
        default_escalation: "log",
      },
    });

    function readData(): string { return "data"; }

    const governed = sannaObserve(readData, {
      constitution,
      enforcementMode: "enforced",
      toolName: "read_data",
    });

    const result = governed();
    expect(result.output).toBe("data");
    expect(result.halted).toBe(false);
  });
});

describe("withSannaGovernance", () => {
  it("should return a wrapper function", () => {
    const govern = withSannaGovernance({
      constitution: makeConstitution(),
    });

    expect(typeof govern).toBe("function");

    const governed = govern(echoAgent);
    const result = governed({ query: "test", context: "context" });
    expect(result.output).toContain("Response to:");
    expect(result.receipt).toBeDefined();
  });

  it("should apply governance to multiple functions", () => {
    const govern = withSannaGovernance({
      constitution: makeConstitution(),
    });

    const fn1 = govern((x: string) => `fn1: ${x}`);
    const fn2 = govern((x: string) => `fn2: ${x}`);

    expect(fn1("hello").output).toBe("fn1: hello");
    expect(fn2("world").output).toBe("fn2: world");
    expect(fn1("hello").receipt).toBeDefined();
    expect(fn2("world").receipt).toBeDefined();
  });
});

describe("buildTraceData", () => {
  it("should build trace data with all fields", () => {
    const constitution = makeConstitution();
    const trace = buildTraceData(
      "What is the policy?",
      "The policy states rules",
      "The policy is about rules.",
      constitution,
    );

    expect(trace.correlationId).toMatch(/^sanna-/);
    expect(trace.query).toBe("What is the policy?");
    expect(trace.context).toBe("The policy states rules");
    expect(trace.output).toBe("The policy is about rules.");
    expect(trace.constitution).toBe(constitution);
  });

  it("should generate unique correlation IDs", () => {
    const trace1 = buildTraceData("q", "c", "o");
    const trace2 = buildTraceData("q", "c", "o");
    expect(trace1.correlationId).not.toBe(trace2.correlationId);
  });

  it("should work without constitution", () => {
    const trace = buildTraceData("query", "context", "output");
    expect(trace.constitution).toBeUndefined();
    expect(trace.checkResults).toBeUndefined();
  });
});

describe("SannaHaltError", () => {
  it("should be an instance of Error", () => {
    const receipt = { receipt_id: "test" } as any;
    const err = new SannaHaltError("test halt", receipt, []);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(SannaHaltError);
    expect(err.name).toBe("SannaHaltError");
    expect(err.message).toBe("test halt");
  });

  it("should carry receipt and failed checks", () => {
    const receipt = { receipt_id: "test" } as any;
    const checks = [{ check_id: "C1", passed: false, severity: "critical", evidence: null }] as any;
    const err = new SannaHaltError("halt", receipt, checks);
    expect(err.receipt).toBe(receipt);
    expect(err.failedChecks).toBe(checks);
  });
});

describe("input resolution", () => {
  it("should resolve query and context from named keys", () => {
    function agent(input: { query: string; context: string }): string {
      return `${input.query} + ${input.context}`;
    }

    const governed = sannaObserve(agent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "my query", context: "my context" });
    expect(result.output).toBe("my query + my context");
  });

  it("should handle alternative key names", () => {
    function agent(input: { prompt: string; documents: string }): string {
      return `${input.prompt} / ${input.documents}`;
    }

    const governed = sannaObserve(agent, {
      constitution: makeConstitution(),
    });

    const result = governed({ prompt: "the prompt", documents: "the docs" });
    expect(result.output).toContain("the prompt");
  });

  it("should use explicit contextParam and queryParam", () => {
    function agent(input: { q: string; ctx: string }): string {
      return `${input.q} - ${input.ctx}`;
    }

    const governed = sannaObserve(agent, {
      constitution: makeConstitution(),
      queryParam: "q",
      contextParam: "ctx",
    });

    const result = governed({ q: "custom query", ctx: "custom context" });
    expect(result.output).toBe("custom query - custom context");
    const inputs = result.receipt.inputs as Record<string, unknown>;
    expect(inputs.query).toBe("custom query");
    expect(inputs.context).toBe("custom context");
  });
});

describe("receipt structure", () => {
  it("should have valid receipt fields", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test", context: "context" });
    const receipt = result.receipt;

    expect(receipt.spec_version).toBeTruthy();
    expect(receipt.receipt_id).toBeTruthy();
    expect(receipt.correlation_id).toMatch(/^sanna-/);
    expect(receipt.timestamp).toBeTruthy();
    expect(receipt.context_hash).toBeTruthy();
    expect(receipt.output_hash).toBeTruthy();
    expect(typeof receipt.checks_passed).toBe("number");
    expect(typeof receipt.checks_failed).toBe("number");
    expect(["PASS", "WARN", "FAIL", "PARTIAL"]).toContain(receipt.status);
  });

  it("should compute fingerprints", () => {
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test" });
    expect(result.receipt.receipt_fingerprint).toBeTruthy();
    expect(result.receipt.receipt_fingerprint).toHaveLength(16);
    expect(result.receipt.full_fingerprint).toHaveLength(64);
  });
});

describe("SAN-863: invariants_scope derivation via sannaObserve", () => {
  it("constitution invariant that cannot be evaluated (UNKNOWN_TYPE) -> limited, with coverage extension", () => {
    // makeConstitution()'s default invariant has rule "No fabrication" and
    // check: null -- detectInvariantType finds no match, so it resolves to
    // UNKNOWN_TYPE (no built-in runner, no registered custom evaluator).
    const governed = sannaObserve(echoAgent, {
      constitution: makeConstitution(),
    });

    const result = governed({ query: "test", context: "context" });
    const receipt = result.receipt as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("limited");
    const ext = receipt.extensions as Record<string, unknown> | undefined;
    const cov = ext?.["com.sanna.coverage"] as Record<string, unknown> | undefined;
    expect(cov).toBeDefined();
    expect(cov?.invariants_declared).toBe(1);
    expect(cov?.invariants_executed).toBe(0);
    expect(cov?.skipped).toEqual([{ id: "INV_NO_FABRICATION", reason: "UNKNOWN_TYPE" }]);
  });

  it("constitution invariant that evaluates cleanly (pii_detection) -> full, no coverage extension", () => {
    const constitution = makeConstitution({
      invariants: [
        { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      ],
    });
    const governed = sannaObserve(echoAgent, { constitution });

    const result = governed({ query: "test", context: "context" });
    const receipt = result.receipt as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("no constitution -> zero declared invariants -> full, no coverage extension", () => {
    const governed = sannaObserve(echoAgent, {});
    const result = governed({ query: "test" });
    const receipt = result.receipt as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });

  it("constitution with zero invariants -> full, no coverage extension (matches Python)", () => {
    const constitution = makeConstitution({ invariants: [] });
    const governed = sannaObserve(echoAgent, { constitution });
    const result = governed({ query: "test" });
    const receipt = result.receipt as unknown as Record<string, unknown>;

    expect(receipt.invariants_scope).toBe("full");
    expect(receipt.extensions).toBeUndefined();
  });
});
