import { describe, it, expect } from "vitest";
import {
  computeInputHash,
  computeReasoningHash,
  buildReceiptTriad,
} from "../src/receipt-v2.js";
import type { AuthorityDecision, CheckResult } from "@sanna-ai/core";

describe("computeInputHash", () => {
  it("should produce a deterministic hash", () => {
    const h1 = computeInputHash("search", { query: "test" });
    const h2 = computeInputHash("search", { query: "test" });
    expect(h1).toBe(h2);
  });

  it("should differ for different tool names", () => {
    const h1 = computeInputHash("search", { query: "test" });
    const h2 = computeInputHash("delete", { query: "test" });
    expect(h1).not.toBe(h2);
  });

  it("should differ for different arguments", () => {
    const h1 = computeInputHash("search", { query: "alpha" });
    const h2 = computeInputHash("search", { query: "beta" });
    expect(h1).not.toBe(h2);
  });
});

describe("computeReasoningHash", () => {
  const decision: AuthorityDecision = {
    decision: "allow",
    reason: "Allowed by policy",
    boundary_type: "can_execute",
  };
  const checks: CheckResult[] = [
    {
      check_id: "C1",
      passed: true,
      severity: "medium",
      evidence: null,
    },
  ];

  it("should produce a deterministic hash", () => {
    const h1 = computeReasoningHash(decision, checks);
    const h2 = computeReasoningHash(decision, checks);
    expect(h1).toBe(h2);
  });

  it("should differ with different decisions", () => {
    const deny: AuthorityDecision = {
      decision: "halt",
      reason: "Denied",
      boundary_type: "cannot_execute",
    };
    const h1 = computeReasoningHash(decision, checks);
    const h2 = computeReasoningHash(deny, checks);
    expect(h1).not.toBe(h2);
  });

  it("should differ with justification", () => {
    const h1 = computeReasoningHash(decision, checks);
    const h2 = computeReasoningHash(decision, checks, "I have a good reason");
    expect(h1).not.toBe(h2);
  });
});

describe("buildReceiptTriad", () => {
  it("should combine two hashes and derive action_hash + context_limitation", () => {
    // SAN-848: action_hash is always derived (== input_hash) at the gateway
    // boundary; there is no independent action_hash input anymore.
    const triad = buildReceiptTriad("aaa", "bbb");
    expect(triad.input_hash).toBe("aaa");
    expect(triad.reasoning_hash).toBe("bbb");
    expect(triad.action_hash).toBe("aaa");
    expect(triad.context_limitation).toBe("gateway_boundary");
  });

  it("should produce a full triad from computed hashes", () => {
    const inputHash = computeInputHash("search", { q: "test" });
    const reasoningHash = computeReasoningHash(
      { decision: "allow", reason: "ok", boundary_type: "can_execute" },
      [],
    );
    const triad = buildReceiptTriad(inputHash, reasoningHash);

    expect(triad.input_hash).toBeTruthy();
    expect(triad.reasoning_hash).toBeTruthy();
    expect(triad.action_hash).toBeTruthy();
    expect(triad.action_hash).toBe(triad.input_hash);
    expect(triad.context_limitation).toBe("gateway_boundary");
    // All should be valid hex hashes
    expect(triad.input_hash).toMatch(/^[a-f0-9]+$/);
  });
});
