/**
 * v1.5 integrity tests (SAN-370 Prompt C)
 *
 * Validates cv=10 emission, verifier required-field enforcement, wire-format
 * parity with Python post-SAN-385, and SDK constant values.
 */

import { describe, it, expect } from "vitest";
import {
  generateReceipt,
  computeFingerprintInput,
  SPEC_VERSION,
  CHECKS_VERSION,
  TOOL_VERSION,
} from "../src/receipt.js";
import { verifyReceipt } from "../src/verifier.js";

// ── SDK constants ────────────────────────────────────────────────────

describe("SDK constants (v1.5 SHIPPED)", () => {
  it("SPEC_VERSION is 1.5", () => {
    expect(SPEC_VERSION).toBe("1.5");
  });

  it("CHECKS_VERSION is 10", () => {
    expect(CHECKS_VERSION).toBe("10");
  });

  it("TOOL_VERSION is 1.5.2", () => {
    expect(TOOL_VERSION).toBe("1.5.2");
  });
});

// ── cv=10 round-trip ─────────────────────────────────────────────────

describe("cv=10 round-trip (agent_identity present)", () => {
  const agentId = { agent_session_id: "test-session-v15-001" };

  const receipt = generateReceipt({
    correlation_id: "v15-cv10-roundtrip",
    inputs: { query: "test" },
    outputs: { response: "ok" },
    checks: [],
    enforcementSurface: "gateway",
    invariantsScope: "full",
    agent_identity: agentId,
  });

  it("emits checks_version 10", () => {
    expect(receipt.checks_version).toBe("10");
  });

  it("emits spec_version 1.5", () => {
    expect(receipt.spec_version).toBe("1.5");
  });

  it("receipt has agent_identity with agent_session_id", () => {
    expect(receipt.agent_identity).toBeDefined();
    expect((receipt.agent_identity as Record<string, unknown>).agent_session_id).toBe("test-session-v15-001");
  });

  it("full_fingerprint is 64 hex chars", () => {
    expect(receipt.full_fingerprint).toHaveLength(64);
    expect(receipt.full_fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("21-field fingerprint formula", () => {
    const fpInput = computeFingerprintInput(receipt as unknown as Record<string, unknown>);
    const parts = fpInput.split("|");
    expect(parts.length).toBe(21);
  });

  it("verifier accepts cv=10 receipt (no public key check)", () => {
    const result = verifyReceipt(receipt as unknown as Record<string, unknown>);
    const agentIdentityErrors = result.errors.filter((e) =>
      e.includes("agent_identity"),
    );
    expect(agentIdentityErrors).toEqual([]);
  });
});

// ── cv=9 legacy round-trip ───────────────────────────────────────────

describe("cv=9 legacy round-trip (no agent_identity, library middleware)", () => {
  const receipt = generateReceipt({
    correlation_id: "v15-cv9-legacy",
    inputs: { query: "middleware-test" },
    outputs: { response: "middleware-ok" },
    checks: [],
    enforcementSurface: "middleware",
    invariantsScope: "full",
    // No agent_identity -- cv=9 legacy path
  });

  it("emits checks_version 9 (legacy)", () => {
    expect(receipt.checks_version).toBe("9");
  });

  it("emits spec_version 1.4 (legacy)", () => {
    expect(receipt.spec_version).toBe("1.4");
  });

  it("receipt has NO agent_identity field", () => {
    expect(receipt.agent_identity).toBeUndefined();
  });

  it("20-field fingerprint formula", () => {
    const fpInput = computeFingerprintInput(receipt as unknown as Record<string, unknown>);
    const parts = fpInput.split("|");
    expect(parts.length).toBe(20);
  });
});

// ── Wire format: cv=9 must NOT have agent_identity key ───────────────

describe("wire format parity with Python post-SAN-385", () => {
  it("JSON.stringify of cv=9 receipt has no agent_identity key", () => {
    const r = generateReceipt({
      correlation_id: "wire-format-test",
      inputs: { query: "x" },
      outputs: { response: "y" },
      checks: [],
      enforcementSurface: "middleware",
      invariantsScope: "full",
    });
    const wire = JSON.stringify(r);
    expect(wire).not.toContain("agent_identity");
  });

  it("JSON.stringify of cv=10 receipt has agent_identity key", () => {
    const r = generateReceipt({
      correlation_id: "wire-format-cv10",
      inputs: { query: "x" },
      outputs: { response: "y" },
      checks: [],
      enforcementSurface: "gateway",
      invariantsScope: "full",
      agent_identity: { agent_session_id: "wire-test-session" },
    });
    const wire = JSON.stringify(r);
    expect(wire).toContain("agent_identity");
    expect(wire).toContain("wire-test-session");
  });
});

// ── Verifier rejection paths ─────────────────────────────────────────

describe("verifier rejects malformed cv=10 receipts", () => {
  it("rejects cv=10 receipt missing agent_identity entirely", () => {
    const r = generateReceipt({
      correlation_id: "verifier-reject-no-ai",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "gateway",
      invariantsScope: "full",
      agent_identity: { agent_session_id: "placeholder" },
    }) as Record<string, unknown>;

    // Manually remove agent_identity to simulate a malformed receipt
    delete r.agent_identity;
    r.checks_version = "10";

    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("agent_identity"))).toBe(true);
  });

  it("rejects cv=10 receipt where agent_identity has no agent_session_id", () => {
    const r = generateReceipt({
      correlation_id: "verifier-reject-no-sid",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "gateway",
      invariantsScope: "full",
      agent_identity: { agent_session_id: "placeholder" },
    }) as Record<string, unknown>;

    // Replace agent_identity with one missing agent_session_id
    r.agent_identity = { role: "test" };
    r.checks_version = "10";

    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("agent_session_id"))).toBe(true);
  });
});

// ── generateReceipt throws when agent_identity missing agent_session_id

describe("generateReceipt throws for invalid agent_identity", () => {
  it("throws when agent_identity has no agent_session_id", () => {
    expect(() => {
      generateReceipt({
        correlation_id: "throw-test",
        inputs: {},
        outputs: {},
        checks: [],
        agent_identity: { role: "test" }, // missing agent_session_id
      });
    }).toThrow("agent_identity must include agent_session_id");
  });

  it("throws when agent_identity.agent_session_id is not a string", () => {
    expect(() => {
      generateReceipt({
        correlation_id: "throw-test-2",
        inputs: {},
        outputs: {},
        checks: [],
        agent_identity: { agent_session_id: 42 } as unknown as Record<string, unknown>,
      });
    }).toThrow("agent_identity must include agent_session_id");
  });
});
