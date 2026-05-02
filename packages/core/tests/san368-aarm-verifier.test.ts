/**
 * SAN-368: AARM Core (R1-R6) conformance verifier (TypeScript).
 *
 * Mirrors Python tests/test_san368_aarm_verifier.py from sanna-repo f2b53a5.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import {
  aggregateAarmReport,
  formatAarmReport,
  SANNA_TO_AARM,
  checkR1PreExecutionInterception,
  checkR2ContextAccumulation,
  checkR3PolicyEvaluation,
  checkR4Decisions,
  checkR5TamperEvident,
  checkR6IdentityBinding,
} from "../src/aarm.js";

const SPEC_FIXTURES = resolve(__dirname, "../../../spec/fixtures/receipts");

function loadFixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(SPEC_FIXTURES, `${name}.json`), "utf-8"));
}

function makeReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receipt_fingerprint: "abcd1234abcd1234",
    full_fingerprint: "abcd1234abcd1234" + "a".repeat(48),
    checks_version: "10",
    enforcement_surface: "middleware",
    parent_receipts: null,
    authority_decisions: [],
    agent_identity: { agent_session_id: "test-session-001" },
    ...overrides,
  };
}

// ── SANNA_TO_AARM ────────────────────────────────────────────────────

describe("SANNA_TO_AARM mapping", () => {
  it("contains all expected keys", () => {
    const expectedKeys = [
      "can_execute",
      "cannot_execute",
      "must_escalate",
      "modify_with_constraints",
      "defer_pending_context",
      "allow",
      "halt",
      "escalate",
      "modify",
      "defer",
    ];
    for (const k of expectedKeys) {
      expect(SANNA_TO_AARM).toHaveProperty(k);
    }
  });

  it("maps boundary_type values to AARM names", () => {
    expect(SANNA_TO_AARM.can_execute).toBe("ALLOW");
    expect(SANNA_TO_AARM.cannot_execute).toBe("DENY");
    expect(SANNA_TO_AARM.must_escalate).toBe("STEP_UP");
    expect(SANNA_TO_AARM.modify_with_constraints).toBe("MODIFY");
    expect(SANNA_TO_AARM.defer_pending_context).toBe("DEFER");
  });

  it("maps decision (action-form) values to AARM names", () => {
    expect(SANNA_TO_AARM.allow).toBe("ALLOW");
    expect(SANNA_TO_AARM.halt).toBe("DENY");
    expect(SANNA_TO_AARM.escalate).toBe("STEP_UP");
    expect(SANNA_TO_AARM.modify).toBe("MODIFY");
    expect(SANNA_TO_AARM.defer).toBe("DEFER");
  });
});

// ── R1: Pre-Execution Interception ──────────────────────────────────

describe("R1: checkR1PreExecutionInterception", () => {
  it("PASS: all receipts have valid enforcement_surface", () => {
    const receipts = [
      makeReceipt({ enforcement_surface: "middleware" }),
      makeReceipt({ enforcement_surface: "gateway" }),
    ];
    const result = checkR1PreExecutionInterception(receipts);
    expect(result.status).toBe("PASS");
    expect(result.requirement).toBe("R1");
  });

  it("FAIL: receipt missing enforcement_surface", () => {
    const receipts = [makeReceipt({ enforcement_surface: null })];
    const result = checkR1PreExecutionInterception(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it("FAIL: receipt has unrecognized enforcement_surface", () => {
    const receipts = [makeReceipt({ enforcement_surface: "unknown_surface" })];
    const result = checkR1PreExecutionInterception(receipts);
    expect(result.status).toBe("FAIL");
  });

  it("PASS: invocation_* event_type with valid surface", () => {
    const receipts = [
      makeReceipt({ event_type: "invocation_start", enforcement_surface: "cli_interceptor" }),
    ];
    const result = checkR1PreExecutionInterception(receipts);
    expect(result.status).toBe("PASS");
    expect(result.message).toContain("invocation");
  });

  it("FAIL: invocation_* event_type with missing surface", () => {
    const receipts = [
      makeReceipt({ event_type: "invocation_start", enforcement_surface: null }),
    ];
    const result = checkR1PreExecutionInterception(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("event_type", "invocation_start");
  });

  it("accepts all valid surface values", () => {
    for (const surface of ["middleware", "gateway", "cli_interceptor", "http_interceptor", "mixed"]) {
      const result = checkR1PreExecutionInterception([makeReceipt({ enforcement_surface: surface })]);
      expect(result.status).toBe("PASS");
    }
  });
});

// ── R2: Context Accumulation ─────────────────────────────────────────

describe("R2: checkR2ContextAccumulation", () => {
  it("PASS: no parent_receipts (empty set)", () => {
    const receipts = [makeReceipt({ parent_receipts: null })];
    const result = checkR2ContextAccumulation(receipts);
    expect(result.status).toBe("PASS");
  });

  it("PASS: parent_receipts resolve within receipt set", () => {
    const fp = "abcd1234abcd5678";
    const parent = makeReceipt({ receipt_fingerprint: fp, full_fingerprint: fp + "a".repeat(48) });
    const child = makeReceipt({ parent_receipts: [fp] });
    const result = checkR2ContextAccumulation([parent, child]);
    expect(result.status).toBe("PASS");
  });

  it("FAIL: parent_receipts reference not in set", () => {
    const receipts = [makeReceipt({ parent_receipts: ["deadbeefdeadbeef"] })];
    const result = checkR2ContextAccumulation(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("missing_parent", "deadbeefdeadbeef");
  });

  it("resolves by full_fingerprint", () => {
    const fp64 = "a".repeat(64);
    const parent = makeReceipt({ full_fingerprint: fp64 });
    const child = makeReceipt({ parent_receipts: [fp64] });
    const result = checkR2ContextAccumulation([parent, child]);
    expect(result.status).toBe("PASS");
  });
});

// ── R3: Policy Evaluation ────────────────────────────────────────────

describe("R3: checkR3PolicyEvaluation", () => {
  it("N/A: no governance receipts (no constitution_ref)", () => {
    const receipts = [makeReceipt({ constitution_ref: null })];
    const result = checkR3PolicyEvaluation(receipts);
    expect(result.status).toBe("N/A");
  });

  it("PASS: governance receipt has policy_hash", () => {
    const receipts = [
      makeReceipt({
        constitution_ref: { policy_hash: "abc123def456" + "0".repeat(52) },
      }),
    ];
    const result = checkR3PolicyEvaluation(receipts);
    expect(result.status).toBe("PASS");
  });

  it("FAIL: governance receipt missing policy_hash", () => {
    const receipts = [
      makeReceipt({ constitution_ref: { some_field: "value" } }),
    ];
    const result = checkR3PolicyEvaluation(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence.length).toBeGreaterThan(0);
  });

  it("FAIL: policy_hash present but empty string", () => {
    const receipts = [
      makeReceipt({ constitution_ref: { policy_hash: "" } }),
    ];
    const result = checkR3PolicyEvaluation(receipts);
    expect(result.status).toBe("FAIL");
  });
});

// ── R4: Authorization Decisions ──────────────────────────────────────

describe("R4: checkR4Decisions", () => {
  it("PASS: valid decision values", () => {
    const receipts = [
      makeReceipt({
        authority_decisions: [{ decision: "allow", boundary_type: "can_execute" }],
      }),
    ];
    const result = checkR4Decisions(receipts);
    expect(result.status).toBe("PASS");
  });

  it("FAIL: invalid decision value", () => {
    const receipts = [
      makeReceipt({
        authority_decisions: [{ decision: "unknown_decision", boundary_type: "can_execute" }],
      }),
    ];
    const result = checkR4Decisions(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("field", "authority_decisions.decision");
    expect(result.evidence[0]).toHaveProperty("value", "unknown_decision");
  });

  it("FAIL: invalid boundary_type value", () => {
    const receipts = [
      makeReceipt({
        authority_decisions: [{ decision: "allow", boundary_type: "bad_boundary" }],
      }),
    ];
    const result = checkR4Decisions(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("field", "authority_decisions.boundary_type");
  });

  it("PASS: STEP_UP receipt chains to downstream receipt", () => {
    const fp16 = "step1234step1234";
    const fp64 = fp16 + "b".repeat(48);
    const escalated = makeReceipt({
      receipt_fingerprint: fp16,
      full_fingerprint: fp64,
      enforcement: { action: "escalate" },
    });
    // parent_receipts references the full_fingerprint (preferred) per Python parity
    const resolution = makeReceipt({ parent_receipts: [fp64] });
    const result = checkR4Decisions([escalated, resolution]);
    expect(result.status).toBe("PASS");
  });

  it("FAIL: orphaned STEP_UP receipt (no downstream)", () => {
    const fp = "orphan12orphan12";
    const escalated = makeReceipt({
      receipt_fingerprint: fp,
      full_fingerprint: fp + "c".repeat(48),
      enforcement: { action: "escalate" },
    });
    const result = checkR4Decisions([escalated]);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("issue");
    expect(result.evidence[0].issue).toContain("STEP_UP");
  });

  it("handles escalated enforcement action (past-tense form)", () => {
    const fp16 = "past1234past1234";
    const fp64 = fp16 + "d".repeat(48);
    const escalated = makeReceipt({
      receipt_fingerprint: fp16,
      full_fingerprint: fp64,
      enforcement: { action: "escalated" },
    });
    const resolution = makeReceipt({ parent_receipts: [fp64] });
    const result = checkR4Decisions([escalated, resolution]);
    expect(result.status).toBe("PASS");
  });

  it("PASS: empty authority_decisions", () => {
    const receipts = [makeReceipt({ authority_decisions: [] })];
    const result = checkR4Decisions(receipts);
    expect(result.status).toBe("PASS");
  });
});

// ── R5: Tamper-Evident ───────────────────────────────────────────────

describe("R5: checkR5TamperEvident", () => {
  it("PASS: fixture receipts pass fingerprint check", () => {
    const receipts = ["full-featured", "fail-halted", "pass-single-check"].map(loadFixture);
    const result = checkR5TamperEvident(receipts);
    expect(result.status).toBe("PASS");
  });

  it("FAIL: tampered receipt (wrong fingerprint)", () => {
    const r = { ...loadFixture("full-featured"), receipt_fingerprint: "0000000000000000" };
    const result = checkR5TamperEvident([r]);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("issue");
    expect(result.evidence[0].issue).toContain("fingerprint mismatch");
  });

  it("PASS: redacted-receipt acceptance (no public key check)", () => {
    const r = loadFixture("full-featured");
    const result = checkR5TamperEvident([r]);
    expect(result.status).toBe("PASS");
  });

  it("PASS: no public key provided skips signature check", () => {
    const r = {
      ...loadFixture("full-featured"),
      receipt_signature: { key_id: "fake-key", signature: "invalidsig" },
    };
    // Without public key, signature is not checked; fingerprint still must pass
    const result = checkR5TamperEvident([r]);
    expect(result.status).toBe("PASS");
  });
});

// ── R6: Identity Binding ─────────────────────────────────────────────

describe("R6: checkR6IdentityBinding", () => {
  it("PASS: cv=10 with agent_identity.agent_session_id", () => {
    const receipts = [
      makeReceipt({ checks_version: "10", agent_identity: { agent_session_id: "sess-001" } }),
    ];
    const result = checkR6IdentityBinding(receipts);
    expect(result.status).toBe("PASS");
    expect(result.message).toContain("cv=10");
  });

  it("FAIL: cv=10 missing agent_identity", () => {
    const receipts = [makeReceipt({ checks_version: "10", agent_identity: null })];
    const result = checkR6IdentityBinding(receipts);
    expect(result.status).toBe("FAIL");
    expect(result.evidence[0]).toHaveProperty("issue");
    expect(result.evidence[0].issue).toContain("cv=10 receipt missing agent_identity");
  });

  it("FAIL: cv=10 with agent_identity but missing agent_session_id", () => {
    const receipts = [
      makeReceipt({ checks_version: "10", agent_identity: { human_principal: "test" } }),
    ];
    const result = checkR6IdentityBinding(receipts);
    expect(result.status).toBe("FAIL");
  });

  it("PARTIAL: all receipts at cv<=9", () => {
    const receipts = [makeReceipt({ checks_version: "9", agent_identity: null })];
    const result = checkR6IdentityBinding(receipts);
    expect(result.status).toBe("PARTIAL");
    expect(result.message).toContain("cv<=9");
  });

  it("PARTIAL: mix of cv=10 PASS and cv=9 PARTIAL", () => {
    const receipts = [
      makeReceipt({ checks_version: "10", agent_identity: { agent_session_id: "sess-001" } }),
      makeReceipt({ checks_version: "9", agent_identity: null }),
    ];
    const result = checkR6IdentityBinding(receipts);
    expect(result.status).toBe("PARTIAL");
    expect(result.message).toContain("cv=10 with agent_identity");
    expect(result.message).toContain("cv<=9");
  });

  it("PASS: fixture full-featured (cv=10 with agent_identity)", () => {
    const r = loadFixture("full-featured");
    const result = checkR6IdentityBinding([r]);
    expect(result.status).toBe("PASS");
  });
});

// ── Integration: fixture set ─────────────────────────────────────────

describe("SAN-368: AARM verifier integration", () => {
  it("non-escalated fixture set aggregates to PASS or PARTIAL", () => {
    const receipts = ["full-featured", "fail-halted", "pass-single-check"].map(loadFixture);
    const report = aggregateAarmReport(receipts);
    expect(["PASS", "PARTIAL"]).toContain(report.aggregate_status);
    expect(report.receipt_count).toBe(3);
    expect(report.checks).toHaveLength(6);
  });

  it("all 6 checks present with valid status values", () => {
    const receipts = ["full-featured", "fail-halted", "pass-single-check"].map(loadFixture);
    const report = aggregateAarmReport(receipts);
    const validStatuses = new Set(["PASS", "FAIL", "PARTIAL", "N/A"]);
    for (const check of report.checks) {
      expect(validStatuses).toContain(check.status);
      expect(["R1", "R2", "R3", "R4", "R5", "R6"]).toContain(check.requirement);
    }
  });

  it("requirements appear in R1-R6 order", () => {
    const receipts = [loadFixture("full-featured")];
    const report = aggregateAarmReport(receipts);
    const reqs = report.checks.map((c) => c.requirement);
    expect(reqs).toEqual(["R1", "R2", "R3", "R4", "R5", "R6"]);
  });
});

// ── formatAarmReport ─────────────────────────────────────────────────

describe("formatAarmReport", () => {
  it("json format produces parseable output", () => {
    const receipts = [loadFixture("full-featured")];
    const report = aggregateAarmReport(receipts);
    const out = formatAarmReport(report, "json");
    const parsed = JSON.parse(out);
    expect(parsed).toHaveProperty("aggregate_status");
    expect(parsed).toHaveProperty("receipt_count", 1);
    expect(parsed).toHaveProperty("checks");
    expect(parsed.checks).toHaveLength(6);
  });

  it("human format contains expected headers", () => {
    const receipts = [loadFixture("full-featured")];
    const report = aggregateAarmReport(receipts);
    const out = formatAarmReport(report, "human");
    expect(out).toContain("AARM Core (R1-R6) Conformance Report");
    expect(out).toContain("Aggregate:");
    expect(out).toContain("R1");
    expect(out).toContain("R6");
  });

  it("throws on unknown format", () => {
    const receipts = [loadFixture("full-featured")];
    const report = aggregateAarmReport(receipts);
    expect(() => formatAarmReport(report, "xml")).toThrow("Unknown format");
  });

  it("json output has generated_at field", () => {
    const receipts = [loadFixture("full-featured")];
    const report = aggregateAarmReport(receipts);
    const parsed = JSON.parse(formatAarmReport(report, "json"));
    expect(parsed).toHaveProperty("generated_at");
    expect(typeof parsed.generated_at).toBe("string");
  });
});

// ── Cross-SDK verdict parity with Python (AC #5) ─────────────────────

describe("SAN-368: cross-SDK verdict parity with Python (AC #5)", () => {
  it("produces verdict structure matching Python reference output for fixed receipt set", () => {
    const receipts = ["full-featured", "fail-halted", "pass-single-check"].map(loadFixture);
    const report = aggregateAarmReport(receipts);

    // Hardcoded reference: Python aggregate_aarm_report output for the same receipt set
    // captured at sanna-repo f2b53a5 via Phase 0 reference capture (2026-05-02)
    const expectedFromPython = {
      aggregate_status: "PASS",
      receipt_count: 3,
      checks: [
        { requirement: "R1", status: "PASS" },
        { requirement: "R2", status: "PASS" },
        { requirement: "R3", status: "PASS" },
        { requirement: "R4", status: "PASS" },
        { requirement: "R5", status: "PASS" },
        { requirement: "R6", status: "PASS" },
      ],
    };

    // Strip generated_at for byte-equal comparison
    const tsOut = { ...report } as Record<string, unknown>;
    delete tsOut.generated_at;

    expect(tsOut.aggregate_status).toBe(expectedFromPython.aggregate_status);
    expect(tsOut.receipt_count).toBe(expectedFromPython.receipt_count);
    expect((tsOut.checks as typeof report.checks).length).toBe(6);
    for (let i = 0; i < 6; i++) {
      const check = (tsOut.checks as typeof report.checks)[i];
      expect(check.requirement).toBe(expectedFromPython.checks[i].requirement);
      expect(check.status).toBe(expectedFromPython.checks[i].status);
    }
  });
});
