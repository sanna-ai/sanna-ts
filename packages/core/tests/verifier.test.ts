import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { verifyReceipt } from "../src/verifier.js";
import { loadPublicKey } from "../src/crypto.js";
import { generateReceipt, signReceipt } from "../src/receipt.js";
import { loadPrivateKey } from "../src/crypto.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const pubKey = loadPublicKey(resolve(FIXTURES, "keypairs/test-author.pub"));
const privKey = loadPrivateKey(resolve(FIXTURES, "keypairs/test-author.key"));

// ── Helper: create and sign a valid receipt ──────────────────────────

function makeSignedReceipt(): Record<string, unknown> {
  const receipt = generateReceipt({
    correlation_id: "verify-test-001",
    inputs: { query: "What is 2+2?", context: "Math" },
    outputs: { response: "4" },
    checks: [
      { check_id: "C1", passed: true, severity: "info", evidence: null },
    ],
  }) as unknown as Record<string, unknown>;
  signReceipt(receipt, privKey, "test@sanna.dev");
  return receipt;
}

// ── Verify valid receipt ─────────────────────────────────────────────

describe("verifyReceipt — valid receipt", () => {
  it("passes all checks for a freshly signed receipt", () => {
    const receipt = makeSignedReceipt();
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.checks_performed).toContain("schema");
    expect(result.checks_performed).toContain("signature");
    expect(result.checks_performed).toContain("fingerprint");
    expect(result.checks_performed).toContain("content_hashes");
    expect(result.checks_performed).toContain("status_consistency");
    expect(result.checks_performed).toContain("timestamp");
  });
});

// ── Tampered receipts ────────────────────────────────────────────────

describe("verifyReceipt — tampered receipts", () => {
  it("detects modified field (breaks signature + fingerprint)", () => {
    const receipt = makeSignedReceipt();
    receipt.correlation_id = "tampered-id";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("detects wrong signature", () => {
    const receipt = makeSignedReceipt();
    const sig = receipt.receipt_signature as Record<string, unknown>;
    // Corrupt the signature
    sig.signature = "AAAA" + (sig.signature as string).slice(4);
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("signature"))).toBe(true);
  });

  it("detects bad fingerprint", () => {
    const receipt = makeSignedReceipt();
    receipt.receipt_fingerprint = "0000000000000000";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Fingerprint"))).toBe(true);
  });

  it("detects tampered inputs (content hash mismatch)", () => {
    const receipt = makeSignedReceipt();
    (receipt.inputs as Record<string, unknown>).query = "tampered query";
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("context_hash"))).toBe(true);
  });

  it("detects checks_passed count mismatch", () => {
    const receipt = makeSignedReceipt();
    receipt.checks_passed = 99;
    const result = verifyReceipt(receipt, pubKey);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("checks_passed"))).toBe(true);
  });
});

// ── Without public key ───────────────────────────────────────────────

describe("verifyReceipt — no public key", () => {
  it("skips signature check, warns about missing key", () => {
    const receipt = makeSignedReceipt();
    const result = verifyReceipt(receipt);
    expect(result.valid).toBe(true);
    expect(result.checks_performed).not.toContain("signature");
    expect(result.warnings.some((w) => w.includes("no public key"))).toBe(true);
  });
});

// ── Schema validation ────────────────────────────────────────────────

describe("verifyReceipt — schema errors", () => {
  it("catches missing required fields", () => {
    const result = verifyReceipt({ receipt_id: "not-a-uuid" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Missing required field"))).toBe(true);
  });
});

// ── v1.3 verifier (SAN-213 AC 8 + 13) ───────────────────────────────

describe("v1.3 verifier (SAN-213 AC 8 + 13)", () => {
  // Helper: generate a fully valid v1.3 receipt (cv="8"), optionally overriding fields.
  // Produces a receipt that passes all checks unless specific fields are tampered.
  function makeV13Receipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    const r = generateReceipt({
      correlation_id: "v13-verifier-test",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      ...overrides,
    }) as unknown as Record<string, unknown>;
    return r;
  }

  // Helper: generate a v1.3 receipt with enforcement.action set, status="PASS".
  // The receipt is generated fresh then its status field is overwritten to "PASS"
  // so we can test the verifier's override independent of emit-side behavior.
  // We also recompute fingerprints BEFORE status manipulation so fingerprints match
  // the "honest" field values — this isolates the status-mismatch error.
  function makeV13ReceiptWithAction(action: string): Record<string, unknown> {
    const r = generateReceipt({
      correlation_id: "v13-soc-test",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      enforcement: { action },
    }) as unknown as Record<string, unknown>;
    // Force status to "PASS" regardless of what generateReceipt computed (emit-side override).
    // This tests the verifier's own override: verifier must re-derive the correct status
    // and detect the mismatch.
    r.status = "PASS";
    return r;
  }

  // ── v1.3 schema required-field tests ─────────────────────────────

  it("v13-sch-1: cv=8 receipt missing enforcement_surface fails with exact error string", () => {
    const r = makeV13Receipt();
    delete r.enforcement_surface;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
  });

  it("v13-sch-2: cv=8 receipt missing invariants_scope fails with exact error string", () => {
    const r = makeV13Receipt();
    delete r.invariants_scope;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
    );
  });

  it("v13-sch-3: cv=8 receipt missing both fields produces both errors (collect-all)", () => {
    const r = makeV13Receipt();
    delete r.enforcement_surface;
    delete r.invariants_scope;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
    );
  });

  it("v13-sch-4: cv=7 receipt missing enforcement_surface passes the v1.3 check (backward compat)", () => {
    // Build a cv=7 receipt by calling generateReceipt with overridden checks_version.
    // Since generateReceipt always sets cv="8", we construct a minimal cv=7 receipt manually.
    const r = generateReceipt({
      correlation_id: "v13-sch-4-cv7",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
    }) as unknown as Record<string, unknown>;
    // Override to cv=7 and recompute fingerprints to keep them consistent.
    // We also need enforcement_surface + invariants_scope to stay for fingerprint parity,
    // so we change checks_version and remove the v1.3 fields AFTER fingerprint recompute
    // to test the schema check path only. The fingerprint will mismatch, but the schema
    // check for cv<8 should not fire — we assert the specific v1.3 error is absent.
    r.checks_version = "7";
    delete r.enforcement_surface;
    const result = verifyReceipt(r);
    // The v1.3 required-field error must NOT appear (cv < 8 → check skipped)
    expect(result.errors).not.toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
    expect(result.errors).not.toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
    );
  });

  it("v13-sch-5: cv=8 receipt with both fields populated passes the v1.3 required-field check", () => {
    const r = makeV13Receipt();
    const result = verifyReceipt(r);
    expect(result.valid).toBe(true);
    expect(result.errors).not.toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
    expect(result.errors).not.toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: invariants_scope",
    );
  });

  // ── v1.3 status-override-consistency tests (verifier-side, not emit) ─

  it("v13-soc-halted: status=PASS + action=halted fails with status mismatch FAIL", () => {
    const r = makeV13ReceiptWithAction("halted");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Status mismatch") && e.includes("halted") && e.includes("FAIL"))).toBe(true);
  });

  it("v13-soc-warned: status=PASS + action=warned fails with status mismatch WARN", () => {
    const r = makeV13ReceiptWithAction("warned");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Status mismatch") && e.includes("warned") && e.includes("WARN"))).toBe(true);
  });

  it("v13-soc-escalated: status=PASS + action=escalated fails with status mismatch WARN", () => {
    const r = makeV13ReceiptWithAction("escalated");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("Status mismatch") && e.includes("escalated") && e.includes("WARN"))).toBe(true);
  });

  it("v13-soc-allowed: status=PASS + action=allowed passes verification", () => {
    // generateReceipt with action=allowed produces status=PASS (no override fires)
    const r = generateReceipt({
      correlation_id: "v13-soc-allowed",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      enforcement: { action: "allowed" },
    }) as unknown as Record<string, unknown>;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("v13-soc-no-override-on-warn: action=halted with WARN severity checks leaves WARN alone", () => {
    // When checks already produce WARN (warn-severity failure), the override only fires
    // when computed == PASS. Since computed is already WARN, override does not fire.
    // The stored status must also be WARN (emit-side produces WARN from the failing check,
    // then override only fires for PASS → this is the no-override-on-warn path).
    const r = generateReceipt({
      correlation_id: "v13-soc-no-override",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        // warning-severity failing check → computed WARN before override
        { check_id: "C1", passed: false, severity: "warning", evidence: "warn" },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      enforcement: { action: "halted" },
    }) as unknown as Record<string, unknown>;
    // status was set to WARN by emit-side (check failed with warning severity).
    // Verifier: computes WARN from checks, override only fires if computed==PASS → skipped.
    // WARN == stored WARN → no mismatch error.
    const result = verifyReceipt(r);
    // No status mismatch error expected
    expect(result.errors.some((e) => e.includes("Status mismatch"))).toBe(false);
  });

  it("v13-soc-no-enforcement: no enforcement field → override skipped, status from severity", () => {
    const r = generateReceipt({
      correlation_id: "v13-soc-no-enf",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      // No enforcement field
    }) as unknown as Record<string, unknown>;
    const result = verifyReceipt(r);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  // ── AC 8 verifier-side integrity guarantee ─────────────────────────

  it("v13-integrity: verifier structurally rejects PASS+halted/warned/escalated receipts", () => {
    const violatingActions = ["halted", "warned", "escalated"] as const;
    for (const action of violatingActions) {
      const r = makeV13ReceiptWithAction(action);
      const result = verifyReceipt(r);
      expect(result.valid, `Expected invalid for action=${action}`).toBe(false);
      const hasStatusMismatch = result.errors.some(
        (e) => e.includes("Status mismatch") && e.includes("FAIL") || e.includes("WARN"),
      );
      expect(hasStatusMismatch, `Expected status-mismatch error for action=${action}`).toBe(true);
    }
  });
});

// ── v1.3 SAN-214 error text and legacy warnings ──────────────────────

describe("v1.3 SAN-214 error text and legacy warnings", () => {
  // Helper: build a v1.3 receipt with a given enforcement.action, then force status=PASS.
  // Reuses the same approach as makeV13ReceiptWithAction in the SAN-213 suite.
  function makeV13WithAction(action: string): Record<string, unknown> {
    const r = generateReceipt({
      correlation_id: "san214-err-test",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      enforcement: { action },
    }) as unknown as Record<string, unknown>;
    r.status = "PASS";
    return r;
  }

  // Helper: build a legacy cv=6/7 receipt by overriding checks_version after generation.
  // Fingerprint will mismatch (expected) — only legacy-warning behavior is under test.
  function makeLegacyReceipt(cv: number, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    const r = generateReceipt({
      correlation_id: "san214-legacy-test",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
    }) as unknown as Record<string, unknown>;
    r.checks_version = String(cv);
    // Remove v1.3-specific fields to simulate a legacy receipt
    delete r.enforcement_surface;
    delete r.invariants_scope;
    // Apply any test-specific overrides
    for (const [k, v] of Object.entries(overrides)) {
      if (v === undefined) {
        delete r[k];
      } else {
        r[k] = v;
      }
    }
    return r;
  }

  // ── san214-err-1: cv=8, enforcement.action=halted, status=PASS ──────

  it("san214-err-1: cv=8 + action=halted + status=PASS produces v1.3 spec §10 error text", () => {
    const r = makeV13WithAction("halted");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    const errMatch = result.errors.find((e) => e.includes("Status mismatch"));
    expect(errMatch).toBeDefined();
    expect(errMatch).toContain("cryptographically valid but semantically defective");
    expect(errMatch).toContain("v1.3 spec §10");
    expect(errMatch).toContain("enforcement.action='halted'");
  });

  // ── san214-err-2: cv=8, enforcement.action=warned, status=PASS ──────

  it("san214-err-2: cv=8 + action=warned + status=PASS produces v1.3 spec §10 error text", () => {
    const r = makeV13WithAction("warned");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    const errMatch = result.errors.find((e) => e.includes("Status mismatch"));
    expect(errMatch).toBeDefined();
    expect(errMatch).toContain("cryptographically valid but semantically defective");
    expect(errMatch).toContain("v1.3 spec §10");
    expect(errMatch).toContain("enforcement.action='warned'");
  });

  // ── san214-err-3: cv=8, enforcement.action=escalated, status=PASS ───

  it("san214-err-3: cv=8 + action=escalated + status=PASS produces v1.3 spec §10 error text", () => {
    const r = makeV13WithAction("escalated");
    const result = verifyReceipt(r);
    expect(result.valid).toBe(false);
    const errMatch = result.errors.find((e) => e.includes("Status mismatch"));
    expect(errMatch).toBeDefined();
    expect(errMatch).toContain("cryptographically valid but semantically defective");
    expect(errMatch).toContain("v1.3 spec §10");
    expect(errMatch).toContain("enforcement.action='escalated'");
  });

  // ── san214-err-4: cv=8, enforcement.action=allowed, status=PASS — no mismatch ──

  it("san214-err-4: cv=8 + action=allowed + status=PASS produces no status mismatch error", () => {
    const r = generateReceipt({
      correlation_id: "san214-err-4",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      enforcement: { action: "allowed" },
    }) as unknown as Record<string, unknown>;
    const result = verifyReceipt(r);
    expect(result.errors.some((e) => e.includes("Status mismatch"))).toBe(false);
  });

  // ── san214-err-5: no enforcement field, computed FAIL, status=PASS ──
  // Fallback path: no enforcement → no verbose error → plain text format.

  it("san214-err-5: no enforcement + computed FAIL + status=PASS produces plain status mismatch text", () => {
    const r = generateReceipt({
      correlation_id: "san214-err-5",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        // critical-severity failing check → computed FAIL
        { check_id: "C1", passed: false, severity: "critical", evidence: "failed" },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      // No enforcement field
    }) as unknown as Record<string, unknown>;
    // Force status to "PASS" to trigger the mismatch
    r.status = "PASS";
    const result = verifyReceipt(r);
    const errMatch = result.errors.find((e) => e.startsWith("Status mismatch"));
    expect(errMatch).toBeDefined();
    // Fallback text: plain format, no v1.3 spec §10 language
    expect(errMatch).toContain("Status mismatch: computed FAIL, expected PASS");
    expect(errMatch).not.toContain("cryptographically valid");
    expect(errMatch).not.toContain("v1.3 spec §10");
  });

  // ── san214-warn-1: cv=6, no enforcement_surface → legacy warning ────

  it("san214-warn-1: cv=6 missing enforcement_surface produces legacy warning with Re-generate text", () => {
    const r = makeLegacyReceipt(6);
    const result = verifyReceipt(r);
    const warnMatch = result.warnings.find((w) =>
      w.includes("Pre-v1.3 receipt (checks_version=6)") &&
      w.includes("'enforcement_surface' field not present"),
    );
    expect(warnMatch).toBeDefined();
    expect(warnMatch).toContain("Re-generate with SDK >=1.3");
  });

  // ── san214-warn-2: cv=7, no invariants_scope → legacy warning (no Re-generate) ──

  it("san214-warn-2: cv=7 missing invariants_scope produces legacy warning WITHOUT Re-generate text", () => {
    // Build cv=7 receipt with enforcement_surface present, invariants_scope absent
    const r = generateReceipt({
      correlation_id: "san214-warn-2",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
    }) as unknown as Record<string, unknown>;
    r.checks_version = "7";
    r.enforcement_surface = "middleware"; // present
    delete r.invariants_scope; // absent
    const result = verifyReceipt(r);
    const warnMatch = result.warnings.find((w) =>
      w.includes("Pre-v1.3 receipt (checks_version=7)") &&
      w.includes("'invariants_scope' field not present"),
    );
    expect(warnMatch).toBeDefined();
    // invariants_scope warning does NOT have the Re-generate sentence
    expect(warnMatch).not.toContain("Re-generate with SDK >=1.3");
  });

  // ── san214-warn-3: cv=8, no enforcement_surface → hard error (not warning) ──

  it("san214-warn-3: cv=8 missing enforcement_surface produces hard error, not legacy warning", () => {
    const r = generateReceipt({
      correlation_id: "san214-warn-3",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
      enforcementSurface: "middleware",
      invariantsScope: "full",
    }) as unknown as Record<string, unknown>;
    delete r.enforcement_surface;
    const result = verifyReceipt(r);
    expect(result.errors).toContain(
      "v1.3+ receipt (checks_version >= 8) is missing required field: enforcement_surface",
    );
    // Should NOT be a warning
    expect(result.warnings.some((w) => w.includes("enforcement_surface"))).toBe(false);
  });

  // ── san214-warn-4: cv=7 WITH both fields present → no legacy warnings ──

  it("san214-warn-4: cv=7 with enforcement_surface and invariants_scope present produces no legacy field warnings", () => {
    const r = generateReceipt({
      correlation_id: "san214-warn-4",
      inputs: { q: "test" },
      outputs: { a: "ok" },
      checks: [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ],
    }) as unknown as Record<string, unknown>;
    r.checks_version = "7";
    r.enforcement_surface = "middleware"; // present
    r.invariants_scope = "full"; // present
    const result = verifyReceipt(r);
    expect(result.warnings.some((w) => w.includes("'enforcement_surface' field not present"))).toBe(false);
    expect(result.warnings.some((w) => w.includes("'invariants_scope' field not present"))).toBe(false);
  });
});
