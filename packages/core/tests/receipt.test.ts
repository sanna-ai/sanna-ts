import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import {
  generateReceipt,
  signReceipt,
  computeFingerprints,
  computeFingerprintInput,
  SPEC_VERSION,
  CHECKS_VERSION,
  TOOL_VERSION,
  TOOL_NAME,
} from "../src/receipt.js";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.js";
import { verify } from "../src/crypto.js";
import { canonicalize, hashContent } from "../src/hashing.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const golden = JSON.parse(readFileSync(resolve(FIXTURES, "golden-hashes.json"), "utf-8"));
const privKey = loadPrivateKey(resolve(FIXTURES, "keypairs/test-author.key"));
const pubKey = loadPublicKey(resolve(FIXTURES, "keypairs/test-author.pub"));

// ── generateReceipt ──────────────────────────────────────────────────

describe("generateReceipt", () => {
  const receipt = generateReceipt({
    correlation_id: "test-001",
    inputs: { query: "What is 2+2?", context: "Math" },
    outputs: { response: "4" },
    checks: [
      {
        check_id: "C1",
        name: "Context Contradiction",
        passed: true,
        severity: "info",
        evidence: null,
      },
    ],
  });

  it("has correct spec_version", () => {
    expect(receipt.spec_version).toBe(SPEC_VERSION);
  });

  it("has correct checks_version", () => {
    expect(receipt.checks_version).toBe(CHECKS_VERSION);
  });

  it("generates UUID v4 receipt_id", () => {
    const uuid4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
    expect(receipt.receipt_id).toMatch(uuid4);
  });

  it("computes context_hash and output_hash", () => {
    expect(receipt.context_hash).toHaveLength(64);
    expect(receipt.output_hash).toHaveLength(64);
  });

  it("computes fingerprints", () => {
    expect(receipt.receipt_fingerprint).toHaveLength(16);
    expect(receipt.full_fingerprint).toHaveLength(64);
  });

  it("counts checks correctly", () => {
    expect(receipt.checks_passed).toBe(1);
    expect(receipt.checks_failed).toBe(0);
    expect(receipt.status).toBe("PASS");
  });

  it("auto-detects FAIL status", () => {
    const failReceipt = generateReceipt({
      correlation_id: "test-fail",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [
        { check_id: "C1", passed: false, severity: "critical", evidence: "bad" },
      ],
    });
    expect(failReceipt.status).toBe("FAIL");
  });

  it("includes optional fields when provided", () => {
    const r = generateReceipt({
      correlation_id: "test-full",
      inputs: { q: "x" },
      outputs: { r: "y" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      enforcement: { action: "allowed", reason: "ok", failed_checks: [], enforcement_mode: "log", timestamp: "2026-01-01T00:00:00Z" },
      extensions: { "com.test": { val: 1 } },
    });
    expect(r.enforcement).toBeDefined();
    expect(r.extensions).toBeDefined();
  });
});

// ── Fingerprint determinism ──────────────────────────────────────────

describe("fingerprint determinism", () => {
  it("same inputs produce same fingerprint", () => {
    const base = {
      correlation_id: "det-001",
      context_hash: "aaaa".repeat(16),
      output_hash: "bbbb".repeat(16),
      checks_version: "6",
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    };
    const fp1 = computeFingerprints(base);
    const fp2 = computeFingerprints(base);
    expect(fp1.receipt_fingerprint).toBe(fp2.receipt_fingerprint);
    expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
  });

  it("different correlation_id changes fingerprint", () => {
    const base = {
      correlation_id: "det-001",
      context_hash: "aaaa".repeat(16),
      output_hash: "bbbb".repeat(16),
      checks_version: "6",
      checks: [],
    };
    const fp1 = computeFingerprints(base);
    const fp2 = computeFingerprints({ ...base, correlation_id: "det-002" });
    expect(fp1.receipt_fingerprint).not.toBe(fp2.receipt_fingerprint);
  });
});

// ── signReceipt ──────────────────────────────────────────────────────

describe("signReceipt", () => {
  it("adds valid receipt_signature block", () => {
    const receipt = generateReceipt({
      correlation_id: "sign-test",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    }) as unknown as Record<string, unknown>;

    signReceipt(receipt, privKey, "test@sanna.dev");

    const sig = receipt.receipt_signature as Record<string, unknown>;
    expect(sig).toBeDefined();
    expect(sig.signature).toBeTruthy();
    expect(sig.key_id).toBe(golden.test_key_id);
    expect(sig.scheme).toBe("receipt_sig_v1");
    expect(sig.signed_by).toBe("test@sanna.dev");
  });

  it("signature verifies with public key", () => {
    const receipt = generateReceipt({
      correlation_id: "sign-verify",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
    }) as unknown as Record<string, unknown>;

    signReceipt(receipt, privKey, "test@sanna.dev");

    // Reconstruct signable form
    const signable = structuredClone(receipt);
    (signable.receipt_signature as Record<string, unknown>).signature = "";
    const canonical = canonicalize(signable);
    const data = Buffer.from(canonical, "utf-8");
    const sig = (receipt.receipt_signature as Record<string, unknown>).signature as string;

    expect(verify(data, sig, pubKey)).toBe(true);
  });
});

// ── Bug #1: checks_hash undefined vs null ────────────────────────────

describe("checks_hash optional fields default to null", () => {
  it("undefined enforcement fields serialize as null, not stripped", () => {
    // A check with triggered_by present but other enforcement fields undefined
    const receipt: Record<string, unknown> = {
      correlation_id: "null-test",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "6",
      checks: [
        {
          check_id: "C1",
          passed: true,
          severity: "info",
          evidence: null,
          triggered_by: "boundary",
          // enforcement_level, check_impl, replayable intentionally omitted
        },
      ],
    };
    const fp1 = computeFingerprints(receipt);

    // Same check but with explicit nulls — should produce identical fingerprint
    const receiptWithNulls: Record<string, unknown> = {
      ...receipt,
      checks: [
        {
          check_id: "C1",
          passed: true,
          severity: "info",
          evidence: null,
          triggered_by: "boundary",
          enforcement_level: null,
          check_impl: null,
          replayable: null,
        },
      ],
    };
    const fp2 = computeFingerprints(receiptWithNulls);
    expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
  });
});

// ── Bug #2: checks_version backward compatibility ────────────────────

describe("checks_version < 6 produces 12-field fingerprint", () => {
  it("checks_version 5 produces 12-field pipe-delimited string", () => {
    const receipt: Record<string, unknown> = {
      correlation_id: "v5-test",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "5",
      checks: [],
      parent_receipts: ["some-parent"],
      workflow_id: "some-workflow",
    };
    const input = computeFingerprintInput(receipt);
    const fields = input.split("|");
    expect(fields).toHaveLength(12);
  });

  it("checks_version 6 produces 14-field pipe-delimited string", () => {
    const receipt: Record<string, unknown> = {
      correlation_id: "v6-test",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "6",
      checks: [],
    };
    const input = computeFingerprintInput(receipt);
    const fields = input.split("|");
    expect(fields).toHaveLength(14);
  });

  it("checks_version 4 produces 12-field string", () => {
    const receipt: Record<string, unknown> = {
      correlation_id: "v4-test",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "4",
      checks: [],
    };
    const input = computeFingerprintInput(receipt);
    expect(input.split("|")).toHaveLength(12);
  });
});

// ── Bug #4: correlation_id pipe validation ───────────────────────────

describe("correlation_id pipe validation", () => {
  it("throws on pipe character in computeFingerprintInput", () => {
    const receipt: Record<string, unknown> = {
      correlation_id: "bad|id",
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      checks_version: "6",
      checks: [],
    };
    expect(() => computeFingerprintInput(receipt)).toThrow(
      "correlation_id must not contain '|' character",
    );
  });

  it("throws on pipe character in generateReceipt", () => {
    expect(() =>
      generateReceipt({
        correlation_id: "has|pipe",
        inputs: { q: "x" },
        outputs: { r: "y" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      }),
    ).toThrow("correlation_id must not contain '|' character");
  });

  it("accepts correlation_id without pipe", () => {
    expect(() =>
      generateReceipt({
        correlation_id: "valid-id-no-pipes",
        inputs: { q: "x" },
        outputs: { r: "y" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      }),
    ).not.toThrow();
  });
});

describe("v1.3 16-field fingerprint (SAN-213)", () => {
  const EXPECTED_MIDDLEWARE_HASH = "fd7f274babdbe7e35bccaf7ab6d2389fbcaaf6798b357f3b2b83ccc992b40860";
  const EXPECTED_FULL_HASH = "a18b869b2e81c0c529552a3c4fa5c92ed08b98a4e146aed778d71d27517f83ac";
  const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  it("applies defaults when params omitted", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
    });
    expect(receipt.enforcement_surface).toBe("middleware");
    expect(receipt.invariants_scope).toBe("full");
  });

  it("explicit values flow through", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "gateway",
      invariantsScope: "authority_only",
    });
    expect(receipt.enforcement_surface).toBe("gateway");
    expect(receipt.invariants_scope).toBe("authority_only");
  });

  it("16-field structure when cv=8", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
    });
    // Force cv=8 on the receipt for testing computeFingerprintInput directly
    const modified = { ...receipt, checks_version: "8" };
    const fpInput = computeFingerprintInput(modified);
    const parts = fpInput.split("|");
    expect(parts.length).toBe(16);
  });

  it("backward compat structure for older cv values", async () => {
    const base = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
    });
    const receipt7 = { ...base, checks_version: "7" };
    const receipt5 = { ...base, checks_version: "5" };
    expect(computeFingerprintInput(receipt7).split("|").length).toBe(14);
    expect(computeFingerprintInput(receipt5).split("|").length).toBe(12);
  });

  it("field 15 byte-parity with Python (CRITICAL)", () => {
    // sha256("middleware") confirmed via: printf '%s' 'middleware' | shasum -a 256
    // Must match Python hash_text("middleware") from receipt.py
    const hash = hashContent("middleware", 64);
    expect(hash).toBe(EXPECTED_MIDDLEWARE_HASH);
  });

  it("field 16 byte-parity with Python (CRITICAL)", () => {
    // sha256("full") confirmed via: printf '%s' 'full' | shasum -a 256
    // Must match Python hash_text("full") from receipt.py
    const hash = hashContent("full", 64);
    expect(hash).toBe(EXPECTED_FULL_HASH);
  });

  it("both fields ACTUALLY participate in the fingerprint (no-op guard)", async () => {
    const r1 = await generateReceipt({ correlation_id: "test", inputs: {}, outputs: {}, checks: [], enforcementSurface: "middleware" });
    const r2 = await generateReceipt({ correlation_id: "test", inputs: {}, outputs: {}, checks: [], enforcementSurface: "gateway" });
    expect(r1.full_fingerprint).not.toBe(r2.full_fingerprint);

    const r3 = await generateReceipt({ correlation_id: "test", inputs: {}, outputs: {}, checks: [], invariantsScope: "full" });
    const r4 = await generateReceipt({ correlation_id: "test", inputs: {}, outputs: {}, checks: [], invariantsScope: "authority_only" });
    expect(r3.full_fingerprint).not.toBe(r4.full_fingerprint);
  });

  it("position correctness: fields 15-16 at correct positions", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcementSurface: "middleware",
      invariantsScope: "full",
    });
    const parts = computeFingerprintInput(receipt).split("|");
    expect(parts[14]).toBe(EXPECTED_MIDDLEWARE_HASH); // 0-indexed field 15
    expect(parts[15]).toBe(EXPECTED_FULL_HASH);       // 0-indexed field 16
  });

  it("missing fields fall back to empty string (defensive verifier path)", async () => {
    // Hand-built receipt missing enforcement_surface and invariants_scope
    // computeFingerprintInput must NOT throw; fields 15-16 use hash("")
    const base = await generateReceipt({ correlation_id: "test", inputs: {}, outputs: {}, checks: [] });
    const incomplete = { ...base, checks_version: "8" } as any;
    delete incomplete.enforcement_surface;
    delete incomplete.invariants_scope;
    // Must not throw
    let fpInput: string;
    expect(() => { fpInput = computeFingerprintInput(incomplete); }).not.toThrow();
    const parts = computeFingerprintInput(incomplete).split("|");
    // Fields 15 and 16 should be hash("") = EMPTY_HASH
    // Note: EMPTY_HASH here is sha256("") which is the hash of empty string
    expect(parts[14]).toBe(EMPTY_HASH);
    expect(parts[15]).toBe(EMPTY_HASH);
  });
});

describe("v1.3 enforcement override (SAN-213 AC 8)", () => {
  it("override-1: halted + computed PASS → FAIL", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "halted", reason: "blocked" },
    });
    expect(receipt.status).toBe("FAIL");
  });

  it("override-2: warned + computed PASS → WARN", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "warned", reason: "warning" },
    });
    expect(receipt.status).toBe("WARN");
  });

  it("override-3: escalated + computed PASS → WARN", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "escalated", reason: "escalated" },
    });
    expect(receipt.status).toBe("WARN");
  });

  it("override-4: allowed + computed PASS → PASS (no change)", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
      enforcement: { action: "allowed", reason: "permitted" },
    });
    expect(receipt.status).toBe("PASS");
  });

  it("override-5: halted + checks-computed WARN → WARN (override does not fire)", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [{ check_id: "c1", passed: false, severity: "warning", evidence: null }],
      enforcement: { action: "halted", reason: "blocked" },
    });
    // computed status is WARN from the failing warning-severity check;
    // override only fires when computed status is PASS — so status stays WARN
    expect(receipt.status).toBe("WARN");
  });

  it("override-6: halted + checks-computed FAIL → FAIL (no change)", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [{ check_id: "c1", passed: false, severity: "critical", evidence: null }],
      enforcement: { action: "halted", reason: "blocked" },
    });
    expect(receipt.status).toBe("FAIL");
  });

  it("override-7: no enforcement param → status purely from checks", async () => {
    const receipt = await generateReceipt({
      correlation_id: "test",
      inputs: {},
      outputs: {},
      checks: [],
    });
    expect(receipt.status).toBe("PASS");
  });

  it("override-8: AC 8 integrity — action=halted can never produce status=PASS", async () => {
    // Structural guarantee: enforcement.action="halted" + status="PASS" is impossible
    const inputs = [
      { checks: [], enforcement: { action: "halted" } },
      { checks: [{ check_id: "c1", passed: true, severity: "critical", evidence: null }], enforcement: { action: "halted" } },
    ];
    for (const params of inputs) {
      const receipt = await generateReceipt({
        correlation_id: "test",
        inputs: {},
        outputs: {},
        ...params,
      } as any);
      expect(receipt.status).not.toBe("PASS");
    }
  });
});

// ── v1.4 tests (SAN-222) ─────────────────────────────────────────────

describe("v1.4 version constants (SAN-222)", () => {
  it("v1.4 version constants", () => {
    expect(SPEC_VERSION).toBe("1.4");
    expect(CHECKS_VERSION).toBe("9");
    expect(TOOL_VERSION).toBe("1.4.0");
    expect(TOOL_NAME).toBe("sanna-ts");
  });
});

describe("v1.4 receipt shape (SAN-222)", () => {
  it("generated receipt has tool_name: 'sanna-ts' by default", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-default-tool-name",
      inputs: {},
      outputs: {},
      checks: [],
    });
    expect(receipt.tool_name).toBe("sanna-ts");
  });

  it("agent_model fields absent when not provided", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-no-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
    }) as unknown as Record<string, unknown>;
    expect("agent_model" in receipt).toBe(false);
    expect("agent_model_provider" in receipt).toBe(false);
    expect("agent_model_version" in receipt).toBe(false);
  });

  it("agent_model fields are null when explicitly null", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-null-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: null,
      agent_model_provider: null,
      agent_model_version: null,
    }) as unknown as Record<string, unknown>;
    expect(receipt.agent_model).toBeNull();
    expect(receipt.agent_model_provider).toBeNull();
    expect(receipt.agent_model_version).toBeNull();
  });

  it("agent_model fields captured when provided", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-with-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: "claude-opus-4-7",
      agent_model_provider: "anthropic",
      agent_model_version: "20250514",
    });
    expect(receipt.agent_model).toBe("claude-opus-4-7");
    expect(receipt.agent_model_provider).toBe("anthropic");
    expect(receipt.agent_model_version).toBe("20250514");
  });
});

describe("v1.4 20-field fingerprint (SAN-222)", () => {
  const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  it("20-field fingerprint structure when cv=9", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-fp-count",
      inputs: {},
      outputs: {},
      checks: [],
    }) as unknown as Record<string, unknown>;
    // cv=9 is the default now
    const fpInput = computeFingerprintInput(receipt);
    const parts = fpInput.split("|");
    expect(parts.length).toBe(20);
  });

  it("agent_model captured at fingerprint position 18 (0-indexed 17)", () => {
    const { hashContent } = require("../src/hashing.js");
    const agentModel = "claude-opus-4-7";
    const expectedHash = hashContent(agentModel, 64);

    const receipt = generateReceipt({
      correlation_id: "v14-fp-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: agentModel,
    }) as unknown as Record<string, unknown>;
    const fpInput = computeFingerprintInput(receipt);
    const parts = fpInput.split("|");
    // Position 18 is 0-indexed [17]
    expect(parts[17]).toBe(expectedHash);
  });

  it("agent_model null/undefined produces EMPTY_HASH at position 18 (0-indexed 17)", () => {
    const receiptNull = generateReceipt({
      correlation_id: "v14-fp-null-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
      agent_model: null,
    }) as unknown as Record<string, unknown>;
    const partsNull = computeFingerprintInput(receiptNull).split("|");
    expect(partsNull[17]).toBe(EMPTY_HASH);

    // Also test absent (undefined)
    const receiptAbsent = generateReceipt({
      correlation_id: "v14-fp-absent-agent-model",
      inputs: {},
      outputs: {},
      checks: [],
    }) as unknown as Record<string, unknown>;
    const partsAbsent = computeFingerprintInput(receiptAbsent).split("|");
    expect(partsAbsent[17]).toBe(EMPTY_HASH);
  });

  it("backward compat: cv=8 still produces 16-field fingerprint", () => {
    const receipt = generateReceipt({
      correlation_id: "v14-compat-cv8",
      inputs: {},
      outputs: {},
      checks: [],
    }) as unknown as Record<string, unknown>;
    const modified = { ...receipt, checks_version: "8" };
    const parts = computeFingerprintInput(modified).split("|");
    expect(parts.length).toBe(16);
  });
});
