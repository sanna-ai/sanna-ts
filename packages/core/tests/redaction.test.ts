/**
 * SAN-250: Redaction module tests.
 * Cross-SDK byte parity with sanna-repo's _make_redaction_marker and
 * _apply_redaction_markers. Tests are ordered to match the spec in the
 * implementation prompt.
 */
import { describe, it, expect, afterEach } from "vitest";
import { createHash } from "node:crypto";
import * as path from "node:path";

import {
  makeRedactionMarker,
  applyRedaction,
  applyRedactionMarkers,
  stringifyPythonEquivalent,
} from "../src/redaction.js";
import type { RedactionConfig } from "../src/redaction.js";
import { generateReceipt, signReceipt, computeFingerprints } from "../src/receipt.js";
import { hashObj } from "../src/hashing.js";
import { generateKeypair } from "../src/crypto.js";
import { verifyReceipt } from "../src/verifier.js";
import { sannaObserve } from "../src/middleware.js";
import { patchChildProcess, unpatchChildProcess } from "../src/interceptors/child-process-interceptor.js";
import { patchFetch, unpatchFetch } from "../src/interceptors/fetch-interceptor.js";
import type { Receipt, ReceiptSink, SinkResult, Constitution } from "../src/types.js";

// ── Fixture constitution ──────────────────────────────────────────────

const PERMISSIVE_CLI = path.resolve(import.meta.dirname, "fixtures/cli-permissive.yaml");
const PERMISSIVE_HTTP = path.resolve(import.meta.dirname, "fixtures/api-permissive.yaml");

// ── Test sink ────────────────────────────────────────────────────────

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(r: Receipt): Promise<SinkResult> {
    this.receipts.push(r);
    return { success: true, receiptId: r.receipt_id };
  }
}

// ── Inline constitution for middleware tests ──────────────────────────

function makeConstitution(overrides: Partial<Constitution> = {}): Constitution {
  return {
    schema_version: "1.0.0",
    identity: { agent_name: "test-agent", domain: "testing", description: "Test", extensions: {} },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [{ id: "B001", description: "Test", category: "scope", severity: "medium" }],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  };
}

// ── Helper: build a minimal cv=9 receipt ─────────────────────────────

function makeReceipt(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = generateReceipt({
    correlation_id: "test-san250-001",
    inputs: { query: "what is the policy?", context: "context text here" },
    outputs: { response: "output text here" },
    checks: [],
    enforcementSurface: "middleware",
    invariantsScope: "full",
  }) as unknown as Record<string, unknown>;
  return { ...base, ...overrides };
}

// ── 1. Marker shape matches Python canonical output ───────────────────

describe("makeRedactionMarker", () => {
  it("test_marker_shape_matches_python_canonical_ascii", () => {
    const marker = makeRedactionMarker("user@example.com");
    expect(marker.__redacted__).toBe(true);
    // Cross-SDK canonical: SHA-256(NFC("user@example.com").encode("utf-8")).hexdigest()
    expect(marker.original_hash).toBe(
      "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514",
    );
  });

  it("test_marker_shape_NFC_normalization", () => {
    // U+00E9 (precomposed é) vs U+0065 U+0301 (decomposed é)
    const composed = "é";
    const decomposed = "é";
    expect(composed).not.toBe(decomposed); // sanity: different byte sequences
    const m1 = makeRedactionMarker(composed);
    const m2 = makeRedactionMarker(decomposed);
    expect(m1.original_hash).toBe(m2.original_hash);
  });
});

// ── 2. applyRedaction field routing ──────────────────────────────────

describe("applyRedaction field routing", () => {
  it("test_apply_redaction_arguments_only", () => {
    const receipt = makeReceipt();
    const config: RedactionConfig = { enabled: true, fields: ["arguments"] };
    const [r, paths] = applyRedaction(receipt, config);
    // inputs.context should be a marker
    const inputs = r.inputs as Record<string, unknown>;
    const outputs = r.outputs as Record<string, unknown>;
    expect((inputs.context as any).__redacted__).toBe(true);
    // outputs.response should NOT be redacted
    expect(typeof outputs.response).toBe("string");
    expect(paths).toEqual(["inputs.context"]);
  });

  it("test_apply_redaction_result_text_only", () => {
    const receipt = makeReceipt();
    const config: RedactionConfig = { enabled: true, fields: ["result_text"] };
    const [r, paths] = applyRedaction(receipt, config);
    const inputs = r.inputs as Record<string, unknown>;
    const outputs = r.outputs as Record<string, unknown>;
    // inputs.context should NOT be redacted
    expect(typeof inputs.context).toBe("string");
    expect((outputs.response as any).__redacted__).toBe(true);
    expect(paths).toEqual(["outputs.response"]);
  });

  it("test_apply_redaction_default_fields", () => {
    const receipt = makeReceipt();
    const config: RedactionConfig = { enabled: true };
    const [r, paths] = applyRedaction(receipt, config);
    const inputs = r.inputs as Record<string, unknown>;
    const outputs = r.outputs as Record<string, unknown>;
    expect((inputs.context as any).__redacted__).toBe(true);
    expect((outputs.response as any).__redacted__).toBe(true);
    expect(paths).toContain("inputs.context");
    expect(paths).toContain("outputs.response");
  });

  it("test_apply_redaction_disabled_no_op", () => {
    const receipt = makeReceipt();
    const originalInputs = JSON.stringify(receipt.inputs);
    const originalOutputs = JSON.stringify(receipt.outputs);
    const config: RedactionConfig = { enabled: false };
    const [r, paths] = applyRedaction(receipt, config);
    expect(paths).toEqual([]);
    expect(JSON.stringify(r.inputs)).toBe(originalInputs);
    expect(JSON.stringify(r.outputs)).toBe(originalOutputs);
  });
});

// ── 3. FIX-12 injection guard ─────────────────────────────────────────

describe("FIX-12 pre-existing marker injection guard", () => {
  it("test_apply_redaction_fix12_injection_guard (inputs.context)", () => {
    const fakeMarker = { __redacted__: true, original_hash: "abc123" };
    const receipt = makeReceipt({
      inputs: { query: null, context: fakeMarker },
      outputs: { response: "some output" },
    });
    const config: RedactionConfig = { enabled: true };
    const [r, paths] = applyRedaction(receipt, config);

    // Verify inputs.context was re-redacted via Python-equivalent serialization
    const inputs = r.inputs as Record<string, unknown>;
    const newMarker = inputs.context as { __redacted__: true; original_hash: string };
    expect(newMarker.__redacted__).toBe(true);

    // The hash should be SHA-256(NFC(stringifyPythonEquivalent(fakeMarker)))
    // stringifyPythonEquivalent({__redacted__: true, original_hash: "abc123"})
    // = '{"__redacted__": true, "original_hash": "abc123"}'
    const expectedSerialized = '{"__redacted__": true, "original_hash": "abc123"}';
    const expectedHash = createHash("sha256").update(expectedSerialized, "utf-8").digest("hex");
    expect(newMarker.original_hash).toBe(expectedHash);

    expect(paths).toContain("inputs.context");
  });

  it("test_apply_redaction_fix12_injection_guard (outputs.response)", () => {
    const fakeMarker = { __redacted__: true, original_hash: "xyz789" };
    const receipt = makeReceipt({
      inputs: { query: null, context: "some context" },
      outputs: { response: fakeMarker },
    });
    const config: RedactionConfig = { enabled: true, fields: ["result_text"] };
    const [r, paths] = applyRedaction(receipt, config);

    const outputs = r.outputs as Record<string, unknown>;
    const newMarker = outputs.response as { __redacted__: true; original_hash: string };
    expect(newMarker.__redacted__).toBe(true);

    const expectedSerialized = '{"__redacted__": true, "original_hash": "xyz789"}';
    const expectedHash = createHash("sha256").update(expectedSerialized, "utf-8").digest("hex");
    expect(newMarker.original_hash).toBe(expectedHash);

    expect(paths).toContain("outputs.response");
  });
});

// ── 4. Python-equivalent JSON serialization ───────────────────────────

describe("stringifyPythonEquivalent", () => {
  it("test_python_equivalent_stringify_basic", () => {
    const result = stringifyPythonEquivalent({ __redacted__: true, original_hash: "abc" });
    // Keys sorted: __redacted__ < original_hash (underscore < 'o')
    // Separators: ", " between pairs, ": " between key and value
    expect(result).toBe('{"__redacted__": true, "original_hash": "abc"}');
  });

  it("test_python_equivalent_stringify_non_ascii_escape", () => {
    const result = stringifyPythonEquivalent({ k: "café" });
    // ensure_ascii=True: é (U+00E9) -> é
    expect(result).toBe('{"k": "caf\\u00e9"}');
  });

  it("serializes null correctly", () => {
    expect(stringifyPythonEquivalent(null)).toBe("null");
  });

  it("serializes booleans correctly", () => {
    expect(stringifyPythonEquivalent(true)).toBe("true");
    expect(stringifyPythonEquivalent(false)).toBe("false");
  });

  it("serializes arrays with correct separators", () => {
    expect(stringifyPythonEquivalent([1, 2, 3])).toBe("[1, 2, 3]");
  });

  it("sorts keys in nested objects", () => {
    const result = stringifyPythonEquivalent({ z: 1, a: 2 });
    expect(result).toBe('{"a": 2, "z": 1}');
  });

  it("escapes control characters correctly", () => {
    const result = stringifyPythonEquivalent({ k: "line\nnewline\ttab" });
    expect(result).toBe('{"k": "line\\nnewline\\ttab"}');
  });
});

// ── 5. Hash and fingerprint recomputation ────────────────────────────

describe("applyRedaction hash recomputation", () => {
  it("test_apply_redaction_recomputes_hashes", () => {
    const receipt = makeReceipt();
    const originalContextHash = receipt.context_hash as string;
    const originalOutputHash = receipt.output_hash as string;

    const config: RedactionConfig = { enabled: true };
    const [r, paths] = applyRedaction(receipt, config);

    // Hashes must change (markers are not equal to original strings)
    expect(r.context_hash).not.toBe(originalContextHash);
    expect(r.output_hash).not.toBe(originalOutputHash);

    // redacted_fields must be set
    expect((r as any).redacted_fields).toContain("inputs.context");
    expect((r as any).redacted_fields).toContain("outputs.response");

    expect(paths).toHaveLength(2);
  });

  it("test_apply_redaction_recomputes_fingerprint_cv10", () => {
    // Build a minimal cv=10 receipt with agent_identity
    const receipt = generateReceipt({
      correlation_id: "test-cv10-fp-001",
      inputs: { query: "test query", context: "test context" },
      outputs: { response: "test output" },
      checks: [],
      enforcementSurface: "middleware",
      invariantsScope: "full",
      agent_identity: { agent_session_id: "session-test-cv10" },
    }) as unknown as Record<string, unknown>;

    const originalFullFp = receipt.full_fingerprint as string;
    const originalReceiptFp = receipt.receipt_fingerprint as string;

    const config: RedactionConfig = { enabled: true };
    const [r] = applyRedaction(receipt, config);

    // Fingerprints must be recomputed (different from before redaction)
    expect(r.full_fingerprint).not.toBe(originalFullFp);
    expect(r.receipt_fingerprint).not.toBe(originalReceiptFp);

    // Verify consistency: recomputing from the updated receipt gives the same values
    const { receipt_fingerprint, full_fingerprint } = computeFingerprints(r);
    expect(r.full_fingerprint).toBe(full_fingerprint);
    expect(r.receipt_fingerprint).toBe(receipt_fingerprint);
  });

  it("hash recompute uses marker-bearing inputs, not originals", () => {
    const receipt = makeReceipt({
      inputs: { query: null, context: "hello" },
      outputs: { response: "world" },
    });
    const config: RedactionConfig = { enabled: true };
    const [r] = applyRedaction(receipt, config);

    // context_hash should equal hashObj(inputs with marker)
    const inputs = r.inputs as Record<string, unknown>;
    expect(r.context_hash).toBe(hashObj(inputs));

    const outputs = r.outputs as Record<string, unknown>;
    expect(r.output_hash).toBe(hashObj(outputs));
  });
});

// ── 6. Middleware end-to-end ──────────────────────────────────────────

describe("middleware with redactionConfig", () => {
  it("test_middleware_emits_redacted_with_config", () => {
    const constitution = makeConstitution();
    const governed = sannaObserve(
      (input: { query: string; context: string }) =>
        `Response: ${input.query}`,
      {
        constitution,
        redactionConfig: { enabled: true },
      },
    );

    const result = governed({
      query: "test query",
      context: "sensitive context data",
    });

    const r = result.receipt as unknown as Record<string, unknown>;

    // content_mode must be set
    expect(r.content_mode).toBe("redacted");
    expect(r.content_mode_source).toBe("local_config");

    // redacted_fields must be set
    const redactedFields = (r as any).redacted_fields as string[];
    expect(redactedFields).toContain("inputs.context");
    expect(redactedFields).toContain("outputs.response");

    // inputs.context should be a marker object
    const inputs = r.inputs as Record<string, unknown>;
    expect((inputs.context as any).__redacted__).toBe(true);
    expect(typeof (inputs.context as any).original_hash).toBe("string");

    // outputs.response should be a marker object
    const outputs = r.outputs as Record<string, unknown>;
    expect((outputs.response as any).__redacted__).toBe(true);
    expect(typeof (outputs.response as any).original_hash).toBe("string");
  });

  it("test_middleware_signature_verifies_redacted", () => {
    const { privateKey, publicKey } = generateKeypair();
    const constitution = makeConstitution();
    const governed = sannaObserve(
      (input: { query: string; context: string }) => `Output: ${input.query}`,
      {
        constitution,
        redactionConfig: { enabled: true },
      },
    );

    const result = governed({
      query: "verifiable query",
      context: "secret context",
    });

    // Sign the receipt
    const receiptObj = result.receipt as unknown as Record<string, unknown>;
    signReceipt(receiptObj, privateKey, "test-signer");

    // Verify the signed receipt with markers
    const verifyResult = verifyReceipt(receiptObj as unknown as Receipt, publicKey);
    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.errors).toEqual([]);
  });
});

// ── 7. Fetch interceptor end-to-end ──────────────────────────────────

describe("fetch interceptor with redactionConfig", () => {
  afterEach(() => {
    unpatchFetch();
  });

  it("test_fetch_interceptor_with_redaction: redactionConfig accepted without error", async () => {
    const sink = new TestSink();

    await patchFetch({
      constitutionPath: PERMISSIVE_HTTP,
      sink,
      agentId: "test-agent-redaction",
      mode: "passthrough",
      redactionConfig: { enabled: true },
    });

    // If patch succeeds, redactionConfig is accepted
    expect(sink.receipts.length).toBeGreaterThan(0); // session_manifest emitted

    const manifestReceipt = sink.receipts.find(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipt).toBeDefined();
  });
});

// ── 8. Child-process interceptor end-to-end ──────────────────────────

describe("child-process interceptor with redactionConfig", () => {
  afterEach(() => {
    unpatchChildProcess();
  });

  it("test_child_process_interceptor_with_redaction: redactionConfig accepted without error", async () => {
    const sink = new TestSink();

    await patchChildProcess({
      constitutionPath: PERMISSIVE_CLI,
      sink,
      agentId: "test-agent-redaction-cli",
      mode: "passthrough",
      redactionConfig: { enabled: true },
    });

    // If patch succeeds, redactionConfig is accepted
    expect(sink.receipts.length).toBeGreaterThan(0); // session_manifest emitted

    const manifestReceipt = sink.receipts.find(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipt).toBeDefined();
  });
});

// ── 9. applyRedaction with no-op inputs (no context/response field) ───

describe("applyRedaction no-op cases", () => {
  it("receipt without inputs.context or outputs.response is unchanged", () => {
    // Gateway-style receipt: inputs.args, outputs.content (no context/response)
    const receipt: Record<string, unknown> = {
      correlation_id: "test-noop-001",
      inputs: { tool: "echo", args: { message: "hello" } },
      outputs: { content: [{ type: "text", text: "hello" }] },
      context_hash: "aaa",
      output_hash: "bbb",
      full_fingerprint: "ccc",
      receipt_fingerprint: "ddd",
      checks_version: "10",
      enforcement_surface: "gateway",
      invariants_scope: "full",
      tool_name: "sanna-ts",
      agent_identity: { agent_session_id: "session-noop" },
    };

    const config: RedactionConfig = { enabled: true };
    const [r, paths] = applyRedaction(receipt, config);

    // No fields redacted since no context/response
    expect(paths).toEqual([]);
    expect(r.context_hash).toBe("aaa"); // unchanged
    expect(r.output_hash).toBe("bbb"); // unchanged
  });

  it("receipt with null context is skipped (falsy guard)", () => {
    const receipt = makeReceipt({
      inputs: { query: "test", context: null },
      outputs: { response: null },
    });
    const config: RedactionConfig = { enabled: true };
    const [, paths] = applyRedaction(receipt, config);
    // null is falsy -- Python's 'if ctx:' check
    expect(paths).toEqual([]);
  });

  it("receipt with empty-string context is skipped (falsy guard)", () => {
    const receipt = makeReceipt({
      inputs: { query: "test", context: "" },
      outputs: { response: "" },
    });
    const config: RedactionConfig = { enabled: true };
    const [, paths] = applyRedaction(receipt, config);
    // empty string is falsy -- Python's 'if ctx:' check
    expect(paths).toEqual([]);
  });
});
