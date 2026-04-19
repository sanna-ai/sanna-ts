import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import {
  generateReceipt,
  signReceipt,
  computeFingerprints,
  SPEC_VERSION,
  CHECKS_VERSION,
} from "../src/receipt.js";
import { loadPrivateKey, loadPublicKey, verify } from "../src/crypto.js";
import { canonicalize } from "../src/hashing.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const privKey = loadPrivateKey(resolve(FIXTURES, "keypairs/test-author.key"));
const pubKey = loadPublicKey(resolve(FIXTURES, "keypairs/test-author.pub"));

/** Minimal valid receipt params for reuse across tests. */
function baseParams() {
  return {
    correlation_id: "chain-test-001",
    inputs: { query: "What is 2+2?", context: "Math" },
    outputs: { response: "4" },
    checks: [
      {
        check_id: "C1",
        name: "boundary-check",
        passed: true,
        severity: "info" as const,
        evidence: null,
      },
    ],
  };
}

// ── generateReceipt with chaining fields ────────────────────────────

describe("generateReceipt with parent_receipts", () => {
  it("includes parent_receipts in output", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      parent_receipts: ["receipt-aaa", "receipt-bbb"],
    });
    expect(receipt.parent_receipts).toEqual(["receipt-aaa", "receipt-bbb"]);
  });
});

describe("generateReceipt with workflow_id", () => {
  it("includes workflow_id in output", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      workflow_id: "wf-123",
    });
    expect(receipt.workflow_id).toBe("wf-123");
  });
});

describe("generateReceipt with content_mode", () => {
  it("includes content_mode in output", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      content_mode: "redacted",
    });
    expect(receipt.content_mode).toBe("redacted");
  });
});

describe("generateReceipt with content_mode_source", () => {
  it("includes content_mode_source in output", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      content_mode_source: "gateway-policy",
    });
    expect(receipt.content_mode_source).toBe("gateway-policy");
  });
});

// ── Null / absent field omission ────────────────────────────────────

describe("parent_receipts=null omits field from receipt", () => {
  it("does not include parent_receipts when null", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      parent_receipts: null,
    });
    expect("parent_receipts" in receipt).toBe(false);
  });
});

describe("workflow_id=null omits field from receipt", () => {
  it("does not include workflow_id when null", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      workflow_id: null,
    });
    expect("workflow_id" in receipt).toBe(false);
  });
});

// ── Fingerprint sensitivity ─────────────────────────────────────────

describe("parent_receipts changes fingerprint", () => {
  it("produces different fingerprint when parent_receipts differs", () => {
    const a = generateReceipt({ ...baseParams() });
    const b = generateReceipt({
      ...baseParams(),
      parent_receipts: ["receipt-xyz"],
    });
    expect(a.receipt_fingerprint).not.toBe(b.receipt_fingerprint);
    expect(a.full_fingerprint).not.toBe(b.full_fingerprint);
  });
});

describe("workflow_id changes fingerprint", () => {
  it("produces different fingerprint when workflow_id differs", () => {
    const a = generateReceipt({ ...baseParams() });
    const b = generateReceipt({
      ...baseParams(),
      workflow_id: "wf-unique",
    });
    expect(a.receipt_fingerprint).not.toBe(b.receipt_fingerprint);
    expect(a.full_fingerprint).not.toBe(b.full_fingerprint);
  });
});

describe("content_mode does NOT change fingerprint", () => {
  it("produces identical fingerprint regardless of content_mode", () => {
    const a = generateReceipt({ ...baseParams() });
    const b = generateReceipt({
      ...baseParams(),
      content_mode: "hashes_only",
    });
    expect(a.receipt_fingerprint).toBe(b.receipt_fingerprint);
    expect(a.full_fingerprint).toBe(b.full_fingerprint);
  });
});

describe("content_mode_source does NOT change fingerprint", () => {
  it("produces identical fingerprint regardless of content_mode_source", () => {
    const a = generateReceipt({ ...baseParams() });
    const b = generateReceipt({
      ...baseParams(),
      content_mode_source: "user-preference",
    });
    expect(a.receipt_fingerprint).toBe(b.receipt_fingerprint);
    expect(a.full_fingerprint).toBe(b.full_fingerprint);
  });
});

describe("empty parent_receipts array produces different fingerprint than null", () => {
  it("[] and null produce different fingerprints", () => {
    const withNull = generateReceipt({ ...baseParams() });
    const withEmpty = generateReceipt({
      ...baseParams(),
      parent_receipts: [],
    });
    // [] is a real value (hash it), null/absent → EMPTY_HASH. They must differ.
    expect(withNull.full_fingerprint).not.toBe(withEmpty.full_fingerprint);
    expect(withNull.receipt_fingerprint).not.toBe(withEmpty.receipt_fingerprint);
  });
});

describe("parent_receipts order matters for fingerprint", () => {
  it('["a","b"] and ["b","a"] produce different fingerprints', () => {
    const ab = generateReceipt({
      ...baseParams(),
      parent_receipts: ["a", "b"],
    });
    const ba = generateReceipt({
      ...baseParams(),
      parent_receipts: ["b", "a"],
    });
    expect(ab.receipt_fingerprint).not.toBe(ba.receipt_fingerprint);
    expect(ab.full_fingerprint).not.toBe(ba.full_fingerprint);
  });
});

// ── Constants ───────────────────────────────────────────────────────

describe("SPEC_VERSION is 1.3", () => {
  it("equals '1.3'", () => {
    expect(SPEC_VERSION).toBe("1.3");
  });
});

describe("CHECKS_VERSION is 8", () => {
  it("equals '8'", () => {
    expect(CHECKS_VERSION).toBe("8");
  });
});

describe("tool_version defaults to sanna-ts/1.3.0", () => {
  it("uses default tool_version when none provided", () => {
    const receipt = generateReceipt({ ...baseParams() });
    expect(receipt.tool_version).toBe("sanna-ts/1.3.0");
  });
});

// ── Receipt with all v1.1 fields ────────────────────────────────────

describe("receipt with all v1.1 fields generates valid fingerprints", () => {
  it("produces 16-hex receipt_fingerprint and 64-hex full_fingerprint", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      parent_receipts: ["parent-1", "parent-2"],
      workflow_id: "wf-all-fields",
      content_mode: "full",
      content_mode_source: "constitution",
    });
    expect(receipt.receipt_fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(receipt.full_fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});

// ── Multiple parent_receipts ────────────────────────────────────────

describe("multiple parent_receipts", () => {
  it("accepts an array with 3 entries", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      parent_receipts: ["r-1", "r-2", "r-3"],
    });
    expect(receipt.parent_receipts).toEqual(["r-1", "r-2", "r-3"]);
    expect(receipt.parent_receipts).toHaveLength(3);
  });
});

// ── workflow_id format ──────────────────────────────────────────────

describe("workflow_id is just a string - any format accepted", () => {
  it("accepts arbitrary string values", () => {
    const formats = [
      "simple-id",
      "550e8400-e29b-41d4-a716-446655440000",
      "urn:workflow:my-org:pipeline-7",
      "https://example.com/workflows/42",
      "",
    ];
    for (const wfId of formats) {
      const receipt = generateReceipt({
        ...baseParams(),
        workflow_id: wfId,
      });
      expect(receipt.workflow_id).toBe(wfId);
    }
  });
});

// ── Determinism ─────────────────────────────────────────────────────

describe("computeFingerprints is deterministic with new fields", () => {
  it("returns identical fingerprints for identical input", () => {
    const receiptData: Record<string, unknown> = {
      correlation_id: "det-test",
      context_hash: "abc123",
      output_hash: "def456",
      checks_version: CHECKS_VERSION,
      checks: [],
      parent_receipts: ["p1", "p2"],
      workflow_id: "wf-det",
    };
    const first = computeFingerprints(receiptData);
    const second = computeFingerprints(receiptData);
    expect(first.receipt_fingerprint).toBe(second.receipt_fingerprint);
    expect(first.full_fingerprint).toBe(second.full_fingerprint);
  });
});

// ── Signing with new fields ─────────────────────────────────────────

describe("signReceipt works with receipts containing new fields", () => {
  it("produces a valid signature over a receipt with chaining fields", () => {
    const receipt = generateReceipt({
      ...baseParams(),
      parent_receipts: ["parent-abc"],
      workflow_id: "wf-sign-test",
      content_mode: "full",
      content_mode_source: "gateway",
    });

    const signed = signReceipt(
      receipt as unknown as Record<string, unknown>,
      privKey,
      "test-author",
    );

    // Verify the signature is present and non-empty
    const sig = signed.receipt_signature as Record<string, unknown>;
    expect(sig).toBeDefined();
    expect(sig.signature).toBeTruthy();
    expect(sig.signed_by).toBe("test-author");
    expect(sig.scheme).toBe("receipt_sig_v1");

    // Verify the signature is cryptographically valid
    const signedCopy = structuredClone(signed);
    (signedCopy.receipt_signature as Record<string, unknown>).signature = "";
    const canonical = canonicalize(signedCopy);
    const data = Buffer.from(canonical, "utf-8");
    const isValid = verify(data, sig.signature as string, pubKey);
    expect(isValid).toBe(true);
  });
});
