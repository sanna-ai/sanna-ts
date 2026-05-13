/**
 * Property-based tests for Sanna crypto primitives (SAN-294).
 *
 * TypeScript mirror of sanna-repo SAN-293 (Hypothesis-based PBT;
 * merged 2026-05-12 as 2ffd764). Uses fast-check to generate random
 * inputs and assert invariants hold across the input space.
 *
 * Complements fixture-based coverage (hashing.test.ts,
 * cross-language.test.ts, receipt-chaining.test.ts,
 * cross-sdk-gateway-redaction-vectors.test.ts).
 *
 * Ten property categories:
 *  1.  Canonical JSON determinism (canonicalize)
 *  2.  NFC scope (hashContent NFC-invariance + hashObj NFC byte-
 *      differentiation; ADR-004 normative)
 *  3.  Fingerprint stability:
 *      3a. computeFingerprints deterministic on repeat calls
 *      3b. computeFingerprints stable across canonical-JSON round-trip
 *  4.  Empty container handling: [] vs null produces distinct
 *      fingerprints (parent_receipts AND privilege_scope list field of
 *      agent_identity at cv=10, per spec Section 2.19)
 *  5.  Float handling:
 *      5a. Integer-valued numbers serialize without decimal point
 *          (cross-SDK byte-parity with Python's int coercion)
 *      5b. Non-integer floats do NOT throw in canonicalize itself (it
 *          serializes them as JSON); the SIGNING path rejects them via
 *          sanitizeForSigning to guard cross-SDK byte-parity. Both
 *          behaviors are tested here.
 *  6.  Special float rejection: NaN / +Infinity / -Infinity
 *  7.  Signature round-trip: sign + verify on arbitrary Buffer;
 *      tampered message AND tampered signature both fail
 *  8.  Field count dispatch: cv-aware dispatch produces 12/14/16/20/21
 *      field fingerprint for cv=5/6-7/8/9/10 (externally observed via
 *      differential receipts)
 *  9.  Redaction marker shape (Spec section 2.11.1); cross-SDK
 *      verified against spec/fixtures/gateway-redaction-vectors.json
 * 10.  Fingerprint cross-site parity:
 *      10a. Static-analysis test: each consumer (verifier.ts, aarm.ts,
 *           redaction.ts, bundle.ts) imports computeFingerprints from
 *           ./receipt.js; no consumer contains an inline function
 *           computeFingerprints declaration
 *      10b. Sample-input integration: emit via redaction.ts path,
 *           verify via computeFingerprints path; identical fingerprints
 *           prove consumers share the canonical function
 *
 * Note on Property 5b: the canonicalize library (RFC 8785 JCS) does
 * NOT throw for non-integer floats — it serializes them as JSON.
 * The rejection happens in sanitizeForSigning (signing path only).
 * The prompt's original claim "non-integer floats raise" is accurate
 * for the signing path; the test is reframed accordingly.
 *
 * CI runs default 100 examples per property. Override via
 * SANNA_FAST_CHECK_NUM_RUNS env var for nightly extended runs.
 * Per-test timeout is 30s to accommodate crypto op variability.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import * as fc from "fast-check";
import {
  canonicalize,
  hashContent,
  hashObj,
  EMPTY_HASH,
} from "../src/hashing.js";
import {
  generateKeypair,
  sign,
  verify,
  type SannaKeypair,
} from "../src/crypto.js";
import {
  computeFingerprintInput,
  computeFingerprints,
  signReceipt,
} from "../src/receipt.js";
import {
  makeRedactionMarker,
  applyRedactionMarkers,
} from "../src/redaction.js";

const NUM_RUNS = parseInt(process.env.SANNA_FAST_CHECK_NUM_RUNS ?? "100", 10);
const fcParams = { numRuns: NUM_RUNS };
const PROPERTY_TIMEOUT_MS = 30_000;

// File-path helper for the static-analysis test (Property 10a)
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const SRC_DIR = resolve(__dirname, "../src");

// ── Shared strategies ─────────────────────────────────────────────────

// fc.fullUnicodeString generates well-formed Unicode (no lone surrogates).
// Equivalent to Python Hypothesis's
// st.text(alphabet=st.characters(blacklist_categories=("Cs",))).
const jsonSafeText = fc.fullUnicodeString({ maxLength: 200 });

const jsonValues: fc.Arbitrary<unknown> = fc.letrec((tie) => ({
  value: fc.oneof(
    fc.constant(null),
    fc.boolean(),
    fc.integer({ min: -(2 ** 53) + 1, max: (2 ** 53) - 1 }),
    jsonSafeText,
    fc.array(tie("value") as fc.Arbitrary<unknown>, { maxLength: 8 }),
    fc.dictionary(
      fc.string({ minLength: 1, maxLength: 20 }),
      tie("value") as fc.Arbitrary<unknown>,
      { maxKeys: 8 },
    ),
  ),
})).value as fc.Arbitrary<unknown>;

/**
 * Build a minimal receipt for a given checks_version that produces a valid
 * (non-empty-input) fingerprint from computeFingerprints.
 *
 * Required fields per cv level (sourced from receipt.ts computeFingerprintInput
 * + spec Section 4 cv-dispatch ladder):
 *   cv=5:   12-field formula — correlation_id, context_hash, output_hash,
 *           checks_version, checks (empty array ok)
 *   cv=6,7: 14-field formula — same + parent_receipts and workflow_id
 *           (both null → EMPTY_HASH by formula)
 *   cv=8:   16-field formula — same + enforcement_surface, invariants_scope
 *           (can be empty strings; hash of "" is EMPTY_HASH)
 *   cv=9:   20-field formula — same + tool_name, agent_model*
 *   cv=10:  21-field formula — same + agent_identity (non-null required);
 *           tool_name MUST be non-empty (else computeFingerprintInput
 *           returns "" short-circuit); enforcement_surface and
 *           invariants_scope MUST be non-empty for same reason
 */
function buildBaseReceipt(cv: number): Record<string, unknown> {
  const base: Record<string, unknown> = {
    correlation_id: "test-corr-san294",
    context_hash: EMPTY_HASH,
    output_hash: EMPTY_HASH,
    checks_version: String(cv),
    checks: [],
  };

  if (cv >= 8) {
    base.enforcement_surface = "middleware";
    base.invariants_scope = "full";
  }

  if (cv >= 9) {
    base.tool_name = "sanna-ts";
    base.agent_model = null;
    base.agent_model_provider = null;
    base.agent_model_version = null;
  }

  if (cv >= 10) {
    base.agent_identity = { agent_session_id: "sn_ag_san294_test" };
  }

  return base;
}

// Receipt strategy: generates one of the 6 supported cv levels
const receiptStrategy = fc
  .constantFrom(5, 6, 7, 8, 9, 10)
  .map((cv) => buildBaseReceipt(cv));

// ── Helper ────────────────────────────────────────────────────────────

function shuffleDictKeys(obj: unknown): unknown {
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    const entries = Object.entries(obj as Record<string, unknown>);
    return Object.fromEntries(
      entries.reverse().map(([k, v]) => [k, shuffleDictKeys(v)]),
    );
  }
  if (Array.isArray(obj)) return obj.map(shuffleDictKeys);
  return obj;
}

// ── 1. Canonical JSON determinism ─────────────────────────────────────

describe("Property 1: Canonical JSON determinism", () => {
  it(
    "canonicalize invariant under dict key reordering",
    () => {
      fc.assert(
        fc.property(jsonValues, (obj) => {
          const shuffled = shuffleDictKeys(obj);
          expect(canonicalize(obj)).toBe(canonicalize(shuffled));
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 2. NFC scope (ADR-004) ────────────────────────────────────────────

describe("Property 2: NFC scope (ADR-004)", () => {
  it(
    "2a: hashContent NFC-invariant — NFC and NFD inputs produce same hash",
    () => {
      fc.assert(
        fc.property(jsonSafeText, (s) => {
          const nfc = s.normalize("NFC");
          const nfd = s.normalize("NFD");
          // hashContent applies NFC normalization internally (step 1 of §3.3
          // pipeline), so both inputs produce the same hash regardless of the
          // input's normalization form.
          expect(hashContent(nfc)).toBe(hashContent(nfd));
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "2b: hashObj does NOT NFC-normalize inside objects (byte-differentiation)",
    () => {
      fc.assert(
        fc.property(jsonSafeText, (s) => {
          const nfc = s.normalize("NFC");
          const nfd = s.normalize("NFD");
          // Only run the assertion when NFC ≠ NFD (i.e., the string contains
          // at least one character with a non-trivial decomposition, such as
          // precomposed characters like "é" U+00E9 vs "e" + U+0301).
          fc.pre(nfc !== nfd);
          // hashObj calls canonicalize which uses JSON.stringify — no NFC
          // normalization. Different byte sequences → different SHA-256 hashes.
          expect(hashObj({ k: nfc })).not.toBe(hashObj({ k: nfd }));
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 3. Fingerprint stability ──────────────────────────────────────────

describe("Property 3: Fingerprint stability", () => {
  it(
    "3a: computeFingerprints deterministic on repeat calls",
    () => {
      fc.assert(
        fc.property(receiptStrategy, (receipt) => {
          const fp1 = computeFingerprints(receipt);
          const fp2 = computeFingerprints(receipt);
          expect(fp1.receipt_fingerprint).toBe(fp2.receipt_fingerprint);
          expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "3b: computeFingerprints stable across canonical-JSON round-trip",
    () => {
      fc.assert(
        fc.property(receiptStrategy, (receipt) => {
          const fp1 = computeFingerprints(receipt);
          // Round-trip through canonical JSON: undefined fields are dropped,
          // all values are JSON-serialized and reparsed. The fingerprint
          // formula uses ?? fallbacks for absent fields, so dropping undefined
          // is equivalent to absence — the fingerprint must not change.
          const roundTripped = JSON.parse(
            canonicalize(receipt),
          ) as Record<string, unknown>;
          const fp2 = computeFingerprints(roundTripped);
          expect(fp1.receipt_fingerprint).toBe(fp2.receipt_fingerprint);
          expect(fp1.full_fingerprint).toBe(fp2.full_fingerprint);
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 4. Empty container handling ([] vs null) ──────────────────────────

describe("Property 4: Empty container handling ([] vs null)", () => {
  it("parent_receipts: [] produces distinct fingerprint from null (cv=6)", () => {
    // At cv=6, field 13 is parentReceiptsHash = hashObj(parent_receipts)
    // when non-null, or EMPTY_HASH when null. [] and null are different
    // inputs to hashObj → different hashes → different fingerprints.
    const base = buildBaseReceipt(6);
    const receiptEmpty = { ...base, parent_receipts: [] };
    const receiptNull = { ...base, parent_receipts: null };
    expect(computeFingerprints(receiptEmpty).receipt_fingerprint).not.toBe(
      computeFingerprints(receiptNull).receipt_fingerprint,
    );
  });

  it(
    "agent_identity.privilege_scope: [] produces distinct fingerprint from null at cv=10",
    () => {
      // privilege_scope is an optional array-of-strings field on agent_identity
      // at cv=10 (spec Section 2.19, line 823: "array of strings or null").
      // Field 21 is agent_identity_hash = hashObj(agent_identity). The
      // distinction between [] and null is load-bearing for audit purposes
      // (empty granted-privileges list is semantically different from
      // "privilege scope not recorded").
      const base = buildBaseReceipt(10);
      const r_empty = {
        ...base,
        agent_identity: {
          agent_session_id: "sn_ag_priv_test",
          privilege_scope: [],
        },
      };
      const r_null = {
        ...base,
        agent_identity: {
          agent_session_id: "sn_ag_priv_test",
          privilege_scope: null,
        },
      };
      expect(computeFingerprints(r_empty).receipt_fingerprint).not.toBe(
        computeFingerprints(r_null).receipt_fingerprint,
      );
    },
  );
});

// ── 5. Float handling ─────────────────────────────────────────────────

describe("Property 5: Float handling (cross-SDK byte-parity)", () => {
  it(
    "5a: integer-valued numbers serialize without decimal point",
    () => {
      // The spec's load-bearing cross-SDK byte-parity claim (Section 3):
      // receipts must be byte-identical across SDKs. JavaScript's typeof
      // does not distinguish int from float — JSON.stringify(2.0) = "2"
      // (no decimal). Python's json.dumps(2.0) = "2.0" (decimal present).
      // RFC 8785 JCS (the canonicalize library) uses JSON.stringify for
      // scalars, so canonicalize(2.0) = "2" in TS. This test asserts that
      // invariant: no decimal point for integer-valued numbers.
      fc.assert(
        fc.property(
          fc.integer({ min: -(2 ** 53) + 1, max: (2 ** 53) - 1 }),
          (n) => {
            const out = canonicalize(n);
            expect(out).not.toMatch(/-?\d+\.\d/);
          },
        ),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "5b: non-integer floats serialize in canonicalize (no throw) but are rejected by the signing path",
    () => {
      // The canonicalize library (RFC 8785 JCS) does NOT throw for
      // non-integer floats: it delegates to JSON.stringify which serializes
      // them normally (e.g., canonicalize(1.5) === "1.5"). The rejection
      // lives in sanitizeForSigning (receipt.ts + verifier.ts), which is
      // called by signReceipt before canonical serialization. This guards
      // the signing path against cross-SDK divergence: Python's
      // canonical_json_bytes may coerce float->int, producing "1" where TS
      // would produce "1.5" without the guard.
      fc.assert(
        fc.property(
          fc.double({
            min: -1e6,
            max: 1e6,
            noNaN: true,
            noDefaultInfinity: true,
          }),
          (f) => {
            fc.pre(f !== Math.floor(f)); // filter: must be a non-integer float
            // canonicalize itself does not throw — it delegates non-integer
            // floats to JSON.stringify, which serializes them as-is (e.g.,
            // "1.5", "0.25", or even "-5e-324" for very small subnormals in
            // exponential notation). We assert only that it returns a string
            // without throwing; the form of the output varies.
            const result = canonicalize(f);
            expect(typeof result).toBe("string");
          },
        ),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "5b (signing): non-integer floats in receipt body are rejected by signReceipt",
    () => {
      const keypair = generateKeypair("san294-pbt-float-test");
      fc.assert(
        fc.property(
          fc.double({
            min: -1e6,
            max: 1e6,
            noNaN: true,
            noDefaultInfinity: true,
          }),
          (f) => {
            fc.pre(f !== Math.floor(f));
            const receipt = buildBaseReceipt(9);
            receipt.non_int_test_field = f;
            expect(() =>
              signReceipt(receipt, keypair.privateKey, "san294-test"),
            ).toThrow();
          },
        ),
        { ...fcParams, numRuns: Math.min(NUM_RUNS, 50) },
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 6. Special float rejection ────────────────────────────────────────

describe("Property 6: Special float rejection (canonicalize)", () => {
  it("6a: NaN raises", () => {
    expect(() => canonicalize(NaN)).toThrow(/NaN is not allowed/);
  });

  it("6b: +Infinity raises", () => {
    expect(() => canonicalize(Infinity)).toThrow(/Infinity is not allowed/);
  });

  it("6c: -Infinity raises", () => {
    expect(() => canonicalize(-Infinity)).toThrow(/Infinity is not allowed/);
  });
});

// ── 7. Signature round-trip ───────────────────────────────────────────

describe("Property 7: Signature round-trip", () => {
  let keypair: SannaKeypair;
  beforeAll(() => {
    keypair = generateKeypair("san294-pbt-test");
  });

  it(
    "sign + verify round-trip on arbitrary bytes",
    () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 10000 }),
          (data) => {
            const buf = Buffer.from(data);
            const sig = sign(buf, keypair.privateKey);
            expect(verify(buf, sig, keypair.publicKey)).toBe(true);
          },
        ),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "tampered message fails verification",
    () => {
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 10000 }),
          fc.nat(),
          fc.integer({ min: 0, max: 7 }),
          (data, byteIdxRaw, bitIdx) => {
            const buf = Buffer.from(data);
            const sig = sign(buf, keypair.privateKey);
            const byteIdx = byteIdxRaw % data.length;
            const tampered = Buffer.from(data);
            tampered[byteIdx] ^= 1 << bitIdx;
            // A flipped bit in data makes verify return false
            expect(verify(tampered, sig, keypair.publicKey)).toBe(false);
          },
        ),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "tampered signature fails verification",
    () => {
      // sign() returns standard Base64 (RFC 4648). Decode → flip one bit
      // in the raw signature bytes → re-encode → verify must return false.
      fc.assert(
        fc.property(
          fc.uint8Array({ minLength: 1, maxLength: 10000 }),
          fc.nat(),
          fc.integer({ min: 0, max: 7 }),
          (data, byteIdxRaw, bitIdx) => {
            const buf = Buffer.from(data);
            const sigB64 = sign(buf, keypair.privateKey);
            const sigBytes = Buffer.from(sigB64, "base64");
            const byteIdx = byteIdxRaw % sigBytes.length;
            sigBytes[byteIdx] ^= 1 << bitIdx;
            const tamperedSigB64 = sigBytes.toString("base64");
            expect(verify(buf, tamperedSigB64, keypair.publicKey)).toBe(false);
          },
        ),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 8. Field count dispatch (cv-aware) ───────────────────────────────

describe("Property 8: Field count dispatch (cv-aware)", () => {
  // cv=5 → 12-field formula (no parent_receipts)
  it("cv=5 excludes parent_receipts from fingerprint (field 13)", () => {
    const base = buildBaseReceipt(5);
    const without = { ...base, parent_receipts: null };
    const withParent = { ...base, parent_receipts: ["r_abc"] };
    expect(computeFingerprints(without).receipt_fingerprint).toBe(
      computeFingerprints(withParent).receipt_fingerprint,
    );
  });

  // cv=6 → 14-field formula (includes parent_receipts at field 13)
  it("cv=6 includes parent_receipts in fingerprint (field 13)", () => {
    const base = buildBaseReceipt(6);
    const without = { ...base, parent_receipts: null };
    const withParent = { ...base, parent_receipts: ["r_abc"] };
    expect(computeFingerprints(without).receipt_fingerprint).not.toBe(
      computeFingerprints(withParent).receipt_fingerprint,
    );
  });

  // cv=7 excludes enforcement_surface (14-field formula)
  it("cv=7 excludes enforcement_surface from fingerprint (14-field formula)", () => {
    const base = buildBaseReceipt(7);
    const r1 = { ...base, enforcement_surface: "middleware" };
    const r2 = { ...base, enforcement_surface: "api_gateway" };
    expect(computeFingerprints(r1).receipt_fingerprint).toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });

  // cv=8 → 16-field formula (adds enforcement_surface + invariants_scope)
  it("cv=8 includes enforcement_surface in fingerprint (field 15)", () => {
    const base = buildBaseReceipt(8);
    const r1 = { ...base, enforcement_surface: "middleware" };
    const r2 = { ...base, enforcement_surface: "api_gateway" };
    expect(computeFingerprints(r1).receipt_fingerprint).not.toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });

  // cv=8 excludes tool_name (16-field formula)
  it("cv=8 excludes tool_name from fingerprint (16-field formula)", () => {
    const base = buildBaseReceipt(8);
    const r1 = { ...base, tool_name: "sanna-ts" };
    const r2 = { ...base, tool_name: "sanna" };
    expect(computeFingerprints(r1).receipt_fingerprint).toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });

  // cv=9 → 20-field formula (adds tool_name at field 17)
  it("cv=9 includes tool_name in fingerprint (field 17)", () => {
    const base = buildBaseReceipt(9);
    const r1 = { ...base, tool_name: "sanna-ts" };
    const r2 = { ...base, tool_name: "sanna" };
    expect(computeFingerprints(r1).receipt_fingerprint).not.toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });

  // cv=9 excludes agent_identity (20-field formula)
  it("cv=9 excludes agent_identity from fingerprint (20-field formula)", () => {
    const base = buildBaseReceipt(9);
    const r1 = { ...base, agent_identity: { agent_session_id: "session-a" } };
    const r2 = { ...base, agent_identity: { agent_session_id: "session-b" } };
    expect(computeFingerprints(r1).receipt_fingerprint).toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });

  // cv=10 → 21-field formula (adds agent_identity_hash at field 21)
  it("cv=10 includes agent_identity in fingerprint (field 21)", () => {
    const base = buildBaseReceipt(10);
    const r1 = { ...base, agent_identity: { agent_session_id: "session-a" } };
    const r2 = { ...base, agent_identity: { agent_session_id: "session-b" } };
    expect(computeFingerprints(r1).receipt_fingerprint).not.toBe(
      computeFingerprints(r2).receipt_fingerprint,
    );
  });
});

// ── 9. Redaction marker shape ─────────────────────────────────────────

describe("Property 9: Redaction marker shape (Spec 2.11.1; cross-SDK)", () => {
  const FIXTURE_PATH = resolve(
    __dirname,
    "../../../spec/fixtures/gateway-redaction-vectors.json",
  );

  it("fixture file resolves at test time (submodule checked out)", () => {
    // spec/fixtures/gateway-redaction-vectors.json comes from the
    // sanna-protocol submodule; CI uses submodules:recursive. This
    // assertion catches a missed submodule checkout before the next test.
    expect(() => readFileSync(FIXTURE_PATH, "utf-8")).not.toThrow();
  });

  it(
    "marker shape matches spec/fixtures/gateway-redaction-vectors.json (cross-SDK byte-parity)",
    () => {
      const fixture = JSON.parse(
        readFileSync(FIXTURE_PATH, "utf-8"),
      ) as Record<string, unknown>;
      const markerVectors = fixture.marker_vectors as Array<
        Record<string, unknown>
      >;

      expect(markerVectors.length).toBeGreaterThan(0);
      let vectorsExercised = 0;

      for (const v of markerVectors) {
        if ("input" in v) {
          // Simple input: verify TS makeRedactionMarker matches the spec fixture
          const marker = makeRedactionMarker(v.input as string);
          const expected = v.expected_marker as {
            __redacted__: boolean;
            original_hash: string;
          };
          expect(marker.__redacted__, `vector ${v.vector_id}`).toBe(true);
          expect(marker.original_hash, `vector ${v.vector_id}`).toBe(
            expected.original_hash,
          );
          vectorsExercised++;
        } else if ("input_nfc" in v && "input_nfd" in v) {
          // NFC/NFD pair: both inputs must produce the same marker
          const markerNfc = makeRedactionMarker(v.input_nfc as string);
          const markerNfd = makeRedactionMarker(v.input_nfd as string);
          const expected = v.expected_marker_for_both as {
            __redacted__: boolean;
            original_hash: string;
          };
          expect(markerNfc.original_hash, `vector ${v.vector_id} (NFC)`).toBe(
            expected.original_hash,
          );
          expect(markerNfd.original_hash, `vector ${v.vector_id} (NFD)`).toBe(
            expected.original_hash,
          );
          vectorsExercised++;
        }
      }

      // Guard: ensure we actually exercised the fixture entries
      expect(vectorsExercised).toBeGreaterThanOrEqual(markerVectors.length);
    },
  );

  it(
    "marker shape is byte-stable across arbitrary string inputs (PBT)",
    () => {
      fc.assert(
        fc.property(jsonSafeText, (s) => {
          const marker = makeRedactionMarker(s);
          // Structural invariants
          expect(marker.__redacted__).toBe(true);
          expect(typeof marker.original_hash).toBe("string");
          expect(marker.original_hash).toHaveLength(64);
          expect(/^[0-9a-f]{64}$/.test(marker.original_hash)).toBe(true);
          // Content invariant: digest = SHA-256(NFC(s)) directly (no additional
          // normalization steps — makeRedactionMarker uses createHash directly,
          // not hashContent which also strips whitespace).
          const expected = createHash("sha256")
            .update(s.normalize("NFC"), "utf-8")
            .digest("hex");
          expect(marker.original_hash).toBe(expected);
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );

  it(
    "marker NFC-invariant: NFC and NFD inputs produce identical markers (PBT)",
    () => {
      fc.assert(
        fc.property(jsonSafeText, (s) => {
          const nfc = s.normalize("NFC");
          const nfd = s.normalize("NFD");
          // makeRedactionMarker NFC-normalizes internally; NFC and NFD
          // inputs must produce the same original_hash (spec §2.11.1).
          expect(makeRedactionMarker(nfc).original_hash).toBe(
            makeRedactionMarker(nfd).original_hash,
          );
        }),
        fcParams,
      );
    },
    PROPERTY_TIMEOUT_MS,
  );
});

// ── 10. Fingerprint cross-site parity ─────────────────────────────────

describe("Property 10: Fingerprint cross-site parity", () => {
  it(
    "10a: all consumer sites import computeFingerprints from ./receipt.js (static-analysis)",
    () => {
      // sanna-ts is centralized: every consumer of fingerprint computation
      // must import the canonical computeFingerprints from ./receipt.js.
      // This test catches drift where a consumer copies the function inline
      // (which would allow the copy to diverge from the canonical version).
      // In a standard ES module project, === reference equality across
      // imports is guaranteed by the module system, but the inline-copy
      // failure mode is not detectable at runtime — only static analysis
      // catches it.
      const consumers = [
        "verifier.ts",
        "aarm.ts",
        "redaction.ts",
        "bundle.ts",
      ];
      for (const file of consumers) {
        const src = readFileSync(resolve(SRC_DIR, file), "utf-8");
        // Each consumer must import computeFingerprints from ./receipt or ./receipt.js
        expect(
          src,
          `${file}: must import computeFingerprints from ./receipt.js`,
        ).toMatch(
          /import\s+\{[^}]*\bcomputeFingerprints\b[^}]*\}\s+from\s+["']\.\/receipt(\.js)?["']/,
        );
        // Negative: no inline function computeFingerprints declaration
        expect(
          src,
          `${file}: must NOT declare inline computeFingerprints function`,
        ).not.toMatch(
          /^\s*(export\s+)?(async\s+)?function\s+computeFingerprints\s*\(/m,
        );
      }
    },
  );

  it(
    "10b: redaction.ts emission path and direct computeFingerprints produce identical fingerprints",
    () => {
      // Build a receipt with real inputs/outputs so applyRedactionMarkers
      // has something to redact and recompute fingerprints from.
      // After applyRedactionMarkers, receipt.receipt_fingerprint is set by
      // calling the imported computeFingerprints. Calling computeFingerprints
      // again on the same updated receipt must return the same fingerprints —
      // proving both callers use the same canonical function.
      const receipt: Record<string, unknown> = {
        ...buildBaseReceipt(9),
        inputs: { context: "sensitive user data for san294-pbt-test" },
        outputs: { response: "AI response text" },
      };
      // Compute content hashes to match the inputs/outputs (mirrors what
      // generateReceipt would do; required for a well-formed receipt).
      receipt.context_hash = hashObj(receipt.inputs as Record<string, unknown>);
      receipt.output_hash = hashObj(receipt.outputs as Record<string, unknown>);

      // Apply redaction via the redaction.ts path
      const [updatedReceipt] = applyRedactionMarkers(receipt, ["arguments"]);

      // Direct computeFingerprints call on the updated receipt
      const directFp = computeFingerprints(
        updatedReceipt as Record<string, unknown>,
      );

      // Both paths must agree on the fingerprints
      expect(updatedReceipt.receipt_fingerprint).toBe(
        directFp.receipt_fingerprint,
      );
      expect(updatedReceipt.full_fingerprint).toBe(directFp.full_fingerprint);
    },
  );
});
