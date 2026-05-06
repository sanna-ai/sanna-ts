/**
 * SAN-406 PR 5: consume cross-SDK redaction-vectors fixture from sanna-protocol.
 *
 * The fixture (added to sanna-protocol in SAN-406 PR 3 at commit 95e87e5) is the
 * load-bearing cross-SDK conformance contract for com.sanna.anomaly extension
 * field-level redaction (spec Section 2.22.5). Both Python (sanna-repo PR 4 at
 * 0809568) and TypeScript (this file) MUST produce verdict matches for every
 * vector.
 *
 * These tests are INDEPENDENT of SAN-487. They call the helper + verifier
 * DIRECTLY without traversing the interceptor's emission path. The 6 end-to-end
 * interceptor tests in PR 2 (under describe.skip with SAN-487 cite) remain
 * skipped.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";

import { redactAttemptedField } from "../src/anomaly.js";
import { verifyInvocationAnomalyReceipt } from "../src/verifier-manifest.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const VECTORS_PATH = resolve(FIXTURES, "redaction-vectors.json");

// Bidirectional contract: SDK locks down the expected vector ID sets. If
// sanna-protocol later adds, renames, or removes a vector, this constant goes
// stale and the "vector ids match expected sets" canary fires. Update both
// sides (these lists AND the spec) under the same SAN ticket.
const EXPECTED_HELPER_VECTOR_IDS: string[] = [
  "helper-cli-full",
  "helper-cli-redacted",
  "helper-cli-hashes-only",
  "helper-mcp-full",
  "helper-mcp-redacted",
  "helper-mcp-hashes-only",
  "helper-http-full",
  "helper-http-redacted",
  "helper-http-hashes-only",
];
const EXPECTED_VERIFIER_VECTOR_IDS: string[] = [
  "verifier-cli-redacted-leaks-raw",
  "verifier-cli-hashes-only-leaks-raw",
  "verifier-mcp-redacted-leaks-raw",
  "verifier-mcp-hashes-only-leaks-raw",
  "verifier-http-redacted-leaks-raw",
  "verifier-http-hashes-only-leaks-raw",
];

interface HelperVector {
  id: string;
  description: string;
  event_type: string;
  field_name: string;
  content_mode: string;
  input: string;
  expected: string;
}

interface VerifierVector {
  id: string;
  description: string;
  event_type: string;
  field_name: string;
  content_mode: string;
  field_value: string;
  expected_check_status: string;
}

interface Fixture {
  version: string;
  san_ticket: string;
  spec_section: string;
  description: string;
  expected_check_name: string;
  helper_vectors: HelperVector[];
  verifier_vectors: VerifierVector[];
}

// Top-level read: vitest reports a clear collection error if the file is missing
// (functions as the hard fixture-presence canary; equivalent to PR 4's separate
// test_fixture_file_exists in Python but achieved via vitest collection-error
// semantics rather than a dedicated test).
const fixture: Fixture = JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));

/**
 * Build a minimal anomaly receipt structure for the marker check.
 *
 * The receipt has only the fields the verifier's marker-check entry path
 * requires:
 * - event_type: read by Check 10 and by ANOMALY_FIELD_BY_EVENT_TYPE in the
 *   marker check helper.
 * - content_mode: read by the marker check (early-return on full/null;
 *   otherwise validates markers).
 * - extensions["com.sanna.anomaly"][field_name]: the value the marker check
 *   inspects.
 * - extensions["com.sanna.anomaly"]["suppression_basis"]: required by the
 *   anomaly extension schema; included for forward-compat even though the
 *   marker check does not read it.
 *
 * No receipt_signature, fingerprint, correlation_id, etc. The verifier's
 * invocation-anomaly entry point does NOT do full schema validation; it
 * runs Check 10 + the marker check + Checks 11/12 (cross-receipt). With
 * receiptSet=null, Checks 11/12 emit WARN early-return; the marker check
 * fires before the early-return per PR 2 placement.
 */
function buildAnomalyReceipt(
  eventType: string,
  fieldName: string,
  contentMode: string,
  fieldValue: string,
): Record<string, unknown> {
  return {
    event_type: eventType,
    content_mode: contentMode,
    extensions: {
      "com.sanna.anomaly": {
        [fieldName]: fieldValue,
        suppression_basis: "constitution",
      },
    },
  };
}

describe("redaction-vectors fixture consumption (SAN-406 PR 5)", () => {
  it("fixture is well-formed", () => {
    expect(fixture.spec_section).toBe("2.22.5");
    expect(fixture.san_ticket).toBe("SAN-406");
    expect(fixture.expected_check_name).toBe("redaction_markers_correct"); // cross-SDK Check.name parity
    expect(fixture.helper_vectors).toHaveLength(9);
    expect(fixture.verifier_vectors).toHaveLength(6);
  });

  it("vector ids match expected sets (bidirectional contract)", () => {
    const actualHelper = fixture.helper_vectors.map((v) => v.id).slice().sort();
    const expectedHelper = [...EXPECTED_HELPER_VECTOR_IDS].sort();
    expect(actualHelper).toEqual(expectedHelper);

    const actualVerifier = fixture.verifier_vectors.map((v) => v.id).slice().sort();
    const expectedVerifier = [...EXPECTED_VERIFIER_VECTOR_IDS].sort();
    expect(actualVerifier).toEqual(expectedVerifier);
  });

  it.each(EXPECTED_HELPER_VECTOR_IDS)(
    "helper vector: %s -> redactAttemptedField(input, content_mode) === expected",
    (vectorId: string) => {
      const matching = fixture.helper_vectors.filter((v) => v.id === vectorId);
      expect(matching).toHaveLength(1);
      const vector = matching[0];

      const result = redactAttemptedField(vector.input, vector.content_mode);
      expect(result).toBe(vector.expected);
    },
  );

  it.each(EXPECTED_VERIFIER_VECTOR_IDS)(
    "verifier vector (NEGATIVE): %s -> marker check FAILS",
    (vectorId: string) => {
      const matching = fixture.verifier_vectors.filter((v) => v.id === vectorId);
      expect(matching).toHaveLength(1);
      const vector = matching[0];

      const receipt = buildAnomalyReceipt(
        vector.event_type,
        vector.field_name,
        vector.content_mode,
        vector.field_value,
      );
      const checks = verifyInvocationAnomalyReceipt(receipt, null);
      const markerCheck = checks.find((c) => c.name === fixture.expected_check_name);

      expect(markerCheck, `marker check ${fixture.expected_check_name} not emitted`).toBeDefined();
      expect(markerCheck?.status).toBe(vector.expected_check_status);
    },
  );

  it.each(EXPECTED_HELPER_VECTOR_IDS)(
    "derived positive verifier: %s -> marker PASS for non-full, no marker for full",
    (vectorId: string) => {
      // Each non-full helper_vector's `expected` value, when used as a receipt's
      // field_value with the same content_mode, MUST produce a marker check with
      // status=PASS. Full mode emits NO marker check. Materializes the derivation
      // rule documented in the fixture's verifier_vectors_doc field.
      const matching = fixture.helper_vectors.filter((v) => v.id === vectorId);
      const vector = matching[0];

      const receipt = buildAnomalyReceipt(
        vector.event_type,
        vector.field_name,
        vector.content_mode,
        vector.expected, // the COMPLIANT value per helper output
      );
      const checks = verifyInvocationAnomalyReceipt(receipt, null);
      const markerCheck = checks.find((c) => c.name === fixture.expected_check_name);

      if (vector.content_mode === "full") {
        // Full mode: verifier emits NO marker check (returns early on full/null).
        expect(markerCheck, `${vectorId} (full mode): marker check should NOT be emitted`).toBeUndefined();
      } else {
        expect(markerCheck, `${vectorId} (${vector.content_mode} mode): marker check expected`).toBeDefined();
        expect(markerCheck?.status).toBe("PASS");
      }
    },
  );
});
