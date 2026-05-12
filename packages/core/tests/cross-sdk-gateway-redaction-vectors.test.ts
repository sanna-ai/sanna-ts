/**
 * SAN-516 PR 3 of 3: consume cross-SDK gateway-redaction-vectors fixture from sanna-protocol.
 *
 * The fixture (added to sanna-protocol in SAN-516 PR 1 of 3 at commit
 * d69977132ba3be4f7a144c8e43a2ff1c65019c91) is the load-bearing cross-SDK
 * conformance contract for spec section 2.11.1 marker objects. Both the
 * Python SDK (sanna-repo at commit cd8b422 under SAN-516 PR 2 of 3) and the
 * TypeScript SDK (this file) MUST produce byte-identical output for the
 * marker_vectors / fix12 / apply_redaction vectors AND reject the
 * verifier_rejection_vectors with the stable umbrella error code
 * REDACTION_CLAIM_WITHOUT_MARKER.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync, existsSync } from "node:fs";

import {
  makeRedactionMarker,
  applyRedaction,
  type RedactionConfig,
} from "../src/redaction.js";
import { checkGatewayRedactionMarkersCorrect } from "../src/verifier.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const VECTORS_PATH = resolve(FIXTURES, "gateway-redaction-vectors.json");

const EXPECTED_MARKER_VECTOR_IDS = [
  "marker-ascii-simple",
  "marker-empty-string",
  "marker-multiline-text",
  "marker-unicode-nfc-vs-nfd",
];
const EXPECTED_FIX12_VECTOR_IDS = ["fix12-pre-existing-marker-simple"];
const EXPECTED_APPLY_REDACTION_VECTOR_IDS = [
  "apply-arguments-only",
  "apply-result-text-only",
  "apply-default-both-fields",
  "apply-disabled-no-op",
  "apply-empty-content",
];
const EXPECTED_VERIFIER_REJECTION_VECTOR_IDS = [
  "reject-content-mode-redacted-no-markers",
  "reject-marker-missing-original-hash",
  "reject-content-mode-full-with-markers",
];

function loadVectors(): any {
  if (!existsSync(VECTORS_PATH)) {
    throw new Error(
      `Fixture file missing at ${VECTORS_PATH}. ` +
        `Run \`git submodule update --init --recursive\` if testing locally.`,
    );
  }
  return JSON.parse(readFileSync(VECTORS_PATH, "utf-8"));
}

describe("SAN-516 PR 3 of 3: cross-SDK gateway-redaction vectors (TS side)", () => {
  it("test_fixture_file_exists -- hard canary; CI sets submodules: recursive", () => {
    expect(existsSync(VECTORS_PATH)).toBe(true);
  });

  it("test_fixture_vector_ids_match_expected_sets -- canary for spec drift", () => {
    const data = loadVectors();
    expect(data.marker_vectors.map((v: any) => v.vector_id)).toEqual(EXPECTED_MARKER_VECTOR_IDS);
    expect(data.fix12_injection_guard_vectors.map((v: any) => v.vector_id)).toEqual(EXPECTED_FIX12_VECTOR_IDS);
    expect(data.apply_redaction_vectors.map((v: any) => v.vector_id)).toEqual(EXPECTED_APPLY_REDACTION_VECTOR_IDS);
    expect(data.verifier_rejection_vectors.map((v: any) => v.vector_id)).toEqual(EXPECTED_VERIFIER_REJECTION_VECTOR_IDS);
  });

  describe("marker_vectors -- byte parity with Python makeRedactionMarker", () => {
    const data = loadVectors();
    it.each(EXPECTED_MARKER_VECTOR_IDS)("marker vector %s", (vectorId) => {
      const vector = data.marker_vectors.find((v: any) => v.vector_id === vectorId)!;
      if (vectorId === "marker-unicode-nfc-vs-nfd") {
        const markerNfc = makeRedactionMarker(vector.input_nfc);
        const markerNfd = makeRedactionMarker(vector.input_nfd);
        const expected = vector.expected_marker_for_both;
        expect(markerNfc).toEqual(expected);
        expect(markerNfd).toEqual(expected);
        expect(markerNfc).toEqual(markerNfd);
      } else {
        const marker = makeRedactionMarker(vector.input);
        expect(marker).toEqual(vector.expected_marker);
      }
    });
  });

  describe("fix12_injection_guard_vectors -- spec 2.11.4 pre-existing marker re-redaction", () => {
    const data = loadVectors();
    it.each(EXPECTED_FIX12_VECTOR_IDS)("fix12 vector %s", (vectorId) => {
      const vector = data.fix12_injection_guard_vectors.find((v: any) => v.vector_id === vectorId)!;
      const receipt: Record<string, unknown> = {
        inputs: { context: structuredClone(vector.pre_existing_marker_input) },
        outputs: { response: "raw" },
      };
      const config: RedactionConfig = { enabled: true, mode: "hash_only", fields: ["arguments"] };
      const [outReceipt, redactedPaths] = applyRedaction(receipt, config);
      expect((outReceipt.inputs as Record<string, unknown>).context).toEqual(
        vector.expected_marker_after_re_redaction,
      );
      expect(redactedPaths).toContain("inputs.context");
    });
  });

  describe("apply_redaction_vectors -- field-level marker substitution byte parity", () => {
    const data = loadVectors();
    it.each(EXPECTED_APPLY_REDACTION_VECTOR_IDS)("apply_redaction vector %s", (vectorId) => {
      const vector = data.apply_redaction_vectors.find((v: any) => v.vector_id === vectorId)!;
      const config: RedactionConfig = {
        enabled: vector.redaction_config.enabled,
        mode: vector.redaction_config.mode ?? "hash_only",
        fields: vector.redaction_config.fields ?? ["arguments", "result_text"],
      };
      const inputReceipt = structuredClone(vector.input_receipt_partial);
      const [outReceipt, redactedPaths] = applyRedaction(
        inputReceipt as Record<string, unknown>,
        config,
      );

      expect((outReceipt.inputs as Record<string, unknown>).context).toEqual(
        vector.expected_inputs_context_after_redaction,
      );
      expect((outReceipt.outputs as Record<string, unknown>).response).toEqual(
        vector.expected_outputs_response_after_redaction,
      );
      expect([...redactedPaths].sort()).toEqual([...vector.expected_redacted_fields].sort());
    });
  });

  describe("verifier_rejection_vectors -- TS verifier rejects with stable umbrella code", () => {
    const data = loadVectors();
    it.each(EXPECTED_VERIFIER_REJECTION_VECTOR_IDS)("rejection vector %s", (vectorId) => {
      const vector = data.verifier_rejection_vectors.find((v: any) => v.vector_id === vectorId)!;
      const receipt = structuredClone(vector.input_receipt_partial) as Record<string, unknown>;
      const errors = checkGatewayRedactionMarkersCorrect(receipt);

      expect(errors.length).toBeGreaterThan(0);
      const expectedCode = vector.expected_error_code;
      const anyMatch = errors.some((err) => err.includes(expectedCode));
      expect(
        anyMatch,
        `Verifier rejected ${vectorId} but errors do not contain stable code '${expectedCode}'. Got: ${JSON.stringify(errors)}`,
      ).toBe(true);
    });
  });
});
