/**
 * Sanna Protocol -- Redaction module (SAN-250)
 *
 * Spec section 2.11.1 marker objects: {__redacted__: true, original_hash: '<sha256-hex>'}
 * Cross-SDK byte-identical with sanna-repo's src/sanna/redaction.py.
 */

import { createHash } from "node:crypto";
import { hashObj } from "./hashing.js";
import { computeFingerprints } from "./receipt.js";

// ── Types ────────────────────────────────────────────────────────────

export interface RedactionMarker {
  __redacted__: true;
  original_hash: string;
}

export interface RedactionConfig {
  enabled: boolean;
  mode?: "hash_only";
  fields?: ReadonlyArray<"arguments" | "result_text">;
}

// ── Python-equivalent JSON serialization ─────────────────────────────

// Mirrors Python's json.dumps with ensure_ascii=True.
// Non-ASCII codepoints get \uXXXX (BMP) or surrogate pair (SMP) escape.
function _escapeStringPython(s: string): string {
  let result = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (code === 0x22) result += '\\"';
    else if (code === 0x5c) result += "\\\\";
    else if (code === 0x08) result += "\\b";
    else if (code === 0x09) result += "\\t";
    else if (code === 0x0a) result += "\\n";
    else if (code === 0x0c) result += "\\f";
    else if (code === 0x0d) result += "\\r";
    else if (code < 0x20 || code > 0x7e) {
      if (code <= 0xffff) {
        result += "\\u" + code.toString(16).padStart(4, "0");
      } else {
        const high = ((code - 0x10000) >> 10) + 0xd800;
        const low = ((code - 0x10000) & 0x3ff) + 0xdc00;
        result += "\\u" + high.toString(16).padStart(4, "0") + "\\u" + low.toString(16).padStart(4, "0");
      }
    } else {
      result += ch;
    }
  }
  result += '"';
  return result;
}

// Byte-identical to Python's json.dumps(value, sort_keys=True) with
// default separators (', ', ': ') and ensure_ascii=True.
// Required for FIX-12 cross-SDK parity of pre-existing-marker re-serialization.
export function stringifyPythonEquivalent(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!isFinite(value)) return "null"; // Python raises ValueError, but fallback for safety
    return String(value);
  }
  if (typeof value === "string") {
    return _escapeStringPython(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stringifyPythonEquivalent(v)).join(", ") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => `${_escapeStringPython(k)}: ${stringifyPythonEquivalent(obj[k])}`);
    return "{" + pairs.join(", ") + "}";
  }
  return "null";
}

// ── Public: marker construction ──────────────────────────────────────

/**
 * Produce a spec section 2.11.1 marker object.
 * Byte-identical with Python's _make_redaction_marker:
 *   normalized = unicodedata.normalize("NFC", original_value)
 *   digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
 */
export function makeRedactionMarker(value: string): RedactionMarker {
  const normalized = value.normalize("NFC");
  const digest = createHash("sha256").update(normalized, "utf-8").digest("hex");
  return { __redacted__: true, original_hash: digest };
}

// ── Internal: apply markers and recompute hashes ──────────────────────

/**
 * Internal engine. Mirrors Python's _apply_redaction_markers line-by-line.
 * Applies spec section 2.11.1 markers to inputs.context and/or outputs.response,
 * then recomputes context_hash, output_hash, redacted_fields, and fingerprints.
 * Mutates receipt in-place (matches Python dict mutation pattern).
 */
export function applyRedactionMarkers(
  receipt: Record<string, unknown>,
  redactionFields: string[],
): [Record<string, unknown>, string[]] {
  const redactedPaths: string[] = [];

  // "arguments" field maps to inputs.context (mirrors Python redaction_fields)
  if (redactionFields.includes("arguments")) {
    const inputsObj = receipt.inputs as Record<string, unknown> | undefined;
    if (inputsObj) {
      const ctx = inputsObj.context;
      if (ctx) {
        if (
          typeof ctx === "object" &&
          ctx !== null &&
          (ctx as Record<string, unknown>).__redacted__ === true
        ) {
          // FIX-12 (spec section 2.11.4): pre-existing marker dict -- re-redact via
          // Python-equivalent json.dumps(sort_keys=True, ensure_ascii=True) serialization.
          const serialized = stringifyPythonEquivalent(ctx);
          inputsObj.context = makeRedactionMarker(serialized);
          redactedPaths.push("inputs.context");
        } else if (typeof ctx === "string") {
          inputsObj.context = makeRedactionMarker(ctx);
          redactedPaths.push("inputs.context");
        }
      }
    }
  }

  // "result_text" field maps to outputs.response
  if (redactionFields.includes("result_text")) {
    const outputsObj = receipt.outputs as Record<string, unknown> | undefined;
    if (outputsObj) {
      const resp = outputsObj.response;
      if (resp) {
        if (
          typeof resp === "object" &&
          resp !== null &&
          (resp as Record<string, unknown>).__redacted__ === true
        ) {
          // FIX-12: pre-existing marker dict in outputs.response
          const serialized = stringifyPythonEquivalent(resp);
          outputsObj.response = makeRedactionMarker(serialized);
          redactedPaths.push("outputs.response");
        } else if (typeof resp === "string") {
          outputsObj.response = makeRedactionMarker(resp);
          redactedPaths.push("outputs.response");
        }
      }
    }
  }

  if (redactedPaths.length === 0) {
    return [receipt, redactedPaths];
  }

  // Recompute content hashes from marker-bearing inputs/outputs
  const updatedInputs = (receipt.inputs ?? {}) as Record<string, unknown>;
  const updatedOutputs = (receipt.outputs ?? {}) as Record<string, unknown>;
  receipt.context_hash = hashObj(updatedInputs);
  receipt.output_hash = hashObj(updatedOutputs);

  // Record redaction metadata
  receipt.redacted_fields = redactedPaths;

  // Recompute fingerprints (cv-dispatched; mirrors Python's inline formula)
  const { receipt_fingerprint, full_fingerprint } = computeFingerprints(receipt);
  receipt.receipt_fingerprint = receipt_fingerprint;
  receipt.full_fingerprint = full_fingerprint;

  return [receipt, redactedPaths];
}

// ── Public: applyRedaction wrapper ───────────────────────────────────

/**
 * Apply redaction markers to a receipt according to the provided config.
 * Returns [updatedReceipt, redactedPaths].
 * If config.enabled is false, returns the receipt unchanged with empty paths.
 */
export function applyRedaction(
  receipt: Record<string, unknown>,
  config: RedactionConfig,
): [Record<string, unknown>, string[]] {
  if (!config.enabled) {
    return [receipt, []];
  }
  return applyRedactionMarkers(
    receipt,
    (config.fields as string[] | undefined) ?? ["arguments", "result_text"],
  );
}
