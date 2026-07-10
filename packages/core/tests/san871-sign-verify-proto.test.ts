/**
 * SAN-871 regression: signReceipt must use a proto-safe canonicalizer.
 *
 * SAN-818 fixed the __proto__ canonical-JSON signature-integrity defect in
 * packages/core/src/hashing.ts (normalizeFloats now uses Object.fromEntries,
 * proto-safe). It was INCOMPLETE: receipt.ts defined a LOCAL sanitizeForSigning
 * (shadowing the proto-safe one exported from crypto.ts) that still used the
 * proto-unsafe `result[k] = ...` bracket-assignment accumulation pattern.
 * signReceipt used this local, proto-unsafe function while verifyReceipt used
 * the proto-safe one -- so a receipt whose content legitimately contains a
 * __proto__ own-key was signed over bytes that DROPPED __proto__, but
 * verified over bytes that KEPT it. Self-verification of such a receipt
 * failed (fails closed -- a correctness/coherence bug, not a second hole).
 *
 * This file proves the bug (RED on pre-fix main) and proves the fix (GREEN
 * post-fix), plus guards the SAN-818 verify-side fix against regression.
 *
 * PROTOTYPE-POLLUTION HYGIENE: this file deliberately constructs objects
 * with an own `__proto__` key. It does so ONLY via JSON.parse (never via
 * Object.assign, spread, or bracket/dot assignment onto a shared or global
 * object), and reads such keys ONLY via
 * Object.prototype.hasOwnProperty.call. No pollution of Object.prototype or
 * any shared object occurs as a result of running this file.
 */
import { describe, it, expect, afterAll } from "vitest";
import {
  generateKeypair,
  generateReceipt,
  signReceipt,
  verifyReceipt,
  canonicalize,
  verify,
} from "../src/index.js";

describe("SAN-871: signReceipt / verifyReceipt proto-safety", () => {
  const kp = generateKeypair();

  // Own __proto__ key can only be produced via JSON.parse (or
  // Object.defineProperty / Object.fromEntries) -- an object LITERAL cannot
  // create an own __proto__ key (`{"__proto__": x}` sets the prototype).
  const inputs = JSON.parse(
    '{"payload":"ok","__proto__":{"note":"benign"}}',
  ) as Record<string, unknown>;

  it("test fixture sanity: inputs has __proto__ as an OWN key", () => {
    expect(Object.prototype.hasOwnProperty.call(inputs, "__proto__")).toBe(true);
  });

  it("A. SELF-CONSISTENCY (negative control, build-independent): sign bytes and verify bytes agree on a __proto__-bearing receipt", () => {
    const r = generateReceipt({
      correlation_id: "san871-a",
      inputs,
      outputs: { r: 1 },
      checks: [],
    });
    const signed = signReceipt(r, kp.privateKey, "san871-test");

    // Reconstruct the verify bytes exactly as checkSignature does: clone,
    // blank the signature, canonicalize, verify -- using the library's own
    // exports only.
    const clone = structuredClone(signed);
    (clone.receipt_signature as { signature: string }).signature = "";
    const verifyBytes = Buffer.from(canonicalize(clone), "utf-8");

    const valid = verify(
      verifyBytes,
      (signed.receipt_signature as { signature: string }).signature,
      kp.publicKey,
    );
    expect(valid).toBe(true);
  });

  it("B. SELF-CONSISTENCY (full path): verifyReceipt() accepts its own signed __proto__-bearing receipt", () => {
    const r = generateReceipt({
      correlation_id: "san871-b",
      inputs,
      outputs: { r: 1 },
      checks: [],
    });
    const signed = signReceipt(r, kp.privateKey, "san871-test");

    const result = verifyReceipt(signed, kp.publicKey);
    expect(result.valid).toBe(true);
  });

  it("C. TAMPER-IN-TRANSIT guard (SAN-818 verify-side fix; GREEN both pre- and post-SAN-871): a __proto__ injected after signing is detected", () => {
    // Sign a CLEAN receipt (no __proto__ anywhere).
    const cleanInputs = { payload: "ok" };
    const r = generateReceipt({
      correlation_id: "san871-c",
      inputs: cleanInputs,
      outputs: { r: 1 },
      checks: [],
    });
    const signed = signReceipt(r, kp.privateKey, "san871-test");

    // Tamper: inject a __proto__ own-key into inputs via JSON string
    // surgery + JSON.parse, keeping the original (now-stale) signature.
    const tamperedJson = JSON.stringify(signed).replace(
      '"payload":"ok"',
      '"payload":"ok","__proto__":{"note":"injected"}',
    );
    const tampered = JSON.parse(tamperedJson) as Record<string, unknown>;
    expect(
      Object.prototype.hasOwnProperty.call(
        tampered.inputs as object,
        "__proto__",
      ),
    ).toBe(true);

    const result = verifyReceipt(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
  });

  afterAll(() => {
    // Prove no pollution leaked onto Object.prototype / a fresh object.
    expect(({} as Record<string, unknown>).note).toBeUndefined();
  });
});
