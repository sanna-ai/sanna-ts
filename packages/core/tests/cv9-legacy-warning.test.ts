/**
 * SAN-371: cv=9 receipts emit CV9_LEGACY-prefixed informational warning.
 *
 * Receipts at cv=9 are valid (verifier returns valid=true) but the warnings
 * array contains a string starting with 'CV9_LEGACY:' to signal partial R6
 * conformance. Mirrors Python tests/test_san371_cv9_legacy.py.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";

import { generateReceipt, signReceipt } from "../src/receipt.js";
import { verifyReceipt } from "../src/verifier.js";
import { loadPrivateKey, loadPublicKey } from "../src/crypto.js";

const SPEC_FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const PRIV = loadPrivateKey(resolve(SPEC_FIXTURES, "keypairs/test-author.key"));
const PUB = loadPublicKey(resolve(SPEC_FIXTURES, "keypairs/test-author.pub"));

describe("SAN-371: CV9_LEGACY warning on cv=9 verifier output", () => {
  it("cv=9 generated receipt emits exactly one CV9_LEGACY-prefixed warning", () => {
    const receipt = signReceipt(
      generateReceipt({
        correlation_id: "san-371-ts-cv9",
        inputs: { query: "test" },
        outputs: { response: "test" },
        checks: [],
        enforcementSurface: "middleware",
        invariantsScope: "full",
      }) as unknown as Record<string, unknown>,
      PRIV,
      "test-author@sanna.dev",
    );
    expect(receipt.checks_version).toBe("9");

    const result = verifyReceipt(receipt, PUB);
    expect(result.valid).toBe(true);
    const legacy = result.warnings.filter((w) => w.startsWith("CV9_LEGACY:"));
    expect(legacy).toHaveLength(1);
  });

  it("cv=10 generated receipt emits no CV9_LEGACY warning", () => {
    const receipt = signReceipt(
      generateReceipt({
        correlation_id: "san-371-ts-cv10",
        inputs: { query: "test" },
        outputs: { response: "test" },
        checks: [],
        enforcementSurface: "gateway",
        invariantsScope: "full",
        agent_identity: { agent_session_id: "san-371-ts-session-cv10" },
      }) as unknown as Record<string, unknown>,
      PRIV,
      "test-author@sanna.dev",
    );
    expect(receipt.checks_version).toBe("10");

    const result = verifyReceipt(receipt, PUB);
    expect(result.valid).toBe(true);
    const legacy = result.warnings.filter((w) => w.startsWith("CV9_LEGACY:"));
    expect(legacy).toHaveLength(0);
  });

  it("archive cv=9 fixture emits CV9_LEGACY warning", () => {
    const fixturePath = resolve(
      SPEC_FIXTURES,
      "receipts/archive/v1.4/full-featured.json",
    );
    const archive = JSON.parse(readFileSync(fixturePath, "utf-8"));
    expect(archive.checks_version).toBe("9");

    // No public key: archive fixture was signed with an older keypair.
    // Verify schema + fingerprint + CV9_LEGACY emission; signature check skipped.
    const result = verifyReceipt(archive);
    expect(result.valid).toBe(true);
    const legacy = result.warnings.filter((w: string) =>
      w.startsWith("CV9_LEGACY:"),
    );
    expect(legacy).toHaveLength(1);
  });
});
