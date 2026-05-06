/**
 * SAN-486: consume cross-SDK bundle-trust-vectors fixture from sanna-protocol.
 *
 * The fixture (added to sanna-protocol in SAN-403 PR 3 of 3 at commit 6795979) is the
 * load-bearing cross-SDK conformance contract for the bundle verifier trust anchor.
 * Both the Python SDK (sanna-repo via SAN-485) and the TypeScript SDK (this file)
 * MUST produce verdict matches for every vector.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import AdmZip from "adm-zip";

import { verifyBundle } from "../src/bundle.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const VECTORS_PATH = resolve(FIXTURES, "bundle-trust-vectors.json");

// Bidirectional contract: SDK locks down the expected vector ID set. If sanna-protocol
// later adds, renames, or removes a vector, this constant goes stale and the
// "vector ids match expected set" canary fires. Update both sides (this list AND the
// spec) under the same SAN ticket. Plain string[] (not `as const`) keeps `it.each`
// typing simple; the bidirectional canary is content-comparison, not type-comparison.
const EXPECTED_VECTOR_IDS: string[] = [
  "genuine_no_anchor",
  "genuine_anchor_match",
  "genuine_anchor_excluding",
  "genuine_empty_anchor_fails_closed",
  "forged_no_anchor_self_consistent",
  "forged_anchored_genuine_only_caught",
  "forged_anchored_attacker_passes_sanity",
];

interface BundleTrustVector {
  id: string;
  bundle: "genuine" | "forged";
  trusted_key_ids: string[] | null;
  expect: { valid: boolean; trust_anchored: boolean };
  rationale?: string;
}

interface BundleTrustVectorsFixture {
  spec_version: string;
  san_ticket: string;
  description: string;
  genuine_key_id: string;
  attacker_key_id: string;
  bundles: { genuine: string; forged: string };
  vectors: BundleTrustVector[];
}

// Top-level read: vitest reports a clear collection error if the file is missing
// (functions as the hard fixture-presence canary; equivalent to Python's separate
// test_fixture_file_exists in SAN-485 but achieved via vitest's collection-error
// semantics rather than a dedicated test).
const fixture: BundleTrustVectorsFixture = JSON.parse(
  readFileSync(VECTORS_PATH, "utf-8"),
);

describe("bundle trust anchor cross-SDK vectors (SAN-486 / SAN-403)", () => {
  it("vectors file is well-formed", () => {
    expect(fixture.spec_version).toBe("1.5");
    expect(fixture.san_ticket).toBe("SAN-403");
    expect(fixture.vectors).toHaveLength(7);
    expect(fixture.genuine_key_id).toHaveLength(64);
    expect(fixture.attacker_key_id).toHaveLength(64);
    expect(fixture.genuine_key_id).not.toBe(fixture.attacker_key_id);
    expect(fixture.bundles.genuine.endsWith("genuine.bundle.zip")).toBe(true);
    expect(fixture.bundles.forged.endsWith("forged.bundle.zip")).toBe(true);
  });

  it("vector ids match expected set (bidirectional contract)", () => {
    // Catches drift in either direction:
    // - Spec adds/renames/drops a vector -> SDK CI fails until EXPECTED_VECTOR_IDS
    //   is updated AND a corresponding test handler lands.
    // - SDK falls behind the spec -> same failure surface.
    // Governance-load-bearing: the SDK is the consumer of the spec contract, and
    // CI failures here are the right place to discover drift, not silently passing.
    const actualIds = fixture.vectors.map((v) => v.id).slice().sort();
    const expectedIds = [...EXPECTED_VECTOR_IDS].sort();
    expect(actualIds).toEqual(expectedIds);
  });

  it("genuine bundle internally references genuine_key_id", () => {
    const bundlePath = resolve(__dirname, "../../..", "spec", fixture.bundles.genuine);
    const zip = new AdmZip(bundlePath);
    const receiptEntry = zip.getEntry("receipt.json");
    if (!receiptEntry) throw new Error("genuine bundle missing receipt.json");
    const receipt = JSON.parse(receiptEntry.getData().toString("utf-8")) as Record<
      string,
      unknown
    >;
    const sig = receipt.receipt_signature as Record<string, unknown>;
    expect(sig.key_id).toBe(fixture.genuine_key_id);

    const pubEntries = zip
      .getEntries()
      .filter(
        (e) => e.entryName.startsWith("public_keys/") && e.entryName.endsWith(".pub"),
      );
    expect(pubEntries).toHaveLength(1);
    expect(pubEntries[0].entryName).toContain(fixture.genuine_key_id);
  });

  it("forged bundle internally references attacker_key_id", () => {
    const bundlePath = resolve(__dirname, "../../..", "spec", fixture.bundles.forged);
    const zip = new AdmZip(bundlePath);
    const receiptEntry = zip.getEntry("receipt.json");
    if (!receiptEntry) throw new Error("forged bundle missing receipt.json");
    const receipt = JSON.parse(receiptEntry.getData().toString("utf-8")) as Record<
      string,
      unknown
    >;
    const sig = receipt.receipt_signature as Record<string, unknown>;
    expect(sig.key_id).toBe(fixture.attacker_key_id);

    const pubEntries = zip
      .getEntries()
      .filter(
        (e) => e.entryName.startsWith("public_keys/") && e.entryName.endsWith(".pub"),
      );
    expect(pubEntries).toHaveLength(1);
    expect(pubEntries[0].entryName).toContain(fixture.attacker_key_id);
  });

  it.each(EXPECTED_VECTOR_IDS)("vector: %s", (vectorId: string) => {
    const matching = fixture.vectors.filter((v) => v.id === vectorId);
    expect(matching).toHaveLength(1);
    const vector = matching[0];

    const bundlePath = resolve(
      __dirname,
      "../../..",
      "spec",
      fixture.bundles[vector.bundle],
    );
    const trusted =
      vector.trusted_key_ids === null ? null : new Set(vector.trusted_key_ids);

    const result = verifyBundle(bundlePath, true, trusted);

    if (result.valid !== vector.expect.valid) {
      const failingChecks = result.checks
        .filter((c) => !c.passed)
        .map((c) => `${c.name}: ${c.detail}`);
      throw new Error(
        `vector ${vectorId}: valid mismatch -- expected ${vector.expect.valid}, got ${result.valid}; failing checks: ${JSON.stringify(failingChecks)}`,
      );
    }
    expect(result.trust_anchored).toBe(vector.expect.trust_anchored);
  });
});
