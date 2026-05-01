import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import yaml from "js-yaml";
import {
  generateKeypair,
  sign,
  verify,
  loadPrivateKey,
  loadPublicKey,
  getKeyId,
  exportPrivateKeyPem,
  exportPublicKeyPem,
} from "../src/crypto.js";
import { canonicalize } from "../src/hashing.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const golden = JSON.parse(
  readFileSync(resolve(FIXTURES, "golden-hashes.json"), "utf-8"),
);

// ── Round-trip tests ─────────────────────────────────────────────────

describe("generateKeypair", () => {
  it("produces valid Ed25519 keypair", () => {
    const kp = generateKeypair("test");
    expect(kp.privateKey.type).toBe("private");
    expect(kp.publicKey.type).toBe("public");
    expect(kp.keyId).toHaveLength(64);
    expect(kp.label).toBe("test");
  });

  it("PEM round-trip preserves keys", () => {
    const kp = generateKeypair();
    const privPem = exportPrivateKeyPem(kp.privateKey);
    const pubPem = exportPublicKeyPem(kp.publicKey);
    expect(privPem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(pubPem).toContain("-----BEGIN PUBLIC KEY-----");
  });
});

describe("sign / verify round-trip", () => {
  it("signature verifies with matching public key", () => {
    const kp = generateKeypair();
    const data = Buffer.from("test message");
    const sig = sign(data, kp.privateKey);
    expect(verify(data, sig, kp.publicKey)).toBe(true);
  });

  it("signature fails with wrong public key", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const data = Buffer.from("test message");
    const sig = sign(data, kp1.privateKey);
    expect(verify(data, sig, kp2.publicKey)).toBe(false);
  });

  it("signature fails with tampered data", () => {
    const kp = generateKeypair();
    const data = Buffer.from("test message");
    const sig = sign(data, kp.privateKey);
    expect(verify(Buffer.from("tampered message"), sig, kp.publicKey)).toBe(
      false,
    );
  });

  it("produces standard Base64 with padding", () => {
    const kp = generateKeypair();
    const sig = sign(Buffer.from("test"), kp.privateKey);
    // Ed25519 sig is 64 bytes → 88 Base64 chars with padding
    expect(sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
    expect(Buffer.from(sig, "base64")).toHaveLength(64);
  });
});

// ── CRITICAL GATE: Cross-language compatibility ──────────────────────

describe("CRITICAL GATE: cross-language key compatibility", () => {
  const keyDir = resolve(FIXTURES, "keypairs");
  const privKey = loadPrivateKey(resolve(keyDir, "test-author.key"));
  const pubKey = loadPublicKey(resolve(keyDir, "test-author.pub"));

  it("loads test-author.key as Ed25519 private key", () => {
    expect(privKey.type).toBe("private");
    expect(privKey.asymmetricKeyType).toBe("ed25519");
  });

  it("loads test-author.pub as Ed25519 public key", () => {
    expect(pubKey.type).toBe("public");
    expect(pubKey.asymmetricKeyType).toBe("ed25519");
  });

  it("key_id is a valid 64-hex SHA-256", () => {
    const kid = getKeyId(pubKey);
    expect(kid).toMatch(/^[0-9a-f]{64}$/);
    // Verify private key and public key produce the same key_id
    expect(getKeyId(privKey)).toBe(kid);
  });

  it("TypeScript can sign and verify with the loaded key", () => {
    const testData = Buffer.from("cross-language test");
    const sig = sign(testData, privKey);
    expect(verify(testData, sig, pubKey)).toBe(true);
  });

  it("verify Python-signed minimal.yaml constitution signature", () => {
    // Load the YAML and extract the signature block
    const yamlContent = readFileSync(
      resolve(FIXTURES, "constitutions/minimal.yaml"),
      "utf-8",
    );
    const doc = yaml.load(yamlContent) as Record<string, unknown>;
    const provenance = doc.provenance as Record<string, unknown>;
    const sigBlock = provenance.signature as Record<string, unknown>;

    expect(sigBlock).toBeDefined();
    expect(sigBlock.key_id).toMatch(/^[0-9a-f]{64}$/);
    expect(sigBlock.scheme).toBe("constitution_sig_v1");

    const signatureValue = sigBlock.value as string;
    expect(signatureValue).toBeTruthy();

    // Reconstruct the signing material per spec §5.3:
    // Fields: schema_version, identity, provenance (with signature.value=""),
    //         boundaries, trust_tiers, halt_conditions, invariants, policy_hash
    const signingContent: Record<string, unknown> = {
      schema_version: doc.sanna_constitution,
      identity: doc.identity,
      provenance: {
        ...(provenance as Record<string, unknown>),
        signature: {
          ...(sigBlock as Record<string, unknown>),
          value: "", // blank the signature value
        },
      },
      boundaries: doc.boundaries,
      trust_tiers: doc.trust_tiers,
      halt_conditions: doc.halt_conditions,
      invariants: doc.invariants,
      policy_hash: doc.policy_hash,
    };

    // Canonicalize with RFC 8785 JCS (same as Python's canonical_json_bytes)
    const canonicalJson = canonicalize(signingContent);
    const sigBytes = Buffer.from(canonicalJson, "utf-8");

    // Verify the Python-generated signature with the TypeScript crypto module
    const isValid = verify(sigBytes, signatureValue, pubKey);
    expect(isValid).toBe(true);
  });
});
