import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import AdmZip from "adm-zip";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  signConstitution,
  saveConstitution,
  loadConstitution,
  generateReceipt,
  signReceipt,
  createBundle,
  verifyBundle,
} from "../src/index.js";
import type { Constitution, CheckResult } from "../src/types.js";

function makeConstitution(): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-bundle-agent",
      domain: "testing",
      description: "Bundle test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test boundary", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [
      { id: "INV_NO_FABRICATION", rule: "No fabrication", enforcement: "halt", check: null },
    ],
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
  };
}

function makeSignedReceipt(
  keypair: ReturnType<typeof generateKeypair>,
  constitution: Constitution,
): Record<string, unknown> {
  const checks: CheckResult[] = [
    { check_id: "C1", name: "Test Check", passed: true, severity: "info", evidence: null },
  ];
  const receipt = generateReceipt({
    correlation_id: "bundle-test-001",
    inputs: { query: "test" },
    outputs: { response: "test result" },
    checks,
    constitution_ref: {
      document_id: `${constitution.identity.agent_name}/1.0`,
      policy_hash: constitution.policy_hash,
    },
  });
  signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test@sanna.dev");
  return receipt as unknown as Record<string, unknown>;
}

describe("Bundle", () => {
  let tmpDir: string;
  let keypair: ReturnType<typeof generateKeypair>;
  let constitution: Constitution;
  let receiptPath: string;
  let constitutionPath: string;
  let publicKeyPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-bundle-test-"));
    keypair = generateKeypair("test");

    // Sign constitution
    constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
    constitutionPath = join(tmpDir, "constitution.yaml");
    saveConstitution(constitution, constitutionPath);

    // Write public key
    publicKeyPath = join(tmpDir, "test.pub");
    writeFileSync(publicKeyPath, exportPublicKeyPem(keypair.publicKey));

    // Generate and sign receipt
    const receipt = makeSignedReceipt(keypair, constitution);
    receiptPath = join(tmpDir, "receipt.json");
    writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
  });

  afterEach(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* */ }
  });

  describe("createBundle", () => {
    it("should create a valid bundle zip", () => {
      const outputPath = join(tmpDir, "test.bundle.zip");
      const result = createBundle({
        receiptPath,
        constitutionPath,
        publicKeyPath,
        outputPath,
        description: "Test bundle",
      });
      expect(result).toContain("test.bundle.zip");

      const zip = new AdmZip(outputPath);
      const entries = zip.getEntries().map((e) => e.entryName);
      expect(entries).toContain("receipt.json");
      expect(entries).toContain("constitution.yaml");
      expect(entries).toContain("metadata.json");
      expect(entries.some((e) => e.startsWith("public_keys/") && e.endsWith(".pub"))).toBe(true);
    });

    it("should include metadata with correct fields", () => {
      const outputPath = join(tmpDir, "test.bundle.zip");
      createBundle({
        receiptPath,
        constitutionPath,
        publicKeyPath,
        outputPath,
        description: "My description",
      });

      const zip = new AdmZip(outputPath);
      const metadata = JSON.parse(zip.getEntry("metadata.json")!.getData().toString("utf-8"));
      expect(metadata.bundle_format_version).toBe("1.0.0");
      expect(metadata.description).toBe("My description");
      expect(metadata.created_at).toBeTruthy();
    });

    it("should throw if receipt file doesn't exist", () => {
      expect(() =>
        createBundle({
          receiptPath: join(tmpDir, "nonexistent.json"),
          constitutionPath,
          publicKeyPath,
          outputPath: join(tmpDir, "out.zip"),
        }),
      ).toThrow(/not found/);
    });

    it("should throw if receipt is unsigned", () => {
      const unsignedReceipt = { spec_version: "1.0", status: "PASS" };
      const unsignedPath = join(tmpDir, "unsigned.json");
      writeFileSync(unsignedPath, JSON.stringify(unsignedReceipt));
      expect(() =>
        createBundle({
          receiptPath: unsignedPath,
          constitutionPath,
          publicKeyPath,
          outputPath: join(tmpDir, "out.zip"),
        }),
      ).toThrow(/not signed/);
    });

    it("should throw if constitution has no policy_hash", () => {
      const unsignedConst = yaml.dump({ sanna_constitution: "1.0.0", identity: { agent_name: "test" } });
      const unsignedConstPath = join(tmpDir, "unsigned-const.yaml");
      writeFileSync(unsignedConstPath, unsignedConst);
      expect(() =>
        createBundle({
          receiptPath,
          constitutionPath: unsignedConstPath,
          publicKeyPath,
          outputPath: join(tmpDir, "out.zip"),
        }),
      ).toThrow(/not signed/);
    });
  });

  describe("verifyBundle", () => {
    it("should verify a valid bundle", () => {
      const outputPath = join(tmpDir, "valid.bundle.zip");
      createBundle({ receiptPath, constitutionPath, publicKeyPath, outputPath });
      const result = verifyBundle(outputPath);
      // Structure, fingerprint, and several checks should pass
      expect(result.checks.length).toBeGreaterThan(0);
      const structCheck = result.checks.find((c) => c.name === "Bundle structure");
      expect(structCheck?.passed).toBe(true);
      const fpCheck = result.checks.find((c) => c.name === "Receipt fingerprint");
      expect(fpCheck?.passed).toBe(true);
    });

    it("should detect invalid zip", () => {
      const badPath = join(tmpDir, "bad.zip");
      writeFileSync(badPath, "not a zip file");
      const result = verifyBundle(badPath);
      expect(result.valid).toBe(false);
      expect(result.checks[0].detail).toContain("Not a valid zip");
    });

    it("should detect missing required files", () => {
      const zip = new AdmZip();
      zip.addFile("receipt.json", Buffer.from("{}"));
      // Missing constitution.yaml and public keys
      const badPath = join(tmpDir, "missing.zip");
      zip.writeZip(badPath);
      const result = verifyBundle(badPath);
      expect(result.valid).toBe(false);
    });

    it("should reject path traversal", () => {
      const zip = new AdmZip();
      zip.addFile("../evil.json", Buffer.from("{}"));
      const badPath = join(tmpDir, "traversal.zip");
      zip.writeZip(badPath);
      const result = verifyBundle(badPath);
      expect(result.valid).toBe(false);
      // adm-zip may strip "../" so it could be "Unsafe path" or "Unexpected member"
      expect(result.checks[0].passed).toBe(false);
    });

    it("should reject unexpected members", () => {
      const zip = new AdmZip();
      zip.addFile("receipt.json", Buffer.from("{}"));
      zip.addFile("constitution.yaml", Buffer.from(""));
      zip.addFile("public_keys/key.pub", Buffer.from(""));
      zip.addFile("metadata.json", Buffer.from("{}"));
      zip.addFile("malicious.exe", Buffer.from("bad"));
      const badPath = join(tmpDir, "unexpected.zip");
      zip.writeZip(badPath);
      const result = verifyBundle(badPath);
      expect(result.valid).toBe(false);
      expect(result.checks[0].detail).toContain("Unexpected member");
    });

    it("should reject too many members", () => {
      const zip = new AdmZip();
      for (let i = 0; i < 15; i++) {
        zip.addFile(`public_keys/key${i}.pub`, Buffer.from(""));
      }
      const badPath = join(tmpDir, "toomany.zip");
      zip.writeZip(badPath);
      const result = verifyBundle(badPath);
      expect(result.valid).toBe(false);
      expect(result.checks[0].detail).toContain("Too many members");
    });

    it("should throw if bundle file doesn't exist", () => {
      expect(() => verifyBundle(join(tmpDir, "nonexistent.zip"))).toThrow(/not found/);
    });

    it("should provide a receipt summary", () => {
      const outputPath = join(tmpDir, "summary.bundle.zip");
      createBundle({ receiptPath, constitutionPath, publicKeyPath, outputPath });
      const result = verifyBundle(outputPath);
      expect(result.receipt_summary).toBeTruthy();
      expect(result.receipt_summary!.status).toBe("PASS");
      expect(result.receipt_summary!.agent_name).toBe("test-bundle-agent");
    });

    it("should detect tampered receipt fingerprint", () => {
      // Create bundle, then modify the receipt fingerprint inside
      const outputPath = join(tmpDir, "tampered.bundle.zip");
      createBundle({ receiptPath, constitutionPath, publicKeyPath, outputPath });

      const zip = new AdmZip(outputPath);
      const receiptEntry = zip.getEntry("receipt.json")!;
      const receipt = JSON.parse(receiptEntry.getData().toString("utf-8"));
      receipt.receipt_fingerprint = "0000000000000000";
      zip.updateFile(receiptEntry, Buffer.from(JSON.stringify(receipt)));
      const tamperedPath = join(tmpDir, "tampered2.bundle.zip");
      zip.writeZip(tamperedPath);

      const result = verifyBundle(tamperedPath);
      const fpCheck = result.checks.find((c) => c.name === "Receipt fingerprint");
      expect(fpCheck?.passed).toBe(false);
    });

    it("should use non-strict mode correctly", () => {
      const outputPath = join(tmpDir, "nonstrict.bundle.zip");
      createBundle({ receiptPath, constitutionPath, publicKeyPath, outputPath });
      const result = verifyBundle(outputPath, false);
      // In non-strict mode, only structure + fingerprint matter
      expect(result.checks.length).toBeGreaterThan(0);
    });
  });

  describe("trust anchor (SAN-403)", () => {
    let bundlePath: string;
    let receiptKeyId: string;

    // Build a fully-verified bundle: save constitution, reload to get stable policy_hash,
    // then create receipt. The outer beforeEach uses the in-memory policy_hash which
    // can differ from the YAML-serialized one; the reload step avoids that mismatch.
    function makeTrustAnchorBundle(dir: string, suffix: string = ""): { bundlePath: string; receiptKeyId: string } {
      const kp = generateKeypair(`ta-${suffix}`);
      const signedConst = signConstitution(makeConstitution(), kp.privateKey, "ta@sanna.dev");
      const constPath = join(dir, `ta${suffix}-constitution.yaml`);
      saveConstitution(signedConst, constPath);
      const reloadedConst = loadConstitution(constPath);

      const pubPath = join(dir, `ta${suffix}.pub`);
      writeFileSync(pubPath, exportPublicKeyPem(kp.publicKey));

      const receipt = generateReceipt({
        correlation_id: `ta-test${suffix}`,
        inputs: { query: "test" },
        outputs: { response: "result" },
        checks: [{ check_id: "C1", name: "Test", passed: true, severity: "info", evidence: null }],
        constitution_ref: {
          document_id: `${signedConst.identity.agent_name}/1.0`,
          policy_hash: reloadedConst.policy_hash,
        },
      });
      signReceipt(receipt as unknown as Record<string, unknown>, kp.privateKey, "ta@sanna.dev");
      const rcptPath = join(dir, `ta${suffix}-receipt.json`);
      writeFileSync(rcptPath, JSON.stringify(receipt, null, 2));

      const bPath = join(dir, `ta${suffix}.bundle.zip`);
      createBundle({ receiptPath: rcptPath, constitutionPath: constPath, publicKeyPath: pubPath, outputPath: bPath });

      const zip = new AdmZip(bPath);
      const pubEntry = zip.getEntries().find(
        (e) => e.entryName.startsWith("public_keys/") && e.entryName.endsWith(".pub")
      )!;
      const keyId = pubEntry.entryName.slice("public_keys/".length, -4);
      return { bundlePath: bPath, receiptKeyId: keyId };
    }

    beforeEach(() => {
      const r = makeTrustAnchorBundle(tmpDir);
      bundlePath = r.bundlePath;
      receiptKeyId = r.receiptKeyId;
    });

    it("no anchor: succeeds with self-consistent signal", () => {
      const result = verifyBundle(bundlePath);
      expect(result.valid).toBe(true);
      expect(result.trust_anchored).toBe(false);
      const anchorCheck = result.checks.find((c) => c.name === "Trust anchor");
      expect(anchorCheck?.passed).toBe(true);
      expect(anchorCheck?.detail).toContain("WARNING");
    });

    it("anchor with matching key_id: succeeds + trust_anchored true", () => {
      const result = verifyBundle(bundlePath, true, new Set([receiptKeyId]));
      expect(result.valid).toBe(true);
      expect(result.trust_anchored).toBe(true);
      const anchorCheck = result.checks.find((c) => c.name === "Trust anchor");
      expect(anchorCheck?.passed).toBe(true);
      expect(anchorCheck?.detail).toContain("all in trust anchor");
    });

    it("anchor excluding key_id: fails", () => {
      const otherKey = "0".repeat(64);
      const result = verifyBundle(bundlePath, true, new Set([otherKey]));
      expect(result.valid).toBe(false);
      expect(result.trust_anchored).toBe(true);
      const anchorCheck = result.checks.find((c) => c.name === "Trust anchor");
      expect(anchorCheck?.passed).toBe(false);
      expect(anchorCheck?.detail).toContain("not in trust anchor");
    });

    it("empty anchor set: fails closed (trust nothing)", () => {
      const result = verifyBundle(bundlePath, true, new Set());
      expect(result.valid).toBe(false);
      expect(result.trust_anchored).toBe(true);
      const anchorCheck = result.checks.find((c) => c.name === "Trust anchor");
      expect(anchorCheck?.passed).toBe(false);
    });

    it("forged bundle: caught by anchor", () => {
      // Build attacker bundle using same safe pattern (save-then-reload policy_hash).
      const { bundlePath: forgedBundlePath } = makeTrustAnchorBundle(tmpDir, "forged");

      // Without anchor: self-consistent forge passes (the bug we are closing)
      const noAnchor = verifyBundle(forgedBundlePath);
      expect(noAnchor.valid).toBe(true);
      expect(noAnchor.trust_anchored).toBe(false);

      // With anchor that lists only the original (genuine) key_id: forgery is caught
      const withAnchor = verifyBundle(forgedBundlePath, true, new Set([receiptKeyId]));
      expect(withAnchor.valid).toBe(false);
      expect(withAnchor.trust_anchored).toBe(true);
    });
  });
});
