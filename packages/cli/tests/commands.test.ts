import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  signConstitution,
  saveConstitution,
  loadConstitution,
  verifyConstitutionSignature,
  generateReceipt,
  signReceipt,
  verifyReceipt,
  createBundle,
} from "@sanna-ai/core";
import type { Constitution, CheckResult } from "@sanna-ai/core";

function makeConstitution(): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "cli-test-agent",
      domain: "testing",
      description: "CLI test agent",
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
      { id: "B001", description: "Test", category: "scope", severity: "medium" },
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

describe("CLI Commands (unit tests via imports)", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-cli-test-"));
  });

  afterEach(() => {
    try { rmSync(tmpDir, { recursive: true, force: true }); } catch { /* */ }
  });

  describe("init", () => {
    it("should create a constitution file from a template", async () => {
      const { runInit } = await import("../src/commands/init.js");
      const output = join(tmpDir, "constitution.yaml");
      await runInit({
        output,
        template: "developer",
        agentName: "my-agent",
        domain: "test",
        description: "Test agent",
        nonInteractive: true,
      });

      expect(existsSync(output)).toBe(true);
      const content = readFileSync(output, "utf-8");
      expect(content).toContain("my-agent");
      expect(content).toContain("test");
      expect(content).toContain("sanna_constitution");
    });

    it("should use different templates", async () => {
      const { runInit } = await import("../src/commands/init.js");
      for (const template of ["developer", "privacy-focused", "locked-down", "minimal"]) {
        const output = join(tmpDir, `${template}.yaml`);
        await runInit({ output, template, nonInteractive: true });
        expect(existsSync(output)).toBe(true);
      }
    });

    it("should refuse to overwrite existing file", async () => {
      const { runInit } = await import("../src/commands/init.js");
      const output = join(tmpDir, "existing.yaml");
      writeFileSync(output, "existing content");
      process.exitCode = 0;
      await runInit({ output, template: "minimal", nonInteractive: true });
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("keygen", () => {
    it("should generate key files in the specified directory", async () => {
      const { runKeygen } = await import("../src/commands/keygen.js");
      const keyDir = join(tmpDir, "keys");
      await runKeygen({ outputDir: keyDir, label: "test" });

      // Should have created .key, .pub, .meta.json files
      const files = require("node:fs").readdirSync(keyDir) as string[];
      const keyFile = files.find((f: string) => f.endsWith(".key"));
      const pubFile = files.find((f: string) => f.endsWith(".pub"));
      const metaFile = files.find((f: string) => f.endsWith(".meta.json"));

      expect(keyFile).toBeDefined();
      expect(pubFile).toBeDefined();
      expect(metaFile).toBeDefined();

      // Meta should contain key_id and label
      const meta = JSON.parse(readFileSync(join(keyDir, metaFile!), "utf-8"));
      expect(meta.key_id).toBeTruthy();
      expect(meta.label).toBe("test");
      expect(meta.scheme).toBe("ed25519");
    });
  });

  describe("sign + verify-constitution round-trip", () => {
    it("should sign a constitution and verify it", () => {
      const keypair = generateKeypair("test");
      const constitution = makeConstitution();

      // Save unsigned constitution
      const constPath = join(tmpDir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      // Sign it
      const loaded = loadConstitution(constPath);
      const signed = signConstitution(loaded, keypair.privateKey, "test@sanna.dev");
      saveConstitution(signed, constPath);

      // Verify
      const reloaded = loadConstitution(constPath);
      expect(reloaded.policy_hash).toBeTruthy();
      expect(reloaded.provenance.signature).toBeTruthy();
      expect(reloaded.provenance.signature!.value).toBeTruthy();
      expect(verifyConstitutionSignature(reloaded, keypair.publicKey)).toBe(true);
    });
  });

  describe("verify", () => {
    it("should verify a valid receipt", () => {
      const keypair = generateKeypair();
      const checks: CheckResult[] = [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ];
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks,
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const result = verifyReceipt(receipt as unknown as Record<string, unknown>, keypair.publicKey);
      expect(result.valid).toBe(true);
    });

    it("should detect tampered receipt", () => {
      const keypair = generateKeypair();
      const checks: CheckResult[] = [
        { check_id: "C1", passed: true, severity: "info", evidence: null },
      ];
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks,
      }) as unknown as Record<string, unknown>;
      signReceipt(receipt, keypair.privateKey, "test");

      // Tamper
      (receipt as any).status = "FAIL";
      const result = verifyReceipt(receipt, keypair.publicKey);
      expect(result.valid).toBe(false);
    });
  });

  describe("verify (extended)", () => {
    it("should verify receipt with constitution chain", async () => {
      const { runVerify } = await import("../src/commands/verify.js");
      const keypair = generateKeypair();

      // Create and sign constitution
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(tmpDir, "verify-const.yaml");
      saveConstitution(constitution, constPath);
      const signedConst = loadConstitution(constPath);

      // Create receipt with matching policy_hash
      const receipt = generateReceipt({
        correlation_id: "verify-chain-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        constitution_ref: {
          document_id: "cli-test-agent/1.0",
          policy_hash: signedConst.policy_hash,
          version: "1.0",
        },
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const receiptPath = join(tmpDir, "verify-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const pubPath = join(tmpDir, "verify-pub.pub");
      writeFileSync(pubPath, exportPublicKeyPem(keypair.publicKey));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runVerify(receiptPath, {
          publicKey: pubPath,
          constitution: constPath,
          constitutionPublicKey: pubPath,
        });
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("VALID");
      expect(output).toContain("constitution_chain");
    });

    it("should detect policy_hash mismatch", async () => {
      const { runVerify } = await import("../src/commands/verify.js");
      const keypair = generateKeypair();

      // Create and sign constitution
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(tmpDir, "mismatch-const.yaml");
      saveConstitution(constitution, constPath);

      // Create receipt with DIFFERENT policy_hash
      const receipt = generateReceipt({
        correlation_id: "mismatch-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        constitution_ref: {
          document_id: "cli-test-agent/1.0",
          policy_hash: "0000000000000000000000000000000000000000000000000000000000000000",
          version: "1.0",
        },
      });
      const receiptPath = join(tmpDir, "mismatch-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runVerify(receiptPath, { constitution: constPath });
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("INVALID");
      expect(output).toContain("mismatch");
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });

    it("should enforce strict mode", async () => {
      const { runVerify } = await import("../src/commands/verify.js");

      // Create unsigned receipt
      const receipt = generateReceipt({
        correlation_id: "strict-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      const receiptPath = join(tmpDir, "strict-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runVerify(receiptPath, { strict: true });
      } finally {
        console.log = origLog;
      }

      expect(process.exitCode).toBe(1);
      const output = logs.join("\n");
      expect(output).toContain("Strict mode");
      process.exitCode = 0;
    });

    it("should output JSON format", async () => {
      const { runVerify } = await import("../src/commands/verify.js");
      const keypair = generateKeypair();

      const receipt = generateReceipt({
        correlation_id: "json-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const receiptPath = join(tmpDir, "json-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const pubPath = join(tmpDir, "json-pub.pub");
      writeFileSync(pubPath, exportPublicKeyPem(keypair.publicKey));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runVerify(receiptPath, { publicKey: pubPath, format: "json" });
      } finally {
        console.log = origLog;
      }

      const parsed = JSON.parse(logs.join("\n"));
      expect(parsed.valid).toBe(true);
      expect(parsed.errors).toBeDefined();
      expect(parsed.checks_performed).toBeDefined();
    });

    it("should warn when constitution is signed but no verification key", async () => {
      const { runVerify } = await import("../src/commands/verify.js");
      const keypair = generateKeypair();

      // Create and sign constitution
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(tmpDir, "warn-const.yaml");
      saveConstitution(constitution, constPath);
      const signedConst = loadConstitution(constPath);

      // Create receipt with matching policy_hash
      const receipt = generateReceipt({
        correlation_id: "warn-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        constitution_ref: {
          document_id: "cli-test-agent/1.0",
          policy_hash: signedConst.policy_hash,
          version: "1.0",
        },
      });
      const receiptPath = join(tmpDir, "warn-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runVerify(receiptPath, { constitution: constPath });
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("no --constitution-public-key provided");
    });
  });

  describe("inspect", () => {
    it("should pretty-print a receipt without errors", async () => {
      const { runInspect } = await import("../src/commands/inspect.js");
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      const receiptPath = join(tmpDir, "receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      // Capture console output
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runInspect(receiptPath, {});
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("SANNA RECEIPT");
      expect(output).toContain("PASS");
      expect(output).toContain("C1");
    });

    it("should output JSON when --json flag is set", async () => {
      const { runInspect } = await import("../src/commands/inspect.js");
      const receipt = generateReceipt({
        correlation_id: "test-001",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      const receiptPath = join(tmpDir, "receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runInspect(receiptPath, { json: true });
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      const parsed = JSON.parse(output);
      expect(parsed.receipt_id).toBeTruthy();
    });
  });

  describe("diff", () => {
    it("should detect differences between two files", async () => {
      const { runDiff } = await import("../src/commands/diff.js");
      const fileA = join(tmpDir, "a.yaml");
      const fileB = join(tmpDir, "b.yaml");
      writeFileSync(fileA, "line1\nline2\nline3\n");
      writeFileSync(fileB, "line1\nline2-modified\nline3\n");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDiff(fileA, fileB);
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("---");
      expect(output).toContain("+++");
    });

    it("should report identical files", async () => {
      const { runDiff } = await import("../src/commands/diff.js");
      const fileA = join(tmpDir, "same.yaml");
      writeFileSync(fileA, "same content\n");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDiff(fileA, fileA);
      } finally {
        console.log = origLog;
      }

      expect(logs.join("\n")).toContain("identical");
    });
  });

  describe("demo", () => {
    it("should run the full demo without errors", async () => {
      const { runDemo } = await import("../src/commands/demo.js");
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runDemo();
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("Sanna Demo");
      expect(output).toContain("Generated Ed25519 keypair");
      expect(output).toContain("Signed constitution");
      expect(output).toContain("Generated receipt");
      expect(output).toContain("Signed receipt");
      expect(output).toContain("Verified receipt");
      expect(output).toContain("VALID");
    });
  });

  describe("check-config", () => {
    it("should validate a correct gateway config", async () => {
      const { runCheckConfig } = await import("../src/commands/check-config.js");

      // Create a constitution and config that references it
      const keypair = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test");
      const constPath = join(tmpDir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      const keyPath = join(tmpDir, "signing.key");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));
      try { require("node:fs").chmodSync(keyPath, 0o600); } catch { /* Windows */ }

      const config = {
        gateway: {
          constitution: constPath,
          signing_key: keyPath,
        },
        downstream: [
          { name: "test-server", command: "node server.js" },
        ],
      };
      const configPath = join(tmpDir, "gateway.yaml");
      writeFileSync(configPath, yaml.dump(config));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runCheckConfig(configPath);
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("YAML syntax valid");
      expect(output).toContain("Result: VALID");
    });

    it("should detect missing config file", async () => {
      const { runCheckConfig } = await import("../src/commands/check-config.js");
      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runCheckConfig(join(tmpDir, "nonexistent.yaml"));
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("drift-report", () => {
    it("should report error for missing DB", async () => {
      const { runDriftReport } = await import("../src/commands/drift-report.js");
      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runDriftReport({ db: join(tmpDir, "nonexistent.db"), window: 30 });
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      expect(logs.join("\n")).toContain("not found");
      process.exitCode = 0;
    });

    it("should generate a drift report from a populated store", async () => {
      const { runDriftReport } = await import("../src/commands/drift-report.js");
      const { ReceiptStore } = await import("@sanna-ai/core");

      process.env.SANNA_ALLOW_TEMP_DB = "1";
      const dbPath = join(tmpDir, "drift.db");
      const store = new ReceiptStore(dbPath);

      // Populate with some receipts
      for (let i = 0; i < 10; i++) {
        store.save({
          receipt_id: `r-${i}`,
          correlation_id: "test",
          timestamp: new Date(Date.now() - i * 86400000).toISOString(),
          status: "PASS",
          checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
          checks_passed: 1,
          checks_failed: 0,
          inputs: { q: "test" },
          outputs: { r: "test" },
          context_hash: "a".repeat(64),
          output_hash: "b".repeat(64),
          constitution_ref: { document_id: "agent-a/1.0", policy_hash: "c".repeat(64) },
        });
      }
      store.close();

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runDriftReport({ db: dbPath, window: 30 });
      } finally {
        console.log = origLog;
        delete process.env.SANNA_ALLOW_TEMP_DB;
      }

      const output = logs.join("\n");
      expect(output).toContain("Fleet Governance Report");
      expect(output).toContain("agent-a");
    });
  });

  describe("approve", () => {
    it("should approve a signed constitution", async () => {
      const { runApprove } = await import("../src/commands/approve.js");
      const keypair = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(tmpDir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      const keyPath = join(tmpDir, "approver.key");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));

      const approvalFile = join(tmpDir, "constitution.approval.json");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runApprove(constPath, { privateKey: keyPath, approvalFile });
      } finally {
        console.log = origLog;
      }

      expect(existsSync(approvalFile)).toBe(true);
      const request = JSON.parse(readFileSync(approvalFile, "utf-8"));
      expect(request.status).toBe("approved");
      expect(request.approvals.length).toBe(1);
    });

    it("should reject unsigned constitution", async () => {
      const { runApprove } = await import("../src/commands/approve.js");
      const keypair = generateKeypair();
      const constitution = makeConstitution();
      const constPath = join(tmpDir, "unsigned.yaml");
      saveConstitution(constitution, constPath);

      const keyPath = join(tmpDir, "approver.key");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));

      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runApprove(constPath, { privateKey: keyPath });
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });

    it("should add to existing approval requiring multiple approvers", async () => {
      const { runApprove } = await import("../src/commands/approve.js");
      const keypair1 = generateKeypair();
      const keypair2 = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair1.privateKey, "test@sanna.dev");
      const constPath = join(tmpDir, "multi.yaml");
      saveConstitution(constitution, constPath);

      const keyPath1 = join(tmpDir, "approver1.key");
      const keyPath2 = join(tmpDir, "approver2.key");
      writeFileSync(keyPath1, exportPrivateKeyPem(keypair1.privateKey));
      writeFileSync(keyPath2, exportPrivateKeyPem(keypair2.privateKey));

      const approvalFile = join(tmpDir, "multi.approval.json");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        // First approval — creates request requiring 2
        await runApprove(constPath, {
          privateKey: keyPath1,
          approvalFile,
          requiredApprovals: "2",
        });

        // After first approval, status should still be pending
        let request = JSON.parse(readFileSync(approvalFile, "utf-8"));
        expect(request.status).toBe("pending");
        expect(request.approvals.length).toBe(1);

        // Second approval
        await runApprove(constPath, {
          privateKey: keyPath2,
          approvalFile,
        });

        request = JSON.parse(readFileSync(approvalFile, "utf-8"));
        expect(request.status).toBe("approved");
        expect(request.approvals.length).toBe(2);
      } finally {
        console.log = origLog;
      }
    });
  });

  describe("bundle-create", () => {
    function createTestBundle(dir: string) {
      const keypair = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(dir, "constitution.yaml");
      saveConstitution(constitution, constPath);

      const keyPath = join(dir, "signing.key");
      const pubPath = join(dir, "signing.pub");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));
      writeFileSync(pubPath, exportPublicKeyPem(keypair.publicKey));

      const receipt = generateReceipt({
        correlation_id: "bundle-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const receiptPath = join(dir, "receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      return { constPath, keyPath, pubPath, receiptPath };
    }

    it("should create an evidence bundle", async () => {
      const { runBundleCreate } = await import("../src/commands/bundle-create.js");
      const { constPath, pubPath, receiptPath } = createTestBundle(tmpDir);
      const outputPath = join(tmpDir, "evidence.zip");

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runBundleCreate({
          receipt: receiptPath,
          constitution: constPath,
          publicKey: pubPath,
          output: outputPath,
        });
      } finally {
        console.log = origLog;
      }

      expect(existsSync(outputPath)).toBe(true);
      expect(logs.join("\n")).toContain("Evidence bundle created");
    });

    it("should error on missing receipt", async () => {
      const { runBundleCreate } = await import("../src/commands/bundle-create.js");
      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runBundleCreate({
          receipt: join(tmpDir, "nonexistent.json"),
          constitution: join(tmpDir, "nonexistent.yaml"),
          publicKey: join(tmpDir, "nonexistent.pub"),
          output: join(tmpDir, "out.zip"),
        });
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("bundle-verify", () => {
    function createTestBundleZip(dir: string): string {
      const keypair = generateKeypair();
      const constitution = signConstitution(makeConstitution(), keypair.privateKey, "test@sanna.dev");
      const constPath = join(dir, "bv-constitution.yaml");
      saveConstitution(constitution, constPath);

      const pubPath = join(dir, "bv-signing.pub");
      writeFileSync(pubPath, exportPublicKeyPem(keypair.publicKey));

      // Load the signed constitution to get its policy_hash for the receipt
      const signedConst = loadConstitution(constPath);

      const receipt = generateReceipt({
        correlation_id: "bundle-verify-test",
        inputs: { q: "test" },
        outputs: { r: "result" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        constitution_ref: {
          document_id: "cli-test-agent/1.0",
          policy_hash: signedConst.policy_hash,
          version: "1.0",
        },
      });
      signReceipt(receipt as unknown as Record<string, unknown>, keypair.privateKey, "test");
      const receiptPath = join(dir, "bv-receipt.json");
      writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));

      const bundlePath = join(dir, "test-bundle.zip");
      createBundle({
        receiptPath,
        constitutionPath: constPath,
        publicKeyPath: pubPath,
        outputPath: bundlePath,
      });
      return bundlePath;
    }

    it("should verify a valid bundle", async () => {
      const { runBundleVerify } = await import("../src/commands/bundle-verify.js");
      const bundlePath = createTestBundleZip(tmpDir);

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runBundleVerify(bundlePath, {});
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("Verdict:  VALID");
    });

    it("should output JSON with --json flag", async () => {
      const { runBundleVerify } = await import("../src/commands/bundle-verify.js");
      const bundlePath = createTestBundleZip(tmpDir);

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runBundleVerify(bundlePath, { json: true });
      } finally {
        console.log = origLog;
      }

      const parsed = JSON.parse(logs.join("\n"));
      expect(parsed.valid).toBe(true);
    });

    it("should reject invalid zip", async () => {
      const { runBundleVerify } = await import("../src/commands/bundle-verify.js");
      const fakePath = join(tmpDir, "fake-bundle.zip");
      writeFileSync(fakePath, Buffer.from("not a zip file"));

      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runBundleVerify(fakePath, {});
      } finally {
        console.log = origLog;
      }

      const output = logs.join("\n");
      expect(output).toContain("INVALID");
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });
  });

  describe("generate", () => {
    it("should generate a receipt from trace data", async () => {
      const { runGenerate } = await import("../src/commands/generate.js");
      const traceData = {
        inputs: { query: "test question" },
        outputs: { response: "test answer" },
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      };
      const tracePath = join(tmpDir, "trace.json");
      writeFileSync(tracePath, JSON.stringify(traceData));

      const outputPath = join(tmpDir, "generated-receipt.json");
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runGenerate(tracePath, { output: outputPath });
      } finally {
        console.log = origLog;
      }

      expect(existsSync(outputPath)).toBe(true);
      const receipt = JSON.parse(readFileSync(outputPath, "utf-8"));
      expect(receipt.receipt_id).toBeTruthy();
      expect(receipt.receipt_fingerprint).toBeTruthy();
    });

    it("should sign when --signing-key provided", async () => {
      const { runGenerate } = await import("../src/commands/generate.js");
      const keypair = generateKeypair();
      const keyPath = join(tmpDir, "gen-signing.key");
      writeFileSync(keyPath, exportPrivateKeyPem(keypair.privateKey));

      const traceData = {
        inputs: { query: "test" },
        outputs: { response: "answer" },
        checks: [],
      };
      const tracePath = join(tmpDir, "trace-sign.json");
      writeFileSync(tracePath, JSON.stringify(traceData));

      const outputPath = join(tmpDir, "signed-receipt.json");
      const logs: string[] = [];
      const origLog = console.log;
      console.log = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        await runGenerate(tracePath, { signingKey: keyPath, output: outputPath });
      } finally {
        console.log = origLog;
      }

      const receipt = JSON.parse(readFileSync(outputPath, "utf-8"));
      expect(receipt.receipt_signature).toBeTruthy();
      expect(receipt.receipt_signature.signature).toBeTruthy();
    });

    it("should error on missing inputs", async () => {
      const { runGenerate } = await import("../src/commands/generate.js");
      const traceData = { outputs: { response: "answer" } };
      const tracePath = join(tmpDir, "bad-trace.json");
      writeFileSync(tracePath, JSON.stringify(traceData));

      const logs: string[] = [];
      const origErr = console.error;
      console.error = (...args: unknown[]) => logs.push(args.join(" "));
      try {
        process.exitCode = 0;
        await runGenerate(tracePath, {});
      } finally {
        console.error = origErr;
      }
      expect(process.exitCode).toBe(1);
      process.exitCode = 0;
    });

    it("should hardcode enforcement_surface = middleware, not read from trace [SAN-213]", async () => {
      const { runGenerate } = await import("../src/commands/generate.js");
      // Trace contains enforcement_surface = "gateway" and invariants_scope = "limited"
      // The CLI is the emitter — must hardcode "middleware"/"full", not self-attest trace values
      const traceData = {
        inputs: { query: "test" },
        outputs: { response: "answer" },
        checks: [],
        enforcement_surface: "gateway",
        invariants_scope: "limited",
      };
      const tracePath = join(tmpDir, "trace-surface.json");
      writeFileSync(tracePath, JSON.stringify(traceData));
      const outputPath = join(tmpDir, "receipt-surface.json");

      const origLog = console.log;
      console.log = () => {};
      try {
        await runGenerate(tracePath, { output: outputPath });
      } finally {
        console.log = origLog;
      }

      const receipt = JSON.parse(readFileSync(outputPath, "utf-8"));
      // CLI must hardcode "middleware", not propagate "gateway" from trace
      expect(receipt.enforcement_surface).toBe("middleware");
      // CLI must hardcode "full", not propagate "limited" from trace
      expect(receipt.invariants_scope).toBe("full");
    });
  });
});
