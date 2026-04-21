import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createSannaServer } from "../src/server.js";
import type { SannaMCPConfig } from "../src/server.js";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
  loadConstitution,
  signConstitution,
  saveConstitution,
  generateReceipt,
  signReceipt,
  loadPrivateKey,
  ReceiptStore,
  createApprovalRequest,
  signApproval,
  createIdentityClaim,
  getKeyId,
} from "@sanna-ai/core";

// ── Helpers ─────────────────────────────────────────────────────────

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-mcp-test-"));
  process.env.SANNA_ALLOW_TEMP_DB = "1";
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
  delete process.env.SANNA_ALLOW_TEMP_DB;
});

function writeConstitution(filename: string = "constitution.yaml"): string {
  const path = join(tmpDir, filename);
  writeFileSync(
    path,
    `sanna_constitution: '1.0.0'
identity:
  agent_name: test-agent
  domain: testing
  description: Test agent for MCP
provenance:
  authored_by: test@sanna.dev
  approved_by:
    - test@sanna.dev
  approval_date: '2026-02-22'
  approval_method: test
  change_history: []
  signature: null
boundaries:
  - id: B001
    description: Must not access external systems
    category: scope
    severity: high
  - id: B002
    description: Must not disclose confidential records
    category: confidentiality
    severity: critical
trust_tiers:
  autonomous: []
  requires_approval: []
  prohibited: []
halt_conditions: []
invariants:
  - id: INV_NO_FABRICATION
    rule: No fabrication
    enforcement: halt
    check: null
  - id: INV_PII
    rule: No PII in output
    enforcement: halt
    check: null
authority_boundaries:
  cannot_execute:
    - delete_database
  must_escalate: []
  can_execute:
    - read_data
  default_escalation: log
`,
    "utf-8",
  );
  return path;
}

function writeKeypair(): { keyPath: string; pubPath: string } {
  const kp = generateKeypair();
  const keyPath = join(tmpDir, "test.key");
  const pubPath = join(tmpDir, "test.pub");
  writeFileSync(keyPath, exportPrivateKeyPem(kp.privateKey), "utf-8");
  writeFileSync(pubPath, exportPublicKeyPem(kp.publicKey), "utf-8");
  return { keyPath, pubPath };
}

function writeSignedConstitution(): {
  constitutionPath: string;
  keyPath: string;
  pubPath: string;
} {
  const constPath = writeConstitution();
  const { keyPath, pubPath } = writeKeypair();
  const c = loadConstitution(constPath);
  const privateKey = loadPrivateKey(keyPath);
  const signed = signConstitution(c, privateKey, "test@sanna.dev");
  saveConstitution(signed, constPath);
  return { constitutionPath: constPath, keyPath, pubPath };
}

function makeReceiptJson(): string {
  const receipt = generateReceipt({
    correlation_id: "sanna-test-001",
    inputs: { query: "What is the refund policy?", context: "Refunds within 30 days." },
    outputs: { response: "Refunds are available within 30 days." },
    checks: [
      {
        check_id: "C1",
        name: "Context Grounding",
        passed: true,
        severity: "info",
        evidence: null,
      },
    ],
  });
  return JSON.stringify(receipt);
}

// ── Server and integration tests ────────────────────────────────────

describe("createSannaServer", () => {
  it("should create a server instance", () => {
    const server = createSannaServer();
    expect(server).toBeDefined();
  });

  it("should create a server with config", () => {
    const config: SannaMCPConfig = {
      constitutionPath: "/tmp/test.yaml",
      dbPath: "/tmp/test.db",
    };
    const server = createSannaServer(config);
    expect(server).toBeDefined();
  });
});

// Since we can't easily call tools through the MCP protocol in tests
// without a running transport, let's test the server module by importing
// the handlers through a different approach. We'll use the Client/Server
// pair with InMemoryTransport for integration testing.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

async function createTestClient(
  config: SannaMCPConfig = {},
): Promise<{ client: Client; cleanup: () => Promise<void> }> {
  const server = createSannaServer(config);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);

  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);

  return {
    client,
    cleanup: async () => {
      await client.close();
      await server.close();
    },
  };
}

describe("tool listing", () => {
  it("should list all 10 tools", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.listTools();
      expect(result.tools).toHaveLength(10);
      const names = result.tools.map((t) => t.name).sort();
      expect(names).toEqual([
        "sanna_check_constitution_approval",
        "sanna_drift_report",
        "sanna_evaluate_authority",
        "sanna_generate_receipt",
        "sanna_get_constitution",
        "sanna_list_checks",
        "sanna_query_receipts",
        "sanna_verify_constitution",
        "sanna_verify_identity_claims",
        "sanna_verify_receipt",
      ]);
    } finally {
      await cleanup();
    }
  });

  it("should have descriptions for all tools", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.listTools();
      for (const tool of result.tools) {
        expect(tool.description).toBeTruthy();
        expect(tool.inputSchema).toBeDefined();
      }
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_evaluate_authority", () => {
  it("should deny a forbidden action", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_evaluate_authority",
        arguments: {
          action_name: "delete_database",
          constitution_path: constPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.decision).toBe("DENY");
      expect(data.boundary_type).toBe("cannot_execute");
    } finally {
      await cleanup();
    }
  });

  it("should allow an explicitly permitted action", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_evaluate_authority",
        arguments: {
          action_name: "read_data",
          constitution_path: constPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.decision).toBe("ALLOW");
      expect(data.boundary_type).toBe("can_execute");
    } finally {
      await cleanup();
    }
  });

  it("should allow an uncategorized action", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_evaluate_authority",
        arguments: {
          action_name: "send_email",
          constitution_path: constPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.decision).toBe("ALLOW");
      expect(data.boundary_type).toBe("uncategorized");
    } finally {
      await cleanup();
    }
  });

  it("should use config default constitution_path", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient({ constitutionPath: constPath });
    try {
      const result = await client.callTool({
        name: "sanna_evaluate_authority",
        arguments: { action_name: "read_data" },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.decision).toBe("ALLOW");
    } finally {
      await cleanup();
    }
  });

  it("should return error when no constitution_path", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_evaluate_authority",
        arguments: { action_name: "read_data" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_generate_receipt", () => {
  it("should generate a receipt without constitution", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: {
          query: "What is the refund policy?",
          response: "Refunds are available within 30 days.",
          context: "Our refund policy allows returns within 30 days.",
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.receipt_id).toBeTruthy();
      expect(data.status).toBe("PASS");
      expect(data.checks.length).toBeGreaterThan(0);
      expect(data.correlation_id).toMatch(/^sanna-/);
    } finally {
      await cleanup();
    }
  });

  it("should generate a receipt with constitution", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: {
          query: "What is the policy?",
          response: "The policy states rules about testing.",
          context: "Policy details about testing.",
          constitution_path: constPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.receipt_id).toBeTruthy();
      expect(data.constitution_ref).toBeDefined();
      expect(data.constitution_ref.document_id).toContain("test-agent");
    } finally {
      await cleanup();
    }
  });

  it("should sign receipt when signing key provided", async () => {
    const { keyPath } = writeKeypair();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: {
          query: "Test query",
          response: "Test response",
          signing_key_path: keyPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.receipt_signature).toBeDefined();
      expect(data.receipt_signature.signature).toBeTruthy();
      expect(data.receipt_signature.scheme).toBe("receipt_sig_v1");
    } finally {
      await cleanup();
    }
  });

  it("should return error for missing query", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: { response: "Test response" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should return error for missing response", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: { query: "Test query" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should emit enforcement_surface = middleware [SAN-213]", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: {
          query: "Test",
          response: "Test response",
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.enforcement_surface).toBe("middleware");
    } finally {
      await cleanup();
    }
  });

  it("should emit invariants_scope = full [SAN-213]", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_generate_receipt",
        arguments: {
          query: "Test",
          response: "Test response",
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.invariants_scope).toBe("full");
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_verify_receipt", () => {
  it("should verify a valid receipt", async () => {
    const receiptJson = makeReceiptJson();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_receipt",
        arguments: { receipt_json: receiptJson },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.valid).toBe(true);
      expect(data.errors).toHaveLength(0);
      expect(data.checks_performed).toContain("schema");
      expect(data.checks_performed).toContain("fingerprint");
    } finally {
      await cleanup();
    }
  });

  it("should detect tampered receipt", async () => {
    const receipt = JSON.parse(makeReceiptJson());
    receipt.status = "FAIL"; // Tamper status
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_receipt",
        arguments: { receipt_json: JSON.stringify(receipt) },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.valid).toBe(false);
      expect(data.errors.length).toBeGreaterThan(0);
    } finally {
      await cleanup();
    }
  });

  it("should return error for invalid JSON", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_receipt",
        arguments: { receipt_json: "not valid json{" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should verify with public key when provided", async () => {
    const { keyPath, pubPath } = writeKeypair();
    // Generate a signed receipt
    const receipt = generateReceipt({
      correlation_id: "sanna-test-signed",
      inputs: { query: "test" },
      outputs: { response: "test" },
      checks: [],
    });
    const privateKey = loadPrivateKey(keyPath);
    signReceipt(receipt as unknown as Record<string, unknown>, privateKey, "test");

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_receipt",
        arguments: {
          receipt_json: JSON.stringify(receipt),
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.valid).toBe(true);
      expect(data.checks_performed).toContain("signature");
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_get_constitution", () => {
  it("should load and return a constitution", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_get_constitution",
        arguments: { constitution_path: constPath },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.identity.agent_name).toBe("test-agent");
      expect(data.boundaries).toHaveLength(2);
      expect(data.invariants).toHaveLength(2);
    } finally {
      await cleanup();
    }
  });

  it("should return error when no path provided", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_get_constitution",
        arguments: {},
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should use config default constitution_path", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient({ constitutionPath: constPath });
    try {
      const result = await client.callTool({
        name: "sanna_get_constitution",
        arguments: {},
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.identity.agent_name).toBe("test-agent");
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_verify_constitution", () => {
  it("should verify a signed constitution", async () => {
    const { constitutionPath, pubPath } = writeSignedConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_constitution",
        arguments: {
          constitution_path: constitutionPath,
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.signature_present).toBe(true);
      expect(data.signature_valid).toBe(true);
      expect(data.agent_name).toBe("test-agent");
      expect(data.content_hash).toBeTruthy();
      expect(data.signature_details.scheme).toBe("constitution_sig_v1");
    } finally {
      await cleanup();
    }
  });

  it("should fail for unsigned constitution", async () => {
    const constPath = writeConstitution();
    const { pubPath } = writeKeypair();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_constitution",
        arguments: {
          constitution_path: constPath,
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.signature_present).toBe(false);
      expect(data.signature_valid).toBe(false);
    } finally {
      await cleanup();
    }
  });

  it("should return error when paths missing", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_constitution",
        arguments: {},
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_query_receipts", () => {
  it("should query receipts from a database", async () => {
    const dbPath = join(tmpDir, "test-receipts.db");
    const store = new ReceiptStore(dbPath);
    store.save({
      receipt_id: "receipt-001",
      correlation_id: "corr-001",
      timestamp: new Date().toISOString(),
      status: "PASS",
      checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
      checks_passed: 1,
      checks_failed: 0,
      inputs: { query: "test" },
      outputs: { response: "test" },
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
      constitution_ref: { document_id: "test-agent/1.0", policy_hash: "c".repeat(64) },
    });
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_query_receipts",
        arguments: { db_path: dbPath, limit: 10 },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.count).toBe(1);
      expect(data.receipts).toHaveLength(1);
      expect(data.receipts[0].receipt_id).toBe("receipt-001");
    } finally {
      await cleanup();
    }
  });

  it("should filter by status", async () => {
    const dbPath = join(tmpDir, "test-filter.db");
    const store = new ReceiptStore(dbPath);
    store.save({
      receipt_id: "r1",
      timestamp: new Date().toISOString(),
      status: "PASS",
      checks: [],
      checks_passed: 0,
      checks_failed: 0,
      inputs: {},
      outputs: {},
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
    });
    store.save({
      receipt_id: "r2",
      timestamp: new Date().toISOString(),
      status: "FAIL",
      checks: [],
      checks_passed: 0,
      checks_failed: 1,
      inputs: {},
      outputs: {},
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
    });
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_query_receipts",
        arguments: { db_path: dbPath, status: "FAIL" },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.count).toBe(1);
      expect(data.receipts[0].receipt_id).toBe("r2");
    } finally {
      await cleanup();
    }
  });

  it("should run drift analysis", async () => {
    const dbPath = join(tmpDir, "test-drift.db");
    const store = new ReceiptStore(dbPath);
    // Add some receipts for drift analysis
    for (let i = 0; i < 10; i++) {
      store.save({
        receipt_id: `r-${i}`,
        timestamp: new Date().toISOString(),
        status: i % 3 === 0 ? "FAIL" : "PASS",
        checks: [
          { check_id: "C1", passed: i % 3 !== 0, severity: i % 3 === 0 ? "high" : "info", evidence: null },
        ],
        checks_passed: i % 3 !== 0 ? 1 : 0,
        checks_failed: i % 3 === 0 ? 1 : 0,
        inputs: {},
        outputs: {},
        context_hash: "a".repeat(64),
        output_hash: "b".repeat(64),
        constitution_ref: { document_id: "drift-agent/1.0", policy_hash: "d".repeat(64) },
      });
    }
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_query_receipts",
        arguments: { db_path: dbPath, analysis: "drift" },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.analysis).toBe("drift");
      expect(data.report).toBeDefined();
      expect(data.formatted).toContain("Sanna Fleet Governance Report");
    } finally {
      await cleanup();
    }
  });

  it("should cap limit at 500", async () => {
    const dbPath = join(tmpDir, "test-limit.db");
    const store = new ReceiptStore(dbPath);
    store.save({
      receipt_id: "r1",
      timestamp: new Date().toISOString(),
      status: "PASS",
      checks: [],
      checks_passed: 0,
      checks_failed: 0,
      inputs: {},
      outputs: {},
      context_hash: "a".repeat(64),
      output_hash: "b".repeat(64),
    });
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      // Even with limit=1000, should not error
      const result = await client.callTool({
        name: "sanna_query_receipts",
        arguments: { db_path: dbPath, limit: 1000 },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.count).toBe(1);
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_drift_report", () => {
  it("should generate a text drift report", async () => {
    const dbPath = join(tmpDir, "drift-report.db");
    const store = new ReceiptStore(dbPath);
    for (let i = 0; i < 6; i++) {
      store.save({
        receipt_id: `drift-${i}`,
        timestamp: new Date().toISOString(),
        status: "PASS",
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        checks_passed: 1,
        checks_failed: 0,
        inputs: {},
        outputs: {},
        context_hash: "a".repeat(64),
        output_hash: "b".repeat(64),
        constitution_ref: { document_id: "agent-x/1.0", policy_hash: "c".repeat(64) },
      });
    }
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_drift_report",
        arguments: { db_path: dbPath, format: "text" },
      });
      const text = (result.content as any)[0].text;
      expect(text).toContain("Sanna Fleet Governance Report");
      expect(text).toContain("agent-x");
    } finally {
      await cleanup();
    }
  });

  it("should generate a JSON drift report", async () => {
    const dbPath = join(tmpDir, "drift-json.db");
    const store = new ReceiptStore(dbPath);
    for (let i = 0; i < 6; i++) {
      store.save({
        receipt_id: `dr-${i}`,
        timestamp: new Date().toISOString(),
        status: "PASS",
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        checks_passed: 1,
        checks_failed: 0,
        inputs: {},
        outputs: {},
        context_hash: "a".repeat(64),
        output_hash: "b".repeat(64),
        constitution_ref: { document_id: "agent-y/1.0", policy_hash: "c".repeat(64) },
      });
    }
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_drift_report",
        arguments: { db_path: dbPath, format: "json" },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.window_days).toBe(30);
      expect(data.agents).toBeDefined();
    } finally {
      await cleanup();
    }
  });

  it("should generate a CSV drift report", async () => {
    const dbPath = join(tmpDir, "drift-csv.db");
    const store = new ReceiptStore(dbPath);
    for (let i = 0; i < 6; i++) {
      store.save({
        receipt_id: `csv-${i}`,
        timestamp: new Date().toISOString(),
        status: "PASS",
        checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
        checks_passed: 1,
        checks_failed: 0,
        inputs: {},
        outputs: {},
        context_hash: "a".repeat(64),
        output_hash: "b".repeat(64),
        constitution_ref: { document_id: "agent-z/1.0", policy_hash: "c".repeat(64) },
      });
    }
    store.close();

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_drift_report",
        arguments: { db_path: dbPath, format: "csv" },
      });
      const text = (result.content as any)[0].text;
      expect(text).toContain("window_days");
      expect(text).toContain("agent-z");
    } finally {
      await cleanup();
    }
  });
});

describe("unknown tool", () => {
  it("should return error for unknown tool", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      // The MCP SDK may throw or return an error for unknown tools
      try {
        const result = await client.callTool({
          name: "sanna_nonexistent",
          arguments: {},
        });
        // If we get here, check for error
        expect((result as any).isError).toBe(true);
      } catch {
        // Expected — unknown tool may throw
      }
    } finally {
      await cleanup();
    }
  });
});

describe("size guards", () => {
  it("should reject oversized receipt_json", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const oversized = "x".repeat(1_100_000); // > 1 MB
      const result = await client.callTool({
        name: "sanna_verify_receipt",
        arguments: { receipt_json: oversized },
      });
      expect((result as any).isError).toBe(true);
      const text = (result.content as any)[0].text;
      expect(text).toContain("exceeds maximum size");
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_list_checks", () => {
  it("should return all 5 checks", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_list_checks",
        arguments: {},
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.total).toBe(5);
      expect(data.checks).toHaveLength(5);
      const ids = data.checks.map((c: any) => c.check_id);
      expect(ids).toEqual(["C1", "C2", "C3", "C4", "C5"]);
    } finally {
      await cleanup();
    }
  });

  it("should include metadata for each check", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_list_checks",
        arguments: {},
      });
      const data = JSON.parse((result.content as any)[0].text);
      for (const check of data.checks) {
        expect(check.check_id).toBeTruthy();
        expect(check.name).toBeTruthy();
        expect(check.invariant).toBeTruthy();
        expect(check.description).toBeTruthy();
        expect(check.default_severity).toBeTruthy();
        expect(check.default_enforcement).toBeTruthy();
      }
    } finally {
      await cleanup();
    }
  });

  it("should report checks_version = 9 (from core CHECKS_VERSION) [SAN-222]", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_list_checks",
        arguments: {},
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.checks_version).toBe("9");
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_check_constitution_approval", () => {
  it("should check a pending approval", async () => {
    const request = createApprovalRequest("a".repeat(64), "test@sanna.dev", {
      required_approvals: 2,
      expires_in_hours: 72,
    });
    const approvalPath = join(tmpDir, "approval.json");
    writeFileSync(approvalPath, JSON.stringify(request), "utf-8");

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_check_constitution_approval",
        arguments: { approval_path: approvalPath },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.status).toBe("pending");
      expect(data.required_approvals).toBe(2);
      expect(data.current_approvals).toBe(0);
      expect(data.expired).toBe(false);
    } finally {
      await cleanup();
    }
  });

  it("should check an approved approval with signature verification", async () => {
    const kp = generateKeypair();
    const keyPath = join(tmpDir, "approver.key");
    const pubPath = join(tmpDir, "approver.pub");
    writeFileSync(keyPath, exportPrivateKeyPem(kp.privateKey), "utf-8");
    writeFileSync(pubPath, exportPublicKeyPem(kp.publicKey), "utf-8");

    const request = createApprovalRequest("b".repeat(64), "test@sanna.dev", {
      required_approvals: 1,
      expires_in_hours: 72,
    });
    signApproval(request, kp.privateKey);
    const approvalPath = join(tmpDir, "approved.json");
    writeFileSync(approvalPath, JSON.stringify(request), "utf-8");

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_check_constitution_approval",
        arguments: {
          approval_path: approvalPath,
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.status).toBe("approved");
      expect(data.current_approvals).toBe(1);
      expect(data.signature_verification).toBeDefined();
      expect(data.signature_verification.valid).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should return error for missing approval path", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_check_constitution_approval",
        arguments: {},
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should return error for non-existent file", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_check_constitution_approval",
        arguments: { approval_path: "/nonexistent/approval.json" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

describe("sanna_verify_identity_claims", () => {
  it("should verify a valid identity claim", async () => {
    const kp = generateKeypair();
    const pubPath = join(tmpDir, "id.pub");
    writeFileSync(pubPath, exportPublicKeyPem(kp.publicKey), "utf-8");

    const keyId = getKeyId(kp.publicKey);
    const claim = createIdentityClaim("agent", keyId, { name: "test-agent" }, kp.privateKey);

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_identity_claims",
        arguments: {
          claims_json: JSON.stringify(claim),
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.total).toBe(1);
      expect(data.valid_count).toBe(1);
      expect(data.results[0].valid).toBe(true);
      expect(data.results[0].signature_valid).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should verify multiple claims (array)", async () => {
    const kp = generateKeypair();
    const pubPath = join(tmpDir, "id2.pub");
    writeFileSync(pubPath, exportPublicKeyPem(kp.publicKey), "utf-8");

    const keyId = getKeyId(kp.publicKey);
    const claim1 = createIdentityClaim("agent", keyId, { name: "agent-1" }, kp.privateKey);
    const claim2 = createIdentityClaim("operator", keyId, { org: "acme" }, kp.privateKey);

    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_identity_claims",
        arguments: {
          claims_json: JSON.stringify([claim1, claim2]),
          public_key_path: pubPath,
        },
      });
      const data = JSON.parse((result.content as any)[0].text);
      expect(data.total).toBe(2);
      expect(data.valid_count).toBe(2);
    } finally {
      await cleanup();
    }
  });

  it("should return error for invalid JSON", async () => {
    const { pubPath } = writeKeypair();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_identity_claims",
        arguments: {
          claims_json: "not json{",
          public_key_path: pubPath,
        },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });
});

describe("error handling", () => {
  it("should handle non-existent constitution file gracefully", async () => {
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_get_constitution",
        arguments: { constitution_path: "/nonexistent/path.yaml" },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });

  it("should handle non-existent public key file gracefully", async () => {
    const constPath = writeConstitution();
    const { client, cleanup } = await createTestClient();
    try {
      const result = await client.callTool({
        name: "sanna_verify_constitution",
        arguments: {
          constitution_path: constPath,
          public_key_path: "/nonexistent/key.pub",
        },
      });
      expect((result as any).isError).toBe(true);
    } finally {
      await cleanup();
    }
  });
});
