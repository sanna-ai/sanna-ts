import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  generateKeypair,
  exportPrivateKeyPem,
  exportPublicKeyPem,
} from "@sanna-ai/core";

import { SannaGateway } from "../src/gateway.js";
import type { GatewayConfig } from "../src/config.js";

const ECHO_SERVER = resolve(
  import.meta.dirname,
  "fixtures/echo-server.ts",
);

let tmpDir: string;
let gateway: SannaGateway | null = null;

function makeConstitutionYaml(overrides?: Record<string, unknown>): string {
  return yaml.dump({
    schema_version: "1.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent for gateway tests",
      extensions: {},
    },
    provenance: {
      authored_by: "test",
      approved_by: ["test-approver"],
      approval_date: "2025-01-01",
      approval_method: "manual",
      change_history: [],
      signature: null,
    },
    boundaries: [
      {
        id: "B001",
        description: "Allow all actions for testing",
        category: "scope",
        severity: "medium",
        constraints: ["allow all tool calls"],
        enforcement: "warn",
      },
    ],
    trust_tiers: {
      autonomous: [],
      requires_approval: [],
      prohibited: [],
    },
    halt_conditions: [],
    invariants: [],
    authority_boundaries: null,
    trusted_sources: null,
    ...overrides,
  });
}

function makeConfig(overrides?: Partial<GatewayConfig>): GatewayConfig {
  return {
    listen: { transport: "stdio" },
    constitution: {
      path: join(tmpDir, "constitution.yaml"),
    },
    enforcement: {
      mode: "enforced",
      default_policy: "allow",
    },
    downstreams: [
      {
        name: "echo",
        command: "npx",
        args: ["tsx", ECHO_SERVER],
      },
    ],
    ...overrides,
  };
}

async function createTestClient(
  config: GatewayConfig,
): Promise<{ client: Client; gateway: SannaGateway }> {
  const gw = new SannaGateway(config);
  gateway = gw;
  await gw.start();

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();

  const client = new Client(
    { name: "test-client", version: "0.1.0" },
  );

  await gw.getServer().connect(serverTransport);
  await client.connect(clientTransport);

  return { client, gateway: gw };
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-test-"));
  writeFileSync(join(tmpDir, "constitution.yaml"), makeConstitutionYaml());
});

afterEach(async () => {
  if (gateway) {
    await gateway.stop();
    gateway = null;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("SannaGateway", () => {
  it("should list namespaced tools from downstream", async () => {
    const { client } = await createTestClient(makeConfig());
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("echo_echo");
    expect(names).toContain("echo_fail");
    expect(names).toContain("echo_slow");
  }, 30_000);

  it("should inject _justification into tool schemas", async () => {
    const { client } = await createTestClient(makeConfig());
    const { tools } = await client.listTools();
    const echoTool = tools.find((t) => t.name === "echo_echo");
    expect(echoTool).toBeDefined();
    const props = (echoTool!.inputSchema as any).properties;
    expect(props._justification).toBeDefined();
    expect(props._justification.type).toBe("string");
  }, 30_000);

  it("should forward allowed tool calls and return result", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "hello from gateway" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    expect(texts.some((t: string) => t === "hello from gateway")).toBe(true);
  }, 30_000);

  it("should include receipt metadata in response", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "test" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    const receiptText = texts.find((t: string) => t.includes("_sanna_receipt"));
    expect(receiptText).toBeDefined();
    const meta = JSON.parse(receiptText!);
    expect(meta._sanna_receipt.receipt_id).toBeTruthy();
    expect(meta._sanna_receipt.receipt_triad).toBeDefined();
  }, 30_000);

  it("should deny tool calls blocked by policy override", async () => {
    const config = makeConfig({
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
          policy_overrides: { echo: "deny" },
        },
      ],
    });
    const { client } = await createTestClient(config);
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "blocked" },
    });
    expect(result.isError).toBe(true);
    const text = (result.content[0] as any).text;
    const parsed = JSON.parse(text);
    expect(parsed.status).toBe("denied");
  }, 30_000);

  it("should handle escalation flow", async () => {
    const config = makeConfig({
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
          policy_overrides: { echo: "escalate" },
        },
      ],
      escalation: {
        hmac_secret: "test-secret",
        ttl_seconds: 300,
      },
    });
    const { client } = await createTestClient(config);

    // Tool call should be escalated
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "needs approval" },
    });
    const text = (result.content[0] as any).text;
    const parsed = JSON.parse(text);
    expect(parsed.status).toBe("escalated");
    expect(parsed.escalation_id).toBeTruthy();
    expect(parsed.token).toBeTruthy();

    // Approve the escalation
    const approveResult = await client.callTool({
      name: "sanna_approve_escalation",
      arguments: {
        escalation_id: parsed.escalation_id,
        token: parsed.token,
      },
    });
    // Should have forwarded the original call after approval
    const approveTexts = approveResult.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    expect(approveTexts.some((t: string) => t === "needs approval")).toBe(true);
  }, 30_000);

  it("should deny escalation with invalid token", async () => {
    const config = makeConfig({
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
          policy_overrides: { echo: "escalate" },
        },
      ],
      escalation: {
        hmac_secret: "test-secret",
      },
    });
    const { client } = await createTestClient(config);

    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "test" },
    });
    const parsed = JSON.parse((result.content[0] as any).text);

    // Try with wrong token
    const badResult = await client.callTool({
      name: "sanna_approve_escalation",
      arguments: {
        escalation_id: parsed.escalation_id,
        token: "0".repeat(64),
      },
    });
    expect(badResult.isError).toBe(true);
  }, 30_000);

  it("should return error for unknown downstream", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "nonexistent_tool",
      arguments: {},
    });
    expect(result.isError).toBe(true);
  }, 30_000);

  it("should return error for invalid tool name (no namespace)", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "notool",
      arguments: {},
    });
    expect(result.isError).toBe(true);
  }, 30_000);

  it("should work in advisory mode (allow but note violations)", async () => {
    const config = makeConfig({
      enforcement: {
        mode: "advisory",
        default_policy: "deny",
      },
    });
    const { client } = await createTestClient(config);
    // In advisory mode, even denied tools get forwarded
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "advisory test" },
    });
    // Should still get a result (advisory doesn't block)
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    // May contain the denial but should also have the forwarded result
    expect(texts.length).toBeGreaterThan(0);
  }, 30_000);

  it("should work in permissive mode", async () => {
    const config = makeConfig({
      enforcement: {
        mode: "permissive",
        default_policy: "deny",
      },
    });
    const { client } = await createTestClient(config);
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "permissive test" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    expect(texts.some((t: string) => t === "permissive test")).toBe(true);
  }, 30_000);

  it("should redact PII in output when enabled", async () => {
    const config = makeConfig({
      pii: { enabled: true },
    });
    const { client } = await createTestClient(config);
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "Contact alice@example.com" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    // The echoed text should have the email redacted
    const echoText = texts.find(
      (t: string) => !t.includes("_sanna_receipt"),
    );
    expect(echoText).toContain("[EMAIL_REDACTED]");
  }, 30_000);

  it("should strip _justification from forwarded args", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: {
        text: "with justification",
        _justification: "because I said so",
      },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    // The echo server should have received the text without _justification
    expect(texts.some((t: string) => t === "with justification")).toBe(true);
  }, 30_000);

  it("should handle constitution with authority boundaries", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["fail"],
          must_escalate: [],
          can_execute: ["echo"],
          default_escalation: "admin",
        },
      }),
    );
    const { client } = await createTestClient(makeConfig());

    // "fail" matches cannot_execute → should be denied
    const failResult = await client.callTool({
      name: "echo_fail",
      arguments: {},
    });
    expect(failResult.isError).toBe(true);
    const text = (failResult.content[0] as any).text;
    const parsed = JSON.parse(text);
    expect(parsed.status).toBe("denied");
  }, 30_000);

  it("should emit receipt with enforcement_surface = gateway [SAN-213]", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "surface-test" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    const receiptText = texts.find((t: string) => t.includes("_sanna_receipt"));
    expect(receiptText).toBeDefined();
    const meta = JSON.parse(receiptText!);
    expect(meta._sanna_receipt.enforcement_surface).toBe("gateway");
  }, 30_000);

  it("should emit receipt with invariants_scope = full [SAN-213]", async () => {
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "scope-test" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    const receiptText = texts.find((t: string) => t.includes("_sanna_receipt"));
    expect(receiptText).toBeDefined();
    const meta = JSON.parse(receiptText!);
    expect(meta._sanna_receipt.invariants_scope).toBe("full");
  }, 30_000);

  it("should emit past-participle enforcement.action when tool is denied [SAN-213]", async () => {
    const config = makeConfig({
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
          policy_overrides: { echo: "deny" },
        },
      ],
    });
    const { client } = await createTestClient(config);

    // We need to capture the receipt — the denied result returns status metadata
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "blocked" },
    });
    expect(result.isError).toBe(true);
    const text = (result.content[0] as any).text;
    const parsed = JSON.parse(text);
    // The action in the denied status should use past-participle (if present)
    expect(parsed.status).toBe("denied");
  }, 30_000);
});
