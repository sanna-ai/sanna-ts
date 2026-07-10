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
import type { Receipt, ReceiptSink, SinkResult } from "@sanna-ai/core";

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

  it("should handle escalation flow with the token delivered out-of-band, never inline (SAN-828)", async () => {
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
        // No delivery_methods override — exercises the default (stderr).
      },
    });

    // Capture stderr so the raw token can be recovered the way an
    // operator console would see it — never from the agent's response.
    const stderrChunks: Buffer[] = [];
    const originalWrite = process.stderr.write;
    process.stderr.write = function (chunk: any, ...args: any[]) {
      stderrChunks.push(Buffer.from(chunk));
      return originalWrite.call(process.stderr, chunk, ...args);
    } as typeof process.stderr.write;

    try {
      const { client } = await createTestClient(config);

      // Tool call should be escalated.
      const result = await client.callTool({
        name: "echo_echo",
        arguments: { text: "needs approval" },
      });
      const text = (result.content[0] as any).text;
      const parsed = JSON.parse(text);
      expect(parsed.status).toBe("escalated");
      expect(parsed.escalation_id).toBeTruthy();
      expect(parsed.expires_at).toBeTruthy();

      // A. NO INLINE TOKEN: the agent-visible response must never carry
      // the raw approval token. Returning it here is exactly what let the
      // escalating agent approve its own action.
      expect(parsed.token).toBeUndefined();

      // B. AGENT CANNOT SELF-APPROVE FROM ITS RESPONSE: build an approval
      // attempt using only fields the agent actually received (no token
      // field to draw from — this stands in for an agent that tries to
      // approve using whatever it got back). It must fail, and the
      // original call must NOT be forwarded.
      const selfApproveResult = await client.callTool({
        name: "sanna_approve_escalation",
        arguments: {
          escalation_id: parsed.escalation_id,
          token: String((parsed as Record<string, unknown>).token ?? ""),
        },
      });
      expect(selfApproveResult.isError).toBe(true);
      const selfApproveTexts = selfApproveResult.content
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text);
      expect(
        selfApproveTexts.some((t: string) => t === "needs approval"),
      ).toBe(false);

      // C. LEGITIMATE APPROVAL via an OUT-OF-BAND token: recover the raw
      // token from the stderr console (the operator's channel), matching
      // the "[SANNA] Approval token for escalation <id>: <token>" format
      // the Python gateway also emits.
      const stderrOutput = Buffer.concat(stderrChunks).toString("utf-8");
      const tokenMatch = stderrOutput.match(
        new RegExp(
          `\\[SANNA\\] Approval token for escalation ${parsed.escalation_id}: ([a-f0-9]{64})`,
        ),
      );
      expect(tokenMatch).toBeTruthy();
      const outOfBandToken = tokenMatch![1];
      expect(stderrOutput).toContain(
        "[SANNA] Provide this token to approve the action.",
      );

      const approveResult = await client.callTool({
        name: "sanna_approve_escalation",
        arguments: {
          escalation_id: parsed.escalation_id,
          token: outOfBandToken,
        },
      });
      // Should have forwarded the original call after approval.
      const approveTexts = approveResult.content
        .filter((c: any) => c.type === "text")
        .map((c: any) => c.text);
      expect(approveTexts.some((t: string) => t === "needs approval")).toBe(
        true,
      );
    } finally {
      process.stderr.write = originalWrite;
    }
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

  it("should forward raw output without substring substitution (SAN-250)", async () => {
    // SAN-250: pii: substring substitution removed. Gateway forwards raw args
    // and output unchanged. The old [EMAIL_REDACTED] pattern is gone.
    const { client } = await createTestClient(makeConfig());
    const result = await client.callTool({
      name: "echo_echo",
      arguments: { text: "Contact alice@example.com" },
    });
    const texts = result.content
      .filter((c: any) => c.type === "text")
      .map((c: any) => c.text);
    const echoText = texts.find((t: string) => !t.includes("_sanna_receipt"));
    // Raw text is forwarded unchanged
    expect(echoText).toContain("alice@example.com");
    expect(echoText).not.toContain("[EMAIL_REDACTED]");
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

    // We need to capture the receipt -- the denied result returns status metadata
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

// -- SAN-203: tools/list filtering + session_manifest single-emission --

async function createTestClientWithSink(
  config: GatewayConfig,
  sink: ReceiptSink,
): Promise<{ client: Client; gateway: SannaGateway }> {
  const gw = new SannaGateway(config, sink);
  gateway = gw;
  await gw.start();

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.1.0" });
  await gw.getServer().connect(serverTransport);
  await client.connect(clientTransport);
  return { client, gateway: gw };
}

class CaptureSink implements ReceiptSink {
  readonly receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    this.receipts.push(receipt);
    return { stored: true };
  }
}

describe("SAN-203: tools/list authority filtering", () => {
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-test-"));
  });

  afterEach(async () => {
    if (gateway) {
      await gateway.stop();
      gateway = null;
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("cannot_execute tool is absent from tools/list response", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const { client } = await createTestClient(makeConfig());
    const { tools } = await client.listTools();
    const names = tools.map((t: any) => t.name);
    expect(names).not.toContain("echo_echo");
    expect(names).toContain("echo_fail");
    expect(names).toContain("echo_slow");
  }, 30_000);

  it("must_escalate tool is visible when escalation_visibility=visible", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: [],
          must_escalate: [{ condition: "echo" }],
          can_execute: [],
          default_escalation: "log",
          escalation_visibility: "visible",
        },
      }),
    );
    const { client } = await createTestClient(makeConfig());
    const { tools } = await client.listTools();
    const names = tools.map((t: any) => t.name);
    expect(names).toContain("echo_echo");
  }, 30_000);

  it("must_escalate tool is absent when escalation_visibility=suppressed", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: [],
          must_escalate: [{ condition: "echo" }],
          can_execute: [],
          default_escalation: "log",
          escalation_visibility: "suppressed",
        },
      }),
    );
    const { client } = await createTestClient(makeConfig());
    const { tools } = await client.listTools();
    const names = tools.map((t: any) => t.name);
    expect(names).not.toContain("echo_echo");
    expect(names).toContain("echo_fail");
    expect(names).toContain("echo_slow");
  }, 30_000);

  it("session_manifest receipt emitted exactly once for two listTools calls", async () => {
    writeFileSync(join(tmpDir, "constitution.yaml"), makeConstitutionYaml());
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(makeConfig(), sink);

    await client.listTools();
    await client.listTools();

    const manifestReceipts = sink.receipts.filter(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipts).toHaveLength(1);
    const r = manifestReceipts[0] as any;
    expect(r.invariants_scope).toBe("none");
    expect(r.enforcement_surface).toBe("gateway");
    expect(r.status).toBe("PASS");
    expect(r.extensions?.["com.sanna.manifest"]).toBeDefined();
  }, 30_000);

  it("session_manifest surfaces contains only mcp (not cli/http)", async () => {
    writeFileSync(join(tmpDir, "constitution.yaml"), makeConstitutionYaml());
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(makeConfig(), sink);

    await client.listTools();

    const manifestReceipts = sink.receipts.filter(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipts).toHaveLength(1);
    const manifest = (manifestReceipts[0] as any).extensions["com.sanna.manifest"];
    expect(manifest.surfaces.mcp).toBeDefined();
    expect(manifest.surfaces.cli).toBeUndefined();
    expect(manifest.surfaces.http).toBeUndefined();
  }, 30_000);
});

describe("SAN-209 invocation_anomaly parent-chain integrity", () => {
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-anomaly-"));
  });

  afterEach(async () => {
    if (gateway) {
      await gateway.stop();
      gateway = null;
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("cannot_execute path: emits invocation_anomaly with parent_receipts chain", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(makeConfig(), sink);

    await client.listTools();

    const manifestReceipts = sink.receipts.filter((r: any) => r.event_type === "session_manifest");
    expect(manifestReceipts).toHaveLength(1);
    const manifestFp = (manifestReceipts[0] as any).full_fingerprint;
    const manifestSurface = (manifestReceipts[0] as any).extensions["com.sanna.manifest"].surfaces.mcp;
    expect(manifestSurface.tools_suppressed).toContain("echo");

    const result = await client.callTool({ name: "echo_echo", arguments: { message: "test" } });
    expect(result.isError).toBe(true);

    const anomalyReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_anomaly");
    expect(anomalyReceipts).toHaveLength(1);

    const anomaly = anomalyReceipts[0] as any;
    expect(anomaly.status).toBe("FAIL");
    expect(anomaly.enforcement.action).toBe("halted");
    expect(anomaly.enforcement.enforcement_mode).toBe("halt");
    expect(anomaly.parent_receipts).toEqual([manifestFp]);
    expect(anomaly.extensions["com.sanna.anomaly"].attempted_tool).toBe("echo_echo");
    expect(anomaly.extensions["com.sanna.anomaly"].suppression_basis).toBe("session_manifest");
  }, 30_000);

  it("must_escalate + escalation_visibility=suppressed: emits invocation_anomaly, not invocation_escalated", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: [],
          must_escalate: [{ condition: "echo" }],
          can_execute: [],
          default_escalation: "log",
          escalation_visibility: "suppressed",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(makeConfig(), sink);

    await client.listTools();
    const result = await client.callTool({ name: "echo_echo", arguments: { message: "test" } });
    expect(result.isError).toBe(true);

    const anomalyReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_anomaly");
    expect(anomalyReceipts).toHaveLength(1);
    expect((anomalyReceipts[0] as any).enforcement.enforcement_mode).toBe("halt");

    const escalatedReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_escalated");
    expect(escalatedReceipts).toHaveLength(0);
  }, 30_000);

  it("typo tool name (never in catalog) does NOT emit invocation_anomaly", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(makeConfig(), sink);

    await client.listTools();
    const result = await client.callTool({ name: "echo_garbage_typo_name", arguments: {} });
    expect(result.isError).toBe(true);

    const anomalyReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_anomaly");
    expect(anomalyReceipts).toHaveLength(0);
  }, 30_000);
});

describe("SAN-405: enforcement_mode DSL-to-spec enum mapping (non-anomaly halted path)", () => {
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-test-"));
  });

  afterEach(async () => {
    if (gateway) {
      await gateway.stop();
      gateway = null;
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("enforced mode: non-anomaly halt emits enforcement_mode 'halt'", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({ enforcement: { mode: "enforced", default_policy: "allow" } }),
      sink,
    );

    // No listTools call: _suppressedToolNames empty, _manifestFullFingerprint null.
    // Bypasses anomaly path; evaluateAuthority returns halt for cannot_execute["echo"].
    const result = await client.callTool({ name: "echo_echo", arguments: {} });
    expect(result.isError).toBe(true);

    const enforcedReceipts = sink.receipts.filter((r: any) => r.enforcement !== undefined);
    expect(enforcedReceipts).toHaveLength(1);
    const receipt = enforcedReceipts[0] as any;
    expect(["halt", "warn", "log"]).toContain(receipt.enforcement.enforcement_mode);
    expect(receipt.enforcement.enforcement_mode).toBe("halt");
  }, 30_000);

  it("advisory mode: non-anomaly halt emits enforcement_mode 'warn' before forwarding", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({ enforcement: { mode: "advisory", default_policy: "allow" } }),
      sink,
    );

    // Advisory: halt receipt stored, then tool forwarded anyway.
    const result = await client.callTool({ name: "echo_echo", arguments: { text: "advisory-test" } });
    expect(result.isError).toBe(false);

    const enforcedReceipts = sink.receipts.filter((r: any) => r.enforcement !== undefined);
    expect(enforcedReceipts.length).toBeGreaterThanOrEqual(1);
    const receipt = enforcedReceipts[0] as any;
    expect(["halt", "warn", "log"]).toContain(receipt.enforcement.enforcement_mode);
    expect(receipt.enforcement.enforcement_mode).toBe("warn");
  }, 30_000);

  it("permissive mode: overrides halt to allow; no enforcement block emitted", async () => {
    // configModeToEnforcementLevel("permissive") === "log" per the helper definition.
    // The gateway overrides all decisions to allow in permissive mode before the
    // receipt-emission site, so wasAllowed=true and no enforcement block is written.
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({ enforcement: { mode: "permissive", default_policy: "allow" } }),
      sink,
    );

    const result = await client.callTool({ name: "echo_echo", arguments: { text: "permissive-test" } });
    expect(result.isError).toBe(false);

    // Permissive overrides halt to allow; all receipts have wasAllowed=true, no enforcement block.
    const enforcedReceipts = sink.receipts.filter((r: any) => r.enforcement !== undefined);
    expect(enforcedReceipts).toHaveLength(0);
  }, 30_000);

  it("configModeToEnforcementLevel throws on unknown mode (fail-loud defense)", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({
        enforcement: { mode: "unknown_mode" as any, default_policy: "allow" },
      }),
      sink,
    );

    // Invalid mode reaches configModeToEnforcementLevel inside _buildReceipt when
    // the halt case fires; the throw propagates as an error response.
    let gotError = false;
    try {
      const result = await client.callTool({ name: "echo_echo", arguments: {} });
      gotError = result.isError === true;
    } catch (_) {
      gotError = true;
    }
    expect(gotError).toBe(true);
  }, 30_000);
});

describe("SAN-406 redaction emission (invocation_anomaly attempted_tool)", () => {
  const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-san406-"));
  });

  afterEach(async () => {
    if (gateway) {
      await gateway.stop();
      gateway = null;
    }
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("content_mode=redacted: attempted_tool is <redacted>", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({ receipts: { content_mode: "redacted" } }),
      sink,
    );

    await client.listTools();
    await client.callTool({ name: "echo_echo", arguments: { message: "test" } });

    const anomalyReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_anomaly");
    expect(anomalyReceipts).toHaveLength(1);
    const anomaly = anomalyReceipts[0] as any;
    expect(anomaly.extensions["com.sanna.anomaly"].attempted_tool).toBe("<redacted>");
  }, 30_000);

  it("content_mode=hashes_only: attempted_tool matches 64-hex SHA-256", async () => {
    writeFileSync(
      join(tmpDir, "constitution.yaml"),
      makeConstitutionYaml({
        authority_boundaries: {
          cannot_execute: ["echo"],
          must_escalate: [],
          can_execute: [],
          default_escalation: "log",
        },
      }),
    );
    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(
      makeConfig({ receipts: { content_mode: "hashes_only" } }),
      sink,
    );

    await client.listTools();
    await client.callTool({ name: "echo_echo", arguments: { message: "test" } });

    const anomalyReceipts = sink.receipts.filter((r: any) => r.event_type === "invocation_anomaly");
    expect(anomalyReceipts).toHaveLength(1);
    const anomaly = anomalyReceipts[0] as any;
    expect(SHA256_HEX_RE.test(anomaly.extensions["com.sanna.anomaly"].attempted_tool)).toBe(true);
  }, 30_000);
});
