import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Receipt, ReceiptSink, SinkResult } from "@sanna-ai/core";

import { SannaGateway } from "../src/gateway.js";
import type { GatewayConfig } from "../src/config.js";

vi.mock("@sanna-ai/core", async (importOriginal) => {
  const mod = await importOriginal<typeof import("@sanna-ai/core")>();
  return {
    ...mod,
    generateManifest: vi.fn((...args: Parameters<typeof mod.generateManifest>) =>
      mod.generateManifest(...args),
    ),
  };
});

const ECHO_SERVER = resolve(import.meta.dirname, "fixtures/echo-server.ts");

let tmpDir: string;
let gateway: SannaGateway | null = null;

function makeConstitutionYaml(): string {
  return yaml.dump({
    schema_version: "1.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent for fail-closed tests",
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
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [],
    authority_boundaries: null,
    trusted_sources: null,
  });
}

function makeConfig(): GatewayConfig {
  return {
    listen: { transport: "stdio" },
    constitution: { path: join(tmpDir, "constitution.yaml") },
    enforcement: { mode: "enforced", default_policy: "allow" },
    downstreams: [{ name: "echo", command: "npx", args: ["tsx", ECHO_SERVER] }],
  };
}

class CaptureSink implements ReceiptSink {
  readonly receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    this.receipts.push(receipt);
    return { stored: true };
  }
}

async function startGateway(
  config: GatewayConfig,
  sink?: ReceiptSink,
): Promise<{ client: Client; gw: SannaGateway }> {
  const gw = new SannaGateway(config, sink);
  gateway = gw;
  await gw.start();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.1.0" });
  await gw.getServer().connect(serverTransport);
  await client.connect(clientTransport);
  return { client, gw };
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-fc-test-"));
  writeFileSync(join(tmpDir, "constitution.yaml"), makeConstitutionYaml());
});

afterEach(async () => {
  if (gateway) {
    await gateway.stop();
    gateway = null;
  }
  rmSync(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("SAN-359: gateway fail-closed on manifest failure", () => {
  it("returns empty tools when manifest generation fails", async () => {
    const { generateManifest } = await import("@sanna-ai/core");
    vi.mocked(generateManifest).mockImplementationOnce(() => {
      throw new Error("mock: generateManifest failure");
    });

    const { client } = await startGateway(makeConfig());
    const { tools } = await client.listTools();

    expect(tools).toHaveLength(0);
  }, 30_000);

  it("returns empty tools when manifest persistence fails", async () => {
    const { client, gw } = await startGateway(makeConfig());

    vi.spyOn(gw as any, "_storeReceipt").mockImplementationOnce(() => {
      throw new Error("mock: persistence failure");
    });

    const { tools } = await client.listTools();

    expect(tools).toHaveLength(0);
  }, 30_000);

  it("_manifestFailed is sticky across subsequent calls", async () => {
    const { generateManifest } = await import("@sanna-ai/core");
    vi.mocked(generateManifest).mockImplementationOnce(() => {
      throw new Error("mock: sticky failure");
    });

    const { client } = await startGateway(makeConfig());

    const first = await client.listTools();
    expect(first.tools).toHaveLength(0);

    // Second call: no mock active, but sticky _manifestFailed should still return []
    const second = await client.listTools();
    expect(second.tools).toHaveLength(0);
  }, 30_000);

  it("normal success path returns full filtered tools", async () => {
    const { client } = await startGateway(makeConfig());
    const { tools } = await client.listTools();

    expect(tools.length).toBeGreaterThan(0);
    const names = tools.map((t) => t.name);
    expect(names).toContain("echo_echo");
  }, 30_000);

  it("FAIL-status receipt emitted on generation failure (best-effort)", async () => {
    const { generateManifest } = await import("@sanna-ai/core");
    vi.mocked(generateManifest).mockImplementationOnce(() => {
      throw new Error("mock: generateManifest failure");
    });

    const sink = new CaptureSink();
    const { client } = await startGateway(makeConfig(), sink);
    await client.listTools();

    const manifestReceipts = sink.receipts.filter(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipts.length).toBeGreaterThan(0);
    const failReceipt = manifestReceipts[0] as any;
    expect(failReceipt.status).toBe("FAIL");
  }, 30_000);

  it("unexpected exception in _emitSessionManifest caught by handler", async () => {
    const { client, gw } = await startGateway(makeConfig());

    vi.spyOn(gw as any, "_emitSessionManifest").mockRejectedValueOnce(
      new Error("mock: unexpected throw bypassing internal catch"),
    );

    const { tools } = await client.listTools();

    expect(tools).toHaveLength(0);
    expect((gw as any)._manifestFailed).toBe(true);
  }, 30_000);

  it("empty tools response has no tool names or metadata", async () => {
    const { generateManifest } = await import("@sanna-ai/core");
    vi.mocked(generateManifest).mockImplementationOnce(() => {
      throw new Error("mock: generation failure");
    });

    const { client } = await startGateway(makeConfig());
    const response = await client.listTools();

    expect(response.tools).toEqual([]);
    expect(Object.keys(response)).not.toContain("error");
  }, 30_000);
});

describe("SAN-380: concurrent tools/list shared-promise pattern", () => {
  it("concurrent tools/list calls emit exactly one session_manifest", async () => {
    const sink = new CaptureSink();
    const { client } = await startGateway(makeConfig(), sink);

    // Fire two listTools concurrently
    const [r1, r2] = await Promise.all([client.listTools(), client.listTools()]);

    const manifestReceipts = sink.receipts.filter(
      (r: any) => r.event_type === "session_manifest",
    );
    expect(manifestReceipts).toHaveLength(1);

    // Both calls should return the same non-empty tools list
    expect(r1.tools.length).toBeGreaterThan(0);
    expect(r2.tools.length).toBeGreaterThan(0);
  }, 30_000);

  it("second concurrent call waits for emission to complete", async () => {
    const sink = new CaptureSink();
    const { client, gw } = await startGateway(makeConfig(), sink);

    // Wrap _emitSessionManifest with a 100ms delay
    const original = (gw as any)._emitSessionManifest.bind(gw);
    let emitCount = 0;
    vi.spyOn(gw as any, "_emitSessionManifest").mockImplementation(async () => {
      emitCount++;
      await new Promise((resolve) => setTimeout(resolve, 100));
      return original();
    });

    const start = Date.now();
    const [r1, r2] = await Promise.all([client.listTools(), client.listTools()]);
    const elapsed = Date.now() - start;

    // Only one emission should have fired
    expect(emitCount).toBe(1);

    // Both calls should have waited for the delayed emission (>= 100ms)
    expect(elapsed).toBeGreaterThanOrEqual(100);

    // Both calls should return tools once emission completes
    expect(r1.tools.length).toBeGreaterThan(0);
    expect(r2.tools.length).toBeGreaterThan(0);
  }, 30_000);
});
