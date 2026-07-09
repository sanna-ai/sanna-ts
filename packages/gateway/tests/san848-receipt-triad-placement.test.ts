/**
 * SAN-848: gateway Receipt Triad placement + fingerprint coverage.
 *
 * Regression coverage for two bugs:
 *  1. The gateway used to attach the Receipt Triad as a TOP-LEVEL
 *     `receipt_triad` property. The canonical receipt.schema.json has
 *     `additionalProperties: false` at the top level and does not declare
 *     `receipt_triad` there -- every such receipt failed full JSON-schema
 *     validation. The fix nests the triad at
 *     extensions["com.sanna.gateway"].receipt_triad, matching the Python
 *     gateway (sanna.gateway.server._generate_receipt).
 *  2. `action_hash` used to hash the real downstream tool result -- a
 *     semantic contradiction of the gateway-boundary definition (the
 *     gateway is a proxy and cannot attest to what the downstream server
 *     actually executed). The fix sets action_hash = input_hash with
 *     context_limitation = "gateway_boundary", matching Python's
 *     compute_receipt_triad.
 *
 * The crux of this ticket is that the triad must live INSIDE the
 * `extensions` object passed into generateReceipt (packages/core/src/
 * receipt.ts computeFingerprintInput hashes `extensions` into the
 * fingerprint), not bolted on after the fact. These tests prove that by
 * recomputing the fingerprint of a real, gateway-emitted, signed receipt
 * from its own content and asserting it matches the receipt's stated
 * full_fingerprint -- if the triad were still fingerprint-uncovered, or if
 * redaction silently invalidated it, this recompute would diverge.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import yaml from "js-yaml";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import Ajv2020 from "ajv/dist/2020.js";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
import addFormats from "ajv-formats";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  generateKeypair,
  exportPrivateKeyPem,
  computeFingerprints,
  verifyReceipt,
} from "@sanna-ai/core";
import type { Receipt, ReceiptSink, SinkResult, KeyObject } from "@sanna-ai/core";

import { SannaGateway } from "../src/gateway.js";
import type { GatewayConfig } from "../src/config.js";

const ECHO_SERVER = resolve(import.meta.dirname, "fixtures/echo-server.ts");

// ── Full canonical receipt.schema.json validator ────────────────────────
//
// packages/core/src/verifier.ts's own Ajv validator intentionally compiles
// ONLY the schema's `allOf` conditional rules, not the full properties /
// required / additionalProperties:false definition (see the comment on
// getAjvValidator there) -- that slice does not catch a stray top-level
// property such as the old top-level `receipt_triad` this ticket removes.
// This validator compiles the COMPLETE schema (the same file the core
// verifier reads from -- not a vendored copy) so these tests independently
// prove full-schema conformance, including additionalProperties:false.
type AjvValidateFn = ((data: unknown) => boolean) & {
  errors?: Array<{ message?: string; keyword?: string; instancePath?: string }> | null;
};

let _fullSchemaValidate: AjvValidateFn | null = null;

function getFullSchemaValidator(): AjvValidateFn {
  if (_fullSchemaValidate) return _fullSchemaValidate;
  const schemaPath = resolve(
    import.meta.dirname,
    "../../../spec/schemas/receipt.schema.json",
  );
  const fullSchema = JSON.parse(readFileSync(schemaPath, "utf-8"));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ajv = new (Ajv2020 as any)({ allErrors: true, strict: false });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (addFormats as any)(ajv);
  _fullSchemaValidate = ajv.compile(fullSchema) as AjvValidateFn;
  return _fullSchemaValidate;
}

// ── Test scaffolding (mirrors gateway.test.ts's CaptureSink pattern) ────

let tmpDir: string;
let gateway: SannaGateway | null = null;

function makeConstitutionYaml(): string {
  return yaml.dump({
    schema_version: "1.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "SAN-848 receipt triad placement tests",
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
  });
}

class CaptureSink implements ReceiptSink {
  readonly receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    // Snapshot synchronously at store-time via structuredClone, mirroring
    // what the real sinks do: LocalSQLiteSink JSON.stringifies the receipt
    // synchronously inside save() (packages/core/src/store.ts), so it
    // persists the object graph as it exists at the moment store() is
    // called -- not whatever a caller mutates afterward. Capturing a live
    // reference here instead would leak an unrelated, pre-existing defect
    // into this test: the gateway's allow-path response construction
    // (packages/gateway/src/gateway.ts _handleToolCall, "m. Return result
    // with receipt metadata") pushes the `_sanna_receipt` summary block
    // onto `resultContent`, which is the SAME array object as
    // `receipt.outputs.content` (set via `outputs: { content:
    // result.content }` in _buildReceipt without cloning). That in-place
    // mutation happens AFTER generateReceipt/signReceipt have already
    // fingerprinted and signed the receipt, so a sink that retains a live
    // object reference (rather than serializing immediately, as the
    // shipping sinks do) would observe a receipt whose outputs.content no
    // longer matches what was actually signed -- a real, separate
    // self-consistency defect, but not the one SAN-848 is about (it is
    // orthogonal to where the Receipt Triad lives). Flagged in the SAN-848
    // report as a discovered follow-up rather than fixed here, per this
    // ticket's own precedent of halting and reporting pre-existing
    // invariant breaks instead of quietly working around them.
    this.receipts.push(structuredClone(receipt));
    return { success: true };
  }
}

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

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-san848-"));
});

afterEach(async () => {
  if (gateway) {
    await gateway.stop();
    gateway = null;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

// ── Shared fixture: drive allow + halt + escalate through a signed gateway ──

interface ThreeDispositions {
  allow: Record<string, unknown>;
  halt: Record<string, unknown>;
  escalate: Record<string, unknown>;
  publicKey: KeyObject;
}

async function driveThreeDispositions(): Promise<ThreeDispositions> {
  const constitutionPath = join(tmpDir, "constitution.yaml");
  writeFileSync(constitutionPath, makeConstitutionYaml());

  // Signing key only (no public_key_path): exercises receipt signing
  // without also invoking constitution-signature verification, which is
  // out of scope here. The in-memory publicKey is used directly below.
  const { privateKey, publicKey } = generateKeypair();
  const privKeyPath = join(tmpDir, "private.pem");
  writeFileSync(privKeyPath, exportPrivateKeyPem(privateKey));

  const config: GatewayConfig = {
    listen: { transport: "stdio" },
    constitution: {
      path: constitutionPath,
      signing_key_path: privKeyPath,
    },
    enforcement: { mode: "enforced", default_policy: "allow" },
    downstreams: [
      {
        name: "echo",
        command: "npx",
        args: ["tsx", ECHO_SERVER],
        policy_overrides: { fail: "deny", slow: "escalate" },
      },
    ],
    escalation: { hmac_secret: "test-secret-san848", ttl_seconds: 300 },
  };

  const sink = new CaptureSink();
  const { client } = await createTestClientWithSink(config, sink);

  // Allow path
  await client.callTool({ name: "echo_echo", arguments: { text: "san848-allow" } });
  // Halt path (policy override -> deny)
  await client.callTool({ name: "echo_fail", arguments: {} });
  // Escalate path (policy override -> escalate; left unapproved)
  await client.callTool({ name: "echo_slow", arguments: { delay_ms: 5 } });

  expect(sink.receipts).toHaveLength(3);
  const receipts = sink.receipts as unknown as Record<string, unknown>[];
  const allow = receipts.find((r) => r.enforcement === undefined);
  const halt = receipts.find(
    (r) => (r.enforcement as Record<string, unknown> | undefined)?.action === "halted",
  );
  const escalate = receipts.find(
    (r) => (r.enforcement as Record<string, unknown> | undefined)?.action === "escalated",
  );

  if (!allow || !halt || !escalate) {
    throw new Error(
      "Failed to identify all three dispositions among captured receipts: " +
        `allow=${!!allow} halt=${!!halt} escalate=${!!escalate}`,
    );
  }

  return { allow, halt, escalate, publicKey };
}

const LABELED = (d: ThreeDispositions) =>
  [
    ["allow", d.allow] as const,
    ["halt", d.halt] as const,
    ["escalate", d.escalate] as const,
  ];

// ── Tests ────────────────────────────────────────────────────────────

describe("SAN-848: gateway Receipt Triad placement + fingerprint coverage", () => {
  it("triad lives at extensions['com.sanna.gateway'].receipt_triad with gateway-boundary semantics", async () => {
    const dispositions = await driveThreeDispositions();

    for (const [label, receipt] of LABELED(dispositions)) {
      // Old bug: top-level `receipt_triad` property. Must be gone.
      expect("receipt_triad" in receipt, label).toBe(false);

      const extensions = receipt.extensions as Record<string, unknown> | undefined;
      expect(extensions, label).toBeDefined();
      const gwExt = extensions?.["com.sanna.gateway"] as Record<string, unknown> | undefined;
      expect(gwExt, label).toBeDefined();
      const triad = gwExt?.receipt_triad as Record<string, unknown> | undefined;
      expect(triad, label).toBeDefined();

      expect(typeof triad?.input_hash).toBe("string");
      expect(typeof triad?.reasoning_hash).toBe("string");
      expect(triad?.action_hash).toBe(triad?.input_hash);
      expect(triad?.context_limitation).toBe("gateway_boundary");
    }
  }, 30_000);

  it("self-consistency: fingerprint recompute + signature verify hold for allow, halt, and escalate receipts", async () => {
    const dispositions = await driveThreeDispositions();

    for (const [, receipt] of LABELED(dispositions)) {
      const { receipt_fingerprint, full_fingerprint } = computeFingerprints(receipt);
      expect(full_fingerprint).toBe(receipt.full_fingerprint);
      expect(receipt_fingerprint).toBe(receipt.receipt_fingerprint);

      expect(receipt.receipt_signature).toBeTruthy();
      const result = verifyReceipt(receipt, dispositions.publicKey);
      const sigErrors = result.errors.filter((e) => /signature/i.test(e));
      expect(sigErrors).toEqual([]);
    }
  }, 30_000);

  it("full-schema validation: each emitted receipt passes the complete canonical receipt.schema.json", async () => {
    const dispositions = await driveThreeDispositions();
    const validate = getFullSchemaValidator();

    for (const [, receipt] of LABELED(dispositions)) {
      const valid = validate(receipt);
      if (!valid) {
        throw new Error(`Schema validation failed: ${JSON.stringify(validate.errors)}`);
      }
      expect(valid).toBe(true);
    }
  }, 30_000);

  it("negative control: a stray top-level property (the old bug's shape) fails full-schema validation", async () => {
    const dispositions = await driveThreeDispositions();
    const validate = getFullSchemaValidator();

    // Sanity: the real, fixed-shape receipt passes.
    expect(validate(dispositions.allow)).toBe(true);

    // Reintroduce the exact bug this ticket fixes: bolt the triad on as a
    // top-level property instead of nesting it under extensions.
    const tampered = {
      ...dispositions.allow,
      receipt_triad: {
        input_hash: "a".repeat(64),
        reasoning_hash: "b".repeat(64),
        action_hash: "a".repeat(64),
        context_limitation: "gateway_boundary",
      },
    };
    const valid = validate(tampered);
    expect(valid).toBe(false);
    expect(validate.errors?.some((e) => e.keyword === "additionalProperties")).toBe(true);
  }, 30_000);

  it("redaction-enabled: a redacted gateway receipt still passes its own fingerprint recomputation", async () => {
    const constitutionPath = join(tmpDir, "constitution.yaml");
    writeFileSync(constitutionPath, makeConstitutionYaml());

    const { privateKey, publicKey } = generateKeypair();
    const privKeyPath = join(tmpDir, "private.pem");
    writeFileSync(privKeyPath, exportPrivateKeyPem(privateKey));

    const config: GatewayConfig = {
      listen: { transport: "stdio" },
      constitution: {
        path: constitutionPath,
        signing_key_path: privKeyPath,
      },
      enforcement: { mode: "enforced", default_policy: "allow" },
      downstreams: [
        {
          name: "echo",
          command: "npx",
          args: ["tsx", ECHO_SERVER],
        },
      ],
      redaction: { enabled: true },
    };

    const sink = new CaptureSink();
    const { client } = await createTestClientWithSink(config, sink);

    await client.callTool({ name: "echo_echo", arguments: { text: "san848-redacted" } });

    expect(sink.receipts).toHaveLength(1);
    const receipt = sink.receipts[0] as unknown as Record<string, unknown>;

    // Fingerprint self-consistency holds even with redaction enabled: the
    // triad lives in `extensions`, which SEC-1 redaction does not touch
    // (it targets inputs.context / outputs.response only) -- whatever
    // applyRedaction does or doesn't change, the receipt's stated
    // fingerprint must still match a fresh recompute over its own content.
    const { receipt_fingerprint, full_fingerprint } = computeFingerprints(receipt);
    expect(full_fingerprint).toBe(receipt.full_fingerprint);
    expect(receipt_fingerprint).toBe(receipt.receipt_fingerprint);

    expect(receipt.receipt_signature).toBeTruthy();
    const result = verifyReceipt(receipt, publicKey);
    const sigErrors = result.errors.filter((e) => /signature/i.test(e));
    expect(sigErrors).toEqual([]);

    // Triad is still intact post-redaction.
    const extensions = receipt.extensions as Record<string, unknown>;
    const gwExt = extensions["com.sanna.gateway"] as Record<string, unknown>;
    const triad = gwExt.receipt_triad as Record<string, unknown>;
    expect(triad.action_hash).toBe(triad.input_hash);
    expect(triad.context_limitation).toBe("gateway_boundary");
  }, 30_000);
});
