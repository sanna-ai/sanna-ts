/**
 * SAN-745: cross-SDK escalate-disposition conformance.
 * Drives the fetch + child_process interceptors with a must_escalate decision in enforce
 * mode and asserts the emitted receipt matches the shared protocol fixture
 * (spec/fixtures/multi-surface-vectors.json -> escalate_disposition_vectors) AND that the
 * action did not execute. The sanna-repo (Python) suite asserts the SAME vector (SAN-745 PR3b).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";

// internal.corp.com can resolve to the ICANN collision IP 127.0.53.53 (a private IP), tripping
// the fetch SSRF guard before the escalate path. Mock DNS to an NXDOMAIN-equivalent (empty).
vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn().mockResolvedValue([]),
  resolve6: vi.fn().mockResolvedValue([]),
}));

import { patchFetch, unpatchFetch } from "../src/interceptors/fetch-interceptor.js";
import { patchChildProcess, unpatchChildProcess } from "../src/interceptors/index.js";
import type { Receipt, ReceiptSink, SinkResult } from "../src/types.js";

const require_ = createRequire(import.meta.url);
const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures");
const CLI_CONSTITUTION = path.join(FIXTURES_DIR, "cli-test.yaml");
const API_CONSTITUTION = path.join(FIXTURES_DIR, "api-test.yaml");
const SPEC_VECTORS = path.resolve(import.meta.dirname, "../../../spec/fixtures/multi-surface-vectors.json");

interface DispositionVector {
  surface: string; decision: string; mode: string;
  expected: {
    blocked: boolean; event_type: string; enforcement_action: string; enforcement_mode: string;
    status: string; enforcement_surface: string; invariants_scope: string; action_hash: string;
  };
}

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> { this.receipts.push(receipt); return { success: true, receiptId: receipt.receipt_id }; }
}
function invocation(sink: TestSink): Receipt[] { return sink.receipts.filter((r: any) => r.event_type !== "session_manifest"); }

const vectors = JSON.parse(fs.readFileSync(SPEC_VECTORS, "utf-8"));
const dispositionVectors: DispositionVector[] = vectors.escalate_disposition_vectors;

function assertReceiptMatches(receipt: any, expected: DispositionVector["expected"]) {
  expect(receipt.event_type).toBe(expected.event_type);
  expect(receipt.enforcement.action).toBe(expected.enforcement_action);
  expect(receipt.enforcement.enforcement_mode).toBe(expected.enforcement_mode);
  expect(receipt.status).toBe(expected.status);
  expect(receipt.enforcement_surface).toBe(expected.enforcement_surface);
  expect(receipt.invariants_scope).toBe(expected.invariants_scope);
  expect(receipt.action_hash).toBe(expected.action_hash);
  // assurance intentionally NOT asserted -- cross-SDK divergence tracked in SAN-765.
}

let realFetch: typeof globalThis.fetch;
beforeEach(() => { realFetch = globalThis.fetch; });
afterEach(() => { unpatchFetch(); unpatchChildProcess(); globalThis.fetch = realFetch; });

describe("SAN-745 cross-SDK escalate-disposition conformance", () => {
  it("fixture present with cli + http vectors (fails loudly if the submodule bump did not take)", () => {
    expect(Array.isArray(dispositionVectors)).toBe(true);
    expect(dispositionVectors.map((v) => v.surface).sort()).toEqual(["cli", "http"]);
  });

  it("cli: must_escalate blocks in enforce mode and the receipt matches the vector", async () => {
    const vec = dispositionVectors.find((v) => v.surface === "cli")!;
    const sink = new TestSink();
    await patchChildProcess({ constitutionPath: CLI_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    const cp = require_("node:child_process");
    expect(() => cp.spawnSync("docker", ["run", "nginx"], { encoding: "utf-8" })).toThrow(/ENOENT/);
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    assertReceiptMatches(receipts[0], vec.expected);
  });

  it("http: must_escalate blocks in enforce mode, the real fetch is never called, and the receipt matches the vector", async () => {
    const vec = dispositionVectors.find((v) => v.surface === "http")!;
    const sink = new TestSink();
    const mock = vi.fn(async () => new Response("ok", { status: 200 }));
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;
    await patchFetch({ constitutionPath: API_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    await expect(fetch("https://internal.corp.com/api/v1", { method: "POST", body: "x" })).rejects.toThrow(TypeError);
    expect(mock).not.toHaveBeenCalled();
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    assertReceiptMatches(receipts[0], vec.expected);
  });
});
