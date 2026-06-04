/**
 * SAN-765: cross-SDK allow-disposition conformance.
 * Drives the fetch + child_process interceptors with an allowed (can_execute) decision in enforce
 * mode and asserts the emitted receipt matches the shared protocol fixture
 * (spec/fixtures/multi-surface-vectors.json -> allow_disposition_vectors) AND that the action
 * executed. The sanna-repo (Python) suite asserts the SAME vector.
 *
 * Per spec Section 7.3 an authority-only interceptor never runs reasoning checks, so an allowed
 * action emits assurance="partial" (NOT "full"; the prior TS halted?partial:full divergence
 * emitted "full" for allowed). action_hash is not pinned (output hash is environment-dependent).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createRequire } from "node:module";
import * as path from "node:path";
import * as fs from "node:fs";

// Prevent real DNS lookups: the fetch SSRF guard resolves hostnames via node:dns/promises.
// Empty arrays are NXDOMAIN-equivalent -- no private IPs found, so the guard passes and the
// interceptor's authority logic (URL-pattern based) runs normally.
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
    status: string; enforcement_surface: string; invariants_scope: string; assurance: string;
    action_hash?: string;
  };
}

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> { this.receipts.push(receipt); return { success: true, receiptId: receipt.receipt_id }; }
}
function invocation(sink: TestSink): Receipt[] { return sink.receipts.filter((r: any) => r.event_type !== "session_manifest"); }

const vectors = JSON.parse(fs.readFileSync(SPEC_VECTORS, "utf-8"));
const allowVectors: DispositionVector[] = vectors.allow_disposition_vectors;

function assertReceiptMatches(receipt: any, expected: DispositionVector["expected"]) {
  expect(receipt.event_type).toBe(expected.event_type);
  expect(receipt.enforcement.action).toBe(expected.enforcement_action);
  expect(receipt.enforcement.enforcement_mode).toBe(expected.enforcement_mode);
  expect(receipt.status).toBe(expected.status);
  expect(receipt.enforcement_surface).toBe(expected.enforcement_surface);
  expect(receipt.invariants_scope).toBe(expected.invariants_scope);
  expect(receipt.assurance).toBe(expected.assurance);
  // action_hash is not pinned for allowed actions (output hash is environment-dependent);
  // honor the fixture's not_pinned list rather than asserting a value.
  if (expected.action_hash !== undefined) {
    expect(receipt.action_hash).toBe(expected.action_hash);
  }
}

let realFetch: typeof globalThis.fetch;
beforeEach(() => { realFetch = globalThis.fetch; });
afterEach(() => { unpatchFetch(); unpatchChildProcess(); globalThis.fetch = realFetch; });

describe("SAN-765 cross-SDK allow-disposition conformance", () => {
  it("fixture present with cli + http vectors (fails loudly if the submodule bump did not take)", () => {
    expect(Array.isArray(allowVectors)).toBe(true);
    expect(allowVectors.map((v) => v.surface).sort()).toEqual(["cli", "http"]);
    expect(allowVectors.every((v) => v.expected.assurance === "partial")).toBe(true);
  });

  it("cli: an allowed command executes in enforce mode and the receipt matches the vector", async () => {
    const vec = allowVectors.find((v) => v.surface === "cli")!;
    const sink = new TestSink();
    await patchChildProcess({ constitutionPath: CLI_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    const cp = require_("node:child_process");
    // echo is can_execute in cli-test.yaml -> allowed -> the real (harmless) echo executes.
    const result = cp.spawnSync("echo", ["hello"], { encoding: "utf-8" });
    expect(result.status).toBe(0); // the action executed
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    assertReceiptMatches(receipts[0], vec.expected);
  });

  it("http: an allowed request executes in enforce mode, the original fetch IS called, and the receipt matches the vector", async () => {
    const vec = allowVectors.find((v) => v.surface === "http")!;
    const sink = new TestSink();
    // Set globalThis.fetch to a mock BEFORE patchFetch saves it as the "original". The allowed
    // path calls the original, so the mock must be invoked (proving execution).
    const mock = vi.fn(async () => new Response("ok", { status: 200 }));
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;
    await patchFetch({ constitutionPath: API_CONSTITUTION, sink, agentId: "test-agent", mode: "enforce" });
    // api.example.com/* is can_execute (api-001) -> allowed.
    const res = await fetch("https://api.example.com/data");
    expect(res.status).toBe(200);
    expect(mock).toHaveBeenCalledOnce(); // the allowed path executed the original
    const receipts = invocation(sink);
    expect(receipts.length).toBe(1);
    assertReceiptMatches(receipts[0], vec.expected);
  });
});
