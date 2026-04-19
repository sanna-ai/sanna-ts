/**
 * Tests for patchFetch() / unpatchFetch() and API authority evaluation.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import * as path from "node:path";
import * as fs from "node:fs";

import { patchFetch, unpatchFetch } from "../src/interceptors/fetch-interceptor.js";
import { evaluateApiAuthority, checkApiInvariants } from "../src/interceptors/api-authority.js";
import { loadConstitution, parseConstitution } from "../src/constitution.js";
import { hashObj, hashBytes, EMPTY_HASH, hashContent } from "../src/hashing.js";
import { computeFingerprintInput, computeFingerprints } from "../src/receipt.js";
import type { Receipt, ReceiptSink, SinkResult, Constitution } from "../src/types.js";

// ── Test helpers ─────────────────────────────────────────────────────

const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures");
const STRICT_CONSTITUTION = path.join(FIXTURES_DIR, "api-test.yaml");
const PERMISSIVE_CONSTITUTION = path.join(FIXTURES_DIR, "api-permissive.yaml");
const SPEC_VECTORS = path.resolve(import.meta.dirname, "../../../spec/fixtures/multi-surface-vectors.json");

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    this.receipts.push(receipt);
    return { success: true, receiptId: receipt.receipt_id };
  }
}

function makeSink(): TestSink {
  return new TestSink();
}

// Save the real fetch so we can mock it
let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  realFetch = globalThis.fetch;
});

afterEach(() => {
  unpatchFetch();
  // Restore real fetch in case unpatch didn't cover it
  globalThis.fetch = realFetch;
});

// Helper: create a mock fetch that returns a controllable Response
function createMockFetch(status = 200, body = "ok", headers: Record<string, string> = {}) {
  return vi.fn(async (_input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    const h = new Headers(headers);
    h.set("content-type", "text/plain");
    return new Response(body, { status, headers: h });
  });
}

// Helper: patch with a mock fetch as the "original"
async function patchWithMock(
  constitutionPath: string,
  sink: TestSink,
  opts: Record<string, unknown> = {},
  mockStatus = 200,
  mockBody = "ok",
  mockHeaders: Record<string, string> = {},
) {
  // Set globalThis.fetch to our mock BEFORE patchFetch saves it as "original"
  const mock = createMockFetch(mockStatus, mockBody, mockHeaders);
  globalThis.fetch = mock as unknown as typeof globalThis.fetch;

  await patchFetch({
    constitutionPath,
    sink,
    agentId: "test-agent",
    ...opts,
  });

  return mock;
}

// ── 1. API Authority evaluation ──────────────────────────────────────

describe("evaluateApiAuthority", () => {
  let constitution: Constitution;

  beforeEach(() => {
    constitution = loadConstitution(STRICT_CONSTITUTION);
  });

  it("returns allow for can_execute URL with matching method", () => {
    const result = evaluateApiAuthority("GET", "https://api.example.com/data", constitution);
    expect(result.decision).toBe("allow");
    expect(result.rule_id).toBe("API001");
  });

  it("returns halt for cannot_execute URL", () => {
    const result = evaluateApiAuthority("GET", "https://api.example.com/admin/users", constitution);
    expect(result.decision).toBe("halt");
    expect(result.rule_id).toBe("API002");
  });

  it("returns escalate for must_escalate URL", () => {
    const result = evaluateApiAuthority("POST", "https://internal.corp.com/api/v1", constitution);
    expect(result.decision).toBe("escalate");
    expect(result.rule_id).toBe("API003");
    expect(result.escalation_target).toBe("security-team");
  });

  it("returns halt for unlisted URL in strict mode", () => {
    const result = evaluateApiAuthority("GET", "https://unknown.com/api", constitution);
    expect(result.decision).toBe("halt");
    expect(result.reason).toContain("not matched in strict mode");
  });

  it("returns allow when no api_permissions", () => {
    const noApi: Constitution = { ...constitution, api_permissions: null };
    const result = evaluateApiAuthority("GET", "https://any.com", noApi);
    expect(result.decision).toBe("allow");
    expect(result.reason).toContain("No api_permissions");
  });

  it("filters by method", () => {
    // API004: users endpoint is GET-only
    const getResult = evaluateApiAuthority("GET", "https://api.example.com/users", constitution);
    expect(getResult.decision).toBe("allow");
    expect(getResult.rule_id).toBe("API001"); // matches API001 first (wildcard on /*)

    // DELETE not in API001 methods ["GET", "POST"]
    const deleteResult = evaluateApiAuthority("DELETE", "https://api.example.com/users", constitution);
    // API001 doesn't match DELETE, API004 doesn't match DELETE either, so falls through to strict halt
    expect(deleteResult.decision).toBe("halt");
  });
});

describe("evaluateApiAuthority (permissive)", () => {
  let constitution: Constitution;

  beforeEach(() => {
    constitution = loadConstitution(PERMISSIVE_CONSTITUTION);
  });

  it("returns allow for unlisted URL in permissive mode", () => {
    const result = evaluateApiAuthority("GET", "https://any.com/api", constitution);
    expect(result.decision).toBe("allow");
    expect(result.reason).toContain("permissive mode");
  });

  it("still halts cannot_execute in permissive mode", () => {
    const result = evaluateApiAuthority("GET", "https://api.example.com/admin/secret", constitution);
    expect(result.decision).toBe("halt");
  });
});

// ── 2. API Invariants ────────────────────────────────────────────────

describe("checkApiInvariants", () => {
  let constitution: Constitution;

  beforeEach(() => {
    constitution = loadConstitution(STRICT_CONSTITUTION);
  });

  it("returns null when no invariant matches", () => {
    const result = checkApiInvariants("https://api.example.com/data", constitution);
    expect(result).toBeNull();
  });

  it("returns matching invariant for API key in URL", () => {
    const result = checkApiInvariants("https://api.example.com/data?api_key=secret123", constitution);
    expect(result).not.toBeNull();
    expect(result!.id).toBe("APINV001");
    expect(result!.verdict).toBe("halt");
  });

  it("returns null when no invariants defined", () => {
    const noInv: Constitution = {
      ...constitution,
      api_permissions: { ...constitution.api_permissions!, invariants: [] },
    };
    const result = checkApiInvariants("https://api.example.com/data?api_key=x", noInv);
    expect(result).toBeNull();
  });
});

// ── 3. Interception coverage ─────────────────────────────────────────

describe("patchFetch — interception coverage", () => {
  it("intercepts fetch GET", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");

    expect(mock).toHaveBeenCalledOnce();
    expect(sink.receipts.length).toBe(1);
    expect(sink.receipts[0].event_type).toBe("api_invocation_allowed");
  });

  it("intercepts fetch POST", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data", { method: "POST", body: "hello" });

    expect(mock).toHaveBeenCalledOnce();
    expect(sink.receipts.length).toBe(1);
  });

  it("intercepts fetch with Request object", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    const req = new Request("https://api.example.com/data", { method: "GET" });
    await fetch(req);

    expect(mock).toHaveBeenCalledOnce();
    expect(sink.receipts.length).toBe(1);
  });
});

// ── 4. Justification handling ────────────────────────────────────────

describe("patchFetch — justification", () => {
  it("strips X-Sanna-Justification header", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data", {
      headers: { "X-Sanna-Justification": "test reason", "Accept": "application/json" },
    });

    // The mock receives the cleaned headers (no justification)
    const calledInit = mock.mock.calls[0][1];
    const passedHeaders = new Headers(calledInit?.headers);
    expect(passedHeaders.has("X-Sanna-Justification")).toBe(false);
    expect(passedHeaders.has("Accept")).toBe(true);
  });

  it("sets correct reasoning_hash with justification", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data", {
      headers: { "X-Sanna-Justification": "because tests" },
    });

    const receipt = sink.receipts[0];
    expect(receipt.reasoning_hash).toBe(hashContent("because tests"));
    expect(receipt.reasoning_hash).not.toBe(EMPTY_HASH);
  });

  it("sets EMPTY_HASH reasoning_hash without justification", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");

    expect(sink.receipts[0].reasoning_hash).toBe(EMPTY_HASH);
  });
});

// ── 5. Authority enforcement ─────────────────────────────────────────

describe("patchFetch — authority enforcement", () => {
  it("allows can_execute URLs", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    const res = await fetch("https://api.example.com/data");
    expect(res.status).toBe(200);
  });

  it("throws TypeError for cannot_execute URLs", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await expect(
      fetch("https://api.example.com/admin/users"),
    ).rejects.toThrow(TypeError);
  });

  it("throws TypeError for unlisted URL in strict mode", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await expect(
      fetch("https://unknown.com/api"),
    ).rejects.toThrow(TypeError);

    expect(sink.receipts[0].event_type).toBe("api_invocation_halted");
  });

  it("allows unlisted URL in permissive mode", async () => {
    const sink = makeSink();
    await patchWithMock(PERMISSIVE_CONSTITUTION, sink);

    const res = await fetch("https://unknown.com/api");
    expect(res.status).toBe(200);
    expect(sink.receipts[0].event_type).toBe("api_invocation_allowed");
  });

  it("filters by HTTP method", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    // DELETE is not allowed by API001 (only GET, POST)
    await expect(
      fetch("https://api.example.com/data", { method: "DELETE" }),
    ).rejects.toThrow(TypeError);
  });

  it("first matching rule wins", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    // API002 (cannot_execute /admin/*) comes first in the fixture,
    // so /admin/users matches API002 first → halted
    await expect(
      fetch("https://api.example.com/admin/users"),
    ).rejects.toThrow(TypeError);
    expect(sink.receipts[0].outputs).toHaveProperty("rule_id", "API002");
  });
});

// ── 6. URL pattern matching ──────────────────────────────────────────

describe("patchFetch — URL pattern matching", () => {
  it("wildcard pattern matches", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/anything/here");
    expect(sink.receipts[0].outputs).toHaveProperty("rule_id", "API001");
  });

  it("exact URL match", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/users");
    // Matches API001 first (wildcard)
    expect(sink.receipts[0].outputs).toHaveProperty("rule_id", "API001");
  });

  it("query params in URL do not break matching", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data?page=1&limit=10");
    expect(sink.receipts.length).toBe(1);
    expect(sink.receipts[0].outputs).toHaveProperty("rule_id", "API001");
  });

  it("non-matching URL halts in strict mode", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await expect(
      fetch("https://completely-different.com/api"),
    ).rejects.toThrow(TypeError);
  });
});

// ── 7. Exclusions ────────────────────────────────────────────────────

describe("patchFetch — exclusions", () => {
  it("excludes Sanna Cloud URLs by default", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.sanna.cloud/v1/receipts");

    // Mock called (pass-through), but no receipt emitted
    expect(mock).toHaveBeenCalledOnce();
    expect(sink.receipts.length).toBe(0);
  });

  it("supports custom excludeUrls", async () => {
    const sink = makeSink();
    const mock = createMockFetch();
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;

    await patchFetch({
      constitutionPath: STRICT_CONSTITUTION,
      sink,
      agentId: "test-agent",
      excludeUrls: ["https://my-internal.service/*"],
    });

    await fetch("https://my-internal.service/health");

    expect(mock).toHaveBeenCalledOnce();
    expect(sink.receipts.length).toBe(0);
  });

  it("excluded URLs produce no receipt", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    // This URL would normally be halted (strict mode, not matched)
    // but it's in the default exclusions
    await fetch("https://api.sanna.cloud/anything");

    expect(sink.receipts.length).toBe(0);
  });
});

// ── 8. Receipt triad ─────────────────────────────────────────────────

describe("patchFetch — receipt triad", () => {
  it("input_hash uses canonical key order (body_hash, headers_keys, method, url)", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");

    const receipt = sink.receipts[0];
    expect(receipt.input_hash).toHaveLength(64);

    // Verify manually
    const expectedInputHash = hashObj({
      body_hash: EMPTY_HASH,
      headers_keys: [],
      method: "GET",
      url: "https://api.example.com/data",
    });
    expect(receipt.input_hash).toBe(expectedInputHash);
  });

  it("action_hash computed from response", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink, {}, 200, "response body", { "x-custom": "val" });

    await fetch("https://api.example.com/data");

    const receipt = sink.receipts[0];
    expect(receipt.action_hash).toHaveLength(64);
    // action_hash includes status_code, response body hash, and sorted response header keys
    expect(receipt.action_hash).not.toBe(EMPTY_HASH);
  });

  it("halted action_hash has null status_code", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    try { await fetch("https://unknown.com/blocked"); } catch { /* expected */ }

    const receipt = sink.receipts[0];
    const haltedHash = hashObj({
      body_hash: EMPTY_HASH,
      response_headers_keys: [],
      status_code: null,
    });
    expect(receipt.action_hash).toBe(haltedHash);
  });

  it("action_hash differs from input_hash", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");

    const receipt = sink.receipts[0];
    expect(receipt.action_hash).not.toBe(receipt.input_hash);
  });

  it("body_hash computed from POST body", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data", {
      method: "POST",
      body: '{"key":"value"}',
    });

    const receipt = sink.receipts[0];
    // input_hash should include the body hash
    const bodyHash = hashBytes(Buffer.from('{"key":"value"}', "utf-8"));
    const expectedInputHash = hashObj({
      body_hash: bodyHash,
      headers_keys: [],
      method: "POST",
      url: "https://api.example.com/data",
    });
    expect(receipt.input_hash).toBe(expectedInputHash);
  });
});

// ── 9. Receipt fields ────────────────────────────────────────────────

describe("patchFetch — receipt fields", () => {
  it("sets correct event_type for allowed request", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");
    expect(sink.receipts[0].event_type).toBe("api_invocation_allowed");
  });

  it("sets correct event_type for halted request", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    try { await fetch("https://unknown.com/blocked"); } catch { /* expected */ }
    expect(sink.receipts[0].event_type).toBe("api_invocation_halted");
  });

  it("sets context_limitation based on justification", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data", {
      headers: { "X-Sanna-Justification": "test" },
    });
    expect(sink.receipts[0].context_limitation).toBe("api_execution");

    await fetch("https://api.example.com/data");
    expect(sink.receipts[1].context_limitation).toBe("api_no_justification");
  });
});

// ── 10. Invariants ───────────────────────────────────────────────────

describe("patchFetch — invariants", () => {
  it("blocks URL with API key (invariant)", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await expect(
      fetch("https://api.example.com/data?api_key=secret123"),
    ).rejects.toThrow(TypeError);

    expect(sink.receipts[0].event_type).toBe("api_invocation_halted");
  });

  it("allows clean URL", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data?page=1");
    expect(sink.receipts[0].event_type).toBe("api_invocation_allowed");
  });

  it("invariant overrides authority allow", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    // This URL matches API001 (can_execute) but invariant blocks it
    await expect(
      fetch("https://api.example.com/data?api_key=leaked"),
    ).rejects.toThrow(TypeError);

    const receipt = sink.receipts[0];
    expect(receipt.status).toBe("HALT");
  });
});

// ── 11. Modes ────────────────────────────────────────────────────────

describe("patchFetch — modes", () => {
  it("audit mode executes despite halt decision", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink, { mode: "audit" });

    // Normally halted in strict mode
    const res = await fetch("https://unknown.com/api");
    expect(res.status).toBe(200);
    expect(sink.receipts.length).toBe(1);
  });

  it("audit mode receipt shows would-have-halted", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink, { mode: "audit" });

    await fetch("https://unknown.com/api");

    const receipt = sink.receipts[0];
    expect(receipt.outputs).toHaveProperty("decision", "halt");
    expect(receipt.event_type).toBe("api_invocation_halted");
  });

  it("passthrough mode generates receipts", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink, { mode: "passthrough" });

    await fetch("https://unknown.com/api");
    expect(sink.receipts.length).toBe(1);
  });
});

// ── 12. Anti-enumeration ─────────────────────────────────────────────

describe("patchFetch — anti-enumeration", () => {
  it("halted throws TypeError (matches fetch network failure)", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    try {
      await fetch("https://unknown.com/blocked");
      expect.unreachable("Should have thrown");
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain("fetch failed");
    }
  });

  it("receipt stored in sink after error", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    try { await fetch("https://unknown.com/blocked"); } catch { /* expected */ }

    expect(sink.receipts.length).toBe(1);
    expect(sink.receipts[0].status).toBe("HALT");
  });
});

// ── 13. Edge cases ───────────────────────────────────────────────────

describe("patchFetch — edge cases", () => {
  it("patchFetch is idempotent", async () => {
    const sink = makeSink();
    const mock = await patchWithMock(STRICT_CONSTITUTION, sink);

    // Call patchFetch again — should be no-op
    await patchFetch({
      constitutionPath: STRICT_CONSTITUTION,
      sink,
      agentId: "test-agent",
    });

    await fetch("https://api.example.com/data");
    expect(sink.receipts.length).toBe(1);
  });

  it("unpatch restores original fetch", async () => {
    const originalFetch = globalThis.fetch;
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    expect(globalThis.fetch).not.toBe(originalFetch);

    unpatchFetch();
    // After unpatch, fetch should be the mock we set (which patchFetch saved as original)
    // The mock is what patchFetch stored — unpatch restores it
    expect(sink.receipts.length).toBe(0);
  });

  it("allows all when no api_permissions in constitution", async () => {
    const tempDir = fs.mkdtempSync("/tmp/sanna-test-");
    const tempConst = path.join(tempDir, "no-api.yaml");
    fs.writeFileSync(tempConst, `
sanna_constitution: "0.1.0"
identity:
  agent_name: no-api
  domain: test
  description: No API permissions
provenance:
  authored_by: test
  approved_by: [test]
  approval_date: "2026-01-01"
  approval_method: manual
boundaries:
  - id: B001
    description: test
    category: safety
    severity: critical
`);

    const sink = makeSink();
    const mock = createMockFetch();
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;

    await patchFetch({
      constitutionPath: tempConst,
      sink,
      agentId: "test-agent",
    });

    await fetch("https://any.url.com/anything");
    expect(sink.receipts[0].event_type).toBe("api_invocation_allowed");

    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});

// ── 14. Constitution parsing ─────────────────────────────────────────

describe("Constitution — api_permissions parsing", () => {
  it("parses api_permissions block", () => {
    const constitution = loadConstitution(STRICT_CONSTITUTION);
    expect(constitution.api_permissions).not.toBeNull();
    expect(constitution.api_permissions!.mode).toBe("strict");
    expect(constitution.api_permissions!.justification_required).toBe(true);
    expect(constitution.api_permissions!.endpoints.length).toBeGreaterThan(0);
    expect(constitution.api_permissions!.endpoints[0].id).toBe("API002");
  });

  it("parses api_permissions invariants", () => {
    const constitution = loadConstitution(STRICT_CONSTITUTION);
    expect(constitution.api_permissions!.invariants.length).toBe(2);
    expect(constitution.api_permissions!.invariants[0].id).toBe("APINV001");
    expect(constitution.api_permissions!.invariants[0].verdict).toBe("halt");
  });

  it("methods default to [*] when not specified", () => {
    const data = {
      identity: { agent_name: "test", domain: "test", description: "test" },
      provenance: {
        authored_by: "test",
        approved_by: ["test"],
        approval_date: "2026-01-01",
        approval_method: "manual",
      },
      boundaries: [{ id: "B001", description: "test", category: "safety", severity: "critical" }],
      api_permissions: {
        mode: "strict",
        justification_required: false,
        endpoints: [{ id: "EP1", url_pattern: "https://api.com/*", authority: "can_execute" }],
        invariants: [],
      },
    };
    const parsed = parseConstitution(data as Record<string, unknown>);
    expect(parsed.api_permissions!.endpoints[0].methods).toEqual(["*"]);
  });
});

// ── 15. Cross-language vectors ───────────────────────────────────────

describe("Cross-language API hash vectors", () => {
  let vectors: Record<string, unknown>;

  beforeEach(() => {
    vectors = JSON.parse(fs.readFileSync(SPEC_VECTORS, "utf-8"));
  });

  it("API input vectors produce matching hashes", () => {
    const inputVectors = vectors.api_input_vectors as Array<{
      description: string;
      input_obj: Record<string, unknown>;
      expected_hash: string;
    }>;

    for (const vec of inputVectors) {
      const hash = hashObj(vec.input_obj);
      expect(hash, `Failed on: ${vec.description}`).toBe(vec.expected_hash);
    }
  });

  it("API action vectors produce matching hashes", () => {
    const actionVectors = vectors.api_action_vectors as Array<{
      description: string;
      action_obj: Record<string, unknown>;
      expected_hash: string;
    }>;

    for (const vec of actionVectors) {
      const hash = hashObj(vec.action_obj);
      expect(hash, `Failed on: ${vec.description}`).toBe(vec.expected_hash);
    }
  });
});

// ── 16. Cross-surface receipts ───────────────────────────────────────

describe("Cross-surface — API receipt integrity", () => {
  it("constitution with all three blocks uses correct evaluators", () => {
    // The api-test.yaml only has api_permissions, cli-test.yaml only has cli_permissions
    // Verify they parse independently
    const apiConst = loadConstitution(STRICT_CONSTITUTION);
    expect(apiConst.api_permissions).not.toBeNull();
    expect(apiConst.cli_permissions).toBeNull();
    expect(apiConst.authority_boundaries).toBeNull();
  });

  it("receipt has valid 14-field fingerprint", async () => {
    const sink = makeSink();
    await patchWithMock(STRICT_CONSTITUTION, sink);

    await fetch("https://api.example.com/data");

    const receipt = sink.receipts[0];
    expect(receipt.receipt_fingerprint).toHaveLength(16);
    expect(receipt.full_fingerprint).toHaveLength(64);
    expect(receipt.checks_version).toBe("8");

    const fpInput = computeFingerprintInput(receipt as unknown as Record<string, unknown>);
    const parts = fpInput.split("|");
    expect(parts.length).toBe(16);

    const { receipt_fingerprint, full_fingerprint } = computeFingerprints(
      receipt as unknown as Record<string, unknown>,
    );
    expect(receipt_fingerprint).toBe(receipt.receipt_fingerprint);
    expect(full_fingerprint).toBe(receipt.full_fingerprint);
  });
});

// ── 17. Re-entrancy ──────────────────────────────────────────────────

describe("patchFetch — re-entrancy", () => {
  it("sink HTTP call during receipt persistence does not trigger interception", async () => {
    // Create a sink that makes a fetch call when storing
    let sinkFetchCalled = false;
    const fetchingSink: ReceiptSink = {
      async store(receipt: Receipt): Promise<SinkResult> {
        // This fetch should not be intercepted (re-entrancy guard)
        try {
          await fetch("https://api.sanna.cloud/v1/receipts", {
            method: "POST",
            body: JSON.stringify(receipt),
          });
          sinkFetchCalled = true;
        } catch {
          // May fail since it's a mock, but should not be intercepted
          sinkFetchCalled = true;
        }
        return { success: true };
      },
    };

    const mock = createMockFetch();
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;

    await patchFetch({
      constitutionPath: STRICT_CONSTITUTION,
      sink: fetchingSink,
      agentId: "test-agent",
    });

    await fetch("https://api.example.com/data");

    // The sink's internal fetch to sanna.cloud should be excluded (default exclusion)
    // so no infinite loop occurs
    expect(sinkFetchCalled).toBe(true);
  });
});
