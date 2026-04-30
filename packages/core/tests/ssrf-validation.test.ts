/**
 * Tests for SSRF private IP validation and URL normalization
 * in the fetch interceptor.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import * as path from "node:path";

import { patchFetch, unpatchFetch, isPrivateIp } from "../src/interceptors/fetch-interceptor.js";
import type { Receipt, ReceiptSink, SinkResult } from "../src/types.js";

// ── Test helpers ─────────────────────────────────────────────────────

const FIXTURES_DIR = path.resolve(import.meta.dirname, "fixtures");
const PERMISSIVE_CONSTITUTION = path.join(FIXTURES_DIR, "api-permissive.yaml");

class TestSink implements ReceiptSink {
  receipts: Receipt[] = [];
  async store(receipt: Receipt): Promise<SinkResult> {
    this.receipts.push(receipt);
    return { success: true, receiptId: receipt.receipt_id };
  }
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  realFetch = globalThis.fetch;
});

afterEach(() => {
  unpatchFetch();
  globalThis.fetch = realFetch;
});

// SAN-209: session_manifest is emitted at patch time; filter it for invocation counts
function invocationReceipts(sink: TestSink): Receipt[] {
  return sink.receipts.filter((r: any) => r.event_type !== "session_manifest");
}

function createMockFetch(status = 200, body = "ok") {
  return vi.fn(async (_input: string | URL | Request, _init?: RequestInit): Promise<Response> => {
    return new Response(body, { status, headers: { "content-type": "text/plain" } });
  });
}

async function patchWithMock(sink: TestSink) {
  const mock = createMockFetch();
  globalThis.fetch = mock as unknown as typeof globalThis.fetch;
  await patchFetch({
    constitutionPath: PERMISSIVE_CONSTITUTION,
    sink,
    agentId: "test-agent",
  });
  return mock;
}

// ── 1. isPrivateIp unit tests ────────────────────────────────────────

describe("isPrivateIp", () => {
  describe("IPv4 private ranges", () => {
    it("blocks 127.0.0.0/8 (loopback)", () => {
      expect(isPrivateIp("127.0.0.1")).toBe(true);
      expect(isPrivateIp("127.255.255.255")).toBe(true);
      expect(isPrivateIp("127.0.0.0")).toBe(true);
    });

    it("blocks 10.0.0.0/8 (private)", () => {
      expect(isPrivateIp("10.0.0.1")).toBe(true);
      expect(isPrivateIp("10.255.255.255")).toBe(true);
      expect(isPrivateIp("10.0.0.0")).toBe(true);
    });

    it("blocks 172.16.0.0/12 (private)", () => {
      expect(isPrivateIp("172.16.0.1")).toBe(true);
      expect(isPrivateIp("172.31.255.255")).toBe(true);
      expect(isPrivateIp("172.16.0.0")).toBe(true);
      // 172.15.x.x is NOT private
      expect(isPrivateIp("172.15.255.255")).toBe(false);
      // 172.32.x.x is NOT private
      expect(isPrivateIp("172.32.0.0")).toBe(false);
    });

    it("blocks 192.168.0.0/16 (private)", () => {
      expect(isPrivateIp("192.168.0.1")).toBe(true);
      expect(isPrivateIp("192.168.255.255")).toBe(true);
      expect(isPrivateIp("192.168.0.0")).toBe(true);
    });

    it("blocks 169.254.0.0/16 (link-local)", () => {
      expect(isPrivateIp("169.254.0.1")).toBe(true);
      expect(isPrivateIp("169.254.169.254")).toBe(true);
      expect(isPrivateIp("169.254.255.255")).toBe(true);
    });

    it("blocks 0.0.0.0/8", () => {
      expect(isPrivateIp("0.0.0.0")).toBe(true);
      expect(isPrivateIp("0.255.255.255")).toBe(true);
    });

    it("allows legitimate public IPs", () => {
      expect(isPrivateIp("8.8.8.8")).toBe(false);
      expect(isPrivateIp("1.1.1.1")).toBe(false);
      expect(isPrivateIp("93.184.216.34")).toBe(false);
      expect(isPrivateIp("203.0.113.1")).toBe(false);
    });
  });

  describe("IPv6 private ranges", () => {
    it("blocks ::1 (loopback)", () => {
      expect(isPrivateIp("::1")).toBe(true);
    });

    it("blocks fc00::/7 (unique local)", () => {
      expect(isPrivateIp("fc00::1")).toBe(true);
      expect(isPrivateIp("fd00::1")).toBe(true);
      expect(isPrivateIp("fdff::1")).toBe(true);
    });

    it("blocks fe80::/10 (link-local)", () => {
      expect(isPrivateIp("fe80::1")).toBe(true);
      expect(isPrivateIp("feb0::1")).toBe(true);
    });

    it("allows public IPv6", () => {
      expect(isPrivateIp("2001:db8::1")).toBe(false);
      expect(isPrivateIp("2607:f8b0:4004:800::200e")).toBe(false);
    });
  });

  describe("IPv4-mapped IPv6 addresses", () => {
    it("blocks ::ffff:127.0.0.1", () => {
      expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
    });

    it("blocks ::ffff:10.0.0.1", () => {
      expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true);
    });

    it("blocks ::ffff:192.168.1.1", () => {
      expect(isPrivateIp("::ffff:192.168.1.1")).toBe(true);
    });

    it("blocks ::ffff:169.254.169.254", () => {
      expect(isPrivateIp("::ffff:169.254.169.254")).toBe(true);
    });

    it("allows ::ffff:8.8.8.8", () => {
      expect(isPrivateIp("::ffff:8.8.8.8")).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("handles decimal IP notation (2130706433 = 127.0.0.1)", () => {
      expect(isPrivateIp("2130706433")).toBe(true);
      // 167772161 = 10.0.0.1
      expect(isPrivateIp("167772161")).toBe(true);
      // 134744072 = 8.8.8.8 (public)
      expect(isPrivateIp("134744072")).toBe(false);
    });

    it("handles octal notation (0177.0.0.1 = 127.0.0.1)", () => {
      expect(isPrivateIp("0177.0.0.1")).toBe(true);
    });

    it("handles octal 010.0.0.1 = 8.0.0.1 (not private)", () => {
      // 010 octal = 8 decimal
      expect(isPrivateIp("010.0.0.1")).toBe(false);
    });

    it("handles octal 012.0.0.1 = 10.0.0.1 (private)", () => {
      // 012 octal = 10 decimal
      expect(isPrivateIp("012.0.0.1")).toBe(true);
    });

    it("handles IPv4-compatible IPv6 (::127.0.0.1)", () => {
      expect(isPrivateIp("::127.0.0.1")).toBe(true);
    });

    it("rejects invalid IPs gracefully", () => {
      expect(isPrivateIp("not-an-ip")).toBe(false);
      expect(isPrivateIp("")).toBe(false);
      expect(isPrivateIp("999.999.999.999")).toBe(false);
    });
  });
});

// ── 2. Fetch interceptor SSRF blocking ──────────────────────────────

describe("patchFetch — SSRF private IP blocking", () => {
  it("blocks fetch to 127.0.0.1", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://127.0.0.1/admin")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to 10.x.x.x", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://10.0.0.1/internal")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to 172.16.x.x", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://172.16.0.1/internal")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to 192.168.x.x", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://192.168.1.1/router")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to 169.254.169.254 (cloud metadata)", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to 0.0.0.0", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://0.0.0.0/")).rejects.toThrow(/private IP/);
  });

  it("blocks fetch to [::1]", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://[::1]/")).rejects.toThrow(/private IP/);
  });

  it("blocks IPv4-mapped IPv6 (::ffff:127.0.0.1)", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://[::ffff:127.0.0.1]/")).rejects.toThrow(/private IP/);
  });

  it("blocks octal IP notation (0177.0.0.1 = 127.0.0.1)", async () => {
    const sink = new TestSink();
    await patchWithMock(sink);

    await expect(fetch("http://0177.0.0.1/admin")).rejects.toThrow(/private IP/);
  });

  it("allows legitimate external URLs", async () => {
    const sink = new TestSink();
    const mock = await patchWithMock(sink);

    const response = await fetch("https://api.example.com/data");
    expect(response.status).toBe(200);
    expect(mock).toHaveBeenCalled();
  });
});

// ── 3. URL normalization ────────────────────────────────────────────

describe("patchFetch — URL normalization prevents bypasses", () => {
  it("case-insensitive hostname matching for excludes", async () => {
    const sink = new TestSink();
    const mock = createMockFetch();
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;

    await patchFetch({
      constitutionPath: PERMISSIVE_CONSTITUTION,
      sink,
      agentId: "test-agent",
      excludeUrls: ["https://api.example.com/*"],
    });

    // Mixed case should still match the exclude pattern
    const response = await fetch("https://API.EXAMPLE.COM/data");
    expect(response.status).toBe(200);
    // Should be excluded (no receipt generated)
    expect(invocationReceipts(sink).length).toBe(0);
  });

  it("percent-encoded paths are normalized before matching", async () => {
    const sink = new TestSink();
    const mock = createMockFetch();
    globalThis.fetch = mock as unknown as typeof globalThis.fetch;

    await patchFetch({
      constitutionPath: PERMISSIVE_CONSTITUTION,
      sink,
      agentId: "test-agent",
      excludeUrls: ["https://api.example.com/data*"],
    });

    // %64%61%74%61 = "data" percent-encoded
    const response = await fetch("https://api.example.com/%64%61%74%61");
    expect(response.status).toBe(200);
    // Should be excluded via normalization
    expect(invocationReceipts(sink).length).toBe(0);
  });
});
