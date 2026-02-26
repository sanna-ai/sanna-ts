import { describe, it, expect, vi, afterEach } from "vitest";
import {
  deliverTokenViaWebhook,
  isPrivateIp,
} from "../src/webhook.js";
import type { WebhookPayload } from "../src/webhook.js";

// Mock DNS resolution — always return a public IP by default
vi.mock("node:dns/promises", () => ({
  resolve4: vi.fn().mockResolvedValue(["93.184.216.34"]),
  resolve6: vi.fn().mockRejectedValue(new Error("no AAAA record")),
}));

afterEach(() => {
  vi.restoreAllMocks();
});

const PAYLOAD: WebhookPayload = {
  escalation_id: "esc-001",
  tool_name: "delete_database",
  reason: "Requires approval",
  token: "abc123",
  expires_at: new Date(Date.now() + 300_000).toISOString(),
};

describe("isPrivateIp", () => {
  it("should block private IP addresses", () => {
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("172.16.0.1")).toBe(true);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("::1")).toBe(true);
    expect(isPrivateIp("169.254.1.1")).toBe(true);
    expect(isPrivateIp("100.64.0.1")).toBe(true);
    expect(isPrivateIp("fc00::1")).toBe(true);
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  it("should allow public IP addresses", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("1.1.1.1")).toBe(false);
    expect(isPrivateIp("93.184.216.34")).toBe(false);
    expect(isPrivateIp("203.0.113.1")).toBe(false);
  });
});

describe("deliverTokenViaWebhook", () => {
  it("should deliver token via webhook", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", mockFetch);

    const result = await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/sanna",
    });

    expect(result).toBe(true);
    expect(mockFetch).toHaveBeenCalledOnce();

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("https://hooks.example.com/sanna");
    const body = JSON.parse(init.body);
    expect(body.escalation_id).toBe("esc-001");
    expect(body.tool_name).toBe("delete_database");
  });

  it("should reject http:// URLs", async () => {
    const mockFetch = vi.fn();
    vi.stubGlobal("fetch", mockFetch);

    const result = await deliverTokenViaWebhook(PAYLOAD, {
      url: "http://hooks.example.com/sanna",
    });

    expect(result).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("should handle redirect as failure", async () => {
    const mockFetch = vi.fn().mockRejectedValue(
      new TypeError("redirect mode is set to error"),
    );
    vi.stubGlobal("fetch", mockFetch);

    const result = await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/redirect",
    });

    expect(result).toBe(false);
  });

  it("should handle network timeout", async () => {
    // fetch that never resolves — AbortSignal.timeout will abort it
    const mockFetch = vi.fn().mockImplementation(
      (_url: string, init: { signal: AbortSignal }) => {
        return new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () => {
            reject(new DOMException("The operation was aborted.", "AbortError"));
          });
        });
      },
    );
    vi.stubGlobal("fetch", mockFetch);

    const result = await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/slow",
      timeoutMs: 50,
    });

    expect(result).toBe(false);
  });

  it("should handle HTTP error responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 500 }),
    );

    const result = await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/error",
    });

    expect(result).toBe(false);
  });

  it("should set Content-Type header", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", mockFetch);

    await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/sanna",
    });

    const init = mockFetch.mock.calls[0][1];
    expect(init.headers["content-type"]).toBe("application/json");
  });

  it("should include custom headers", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", mockFetch);

    await deliverTokenViaWebhook(PAYLOAD, {
      url: "https://hooks.example.com/sanna",
      headers: {
        "X-Webhook-Secret": "my-secret",
        Authorization: "Bearer tok123",
      },
    });

    const init = mockFetch.mock.calls[0][1];
    expect(init.headers["X-Webhook-Secret"]).toBe("my-secret");
    expect(init.headers["Authorization"]).toBe("Bearer tok123");
    // Content-Type should still be set
    expect(init.headers["content-type"]).toBe("application/json");
  });
});
