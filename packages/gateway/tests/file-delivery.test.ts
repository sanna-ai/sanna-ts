import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { deliverTokenToFile } from "../src/file-delivery.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-file-delivery-"));
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function tokenFilePath(): string {
  return join(tmpDir, "pending_tokens.json");
}

function readTokens(): unknown[] {
  return JSON.parse(readFileSync(tokenFilePath(), "utf-8"));
}

function makeToken(
  id: string,
  expiresInMs = 300_000,
): Record<string, unknown> {
  return {
    escalation_id: id,
    tool_name: "test_tool",
    reason: "test reason",
    token: `token-${id}`,
    expires_at: new Date(Date.now() + expiresInMs).toISOString(),
  };
}

describe("deliverTokenToFile", () => {
  it("should write token to file", () => {
    deliverTokenToFile(makeToken("esc-1"), {
      tokenFilePath: tokenFilePath(),
    });

    const tokens = readTokens();
    expect(tokens).toHaveLength(1);
    expect((tokens[0] as Record<string, unknown>).escalation_id).toBe("esc-1");
    expect((tokens[0] as Record<string, unknown>).delivered_at).toBeTruthy();
  });

  it("should append to existing tokens", () => {
    const path = tokenFilePath();
    deliverTokenToFile(makeToken("esc-1"), { tokenFilePath: path });
    deliverTokenToFile(makeToken("esc-2"), { tokenFilePath: path });

    const tokens = readTokens();
    expect(tokens).toHaveLength(2);
    expect((tokens[0] as Record<string, unknown>).escalation_id).toBe("esc-1");
    expect((tokens[1] as Record<string, unknown>).escalation_id).toBe("esc-2");
  });

  it("should prune expired tokens", () => {
    const path = tokenFilePath();

    // Write an expired token
    deliverTokenToFile(makeToken("esc-expired", -1000), {
      tokenFilePath: path,
    });

    // Write a fresh token — this should prune the expired one
    deliverTokenToFile(makeToken("esc-fresh"), { tokenFilePath: path });

    const tokens = readTokens();
    expect(tokens).toHaveLength(1);
    expect((tokens[0] as Record<string, unknown>).escalation_id).toBe(
      "esc-fresh",
    );
  });

  it("should enforce size cap", () => {
    const path = tokenFilePath();

    deliverTokenToFile(makeToken("esc-1"), {
      tokenFilePath: path,
      maxPendingTokens: 2,
    });
    deliverTokenToFile(makeToken("esc-2"), {
      tokenFilePath: path,
      maxPendingTokens: 2,
    });
    deliverTokenToFile(makeToken("esc-3"), {
      tokenFilePath: path,
      maxPendingTokens: 2,
    });

    const tokens = readTokens();
    expect(tokens).toHaveLength(2);
    // Oldest dropped, newest kept
    expect((tokens[0] as Record<string, unknown>).escalation_id).toBe("esc-2");
    expect((tokens[1] as Record<string, unknown>).escalation_id).toBe("esc-3");
  });

  it("should handle missing file gracefully", () => {
    const path = join(tmpDir, "subdir", "tokens.json");

    deliverTokenToFile(makeToken("esc-new"), { tokenFilePath: path });

    const tokens = JSON.parse(readFileSync(path, "utf-8"));
    expect(tokens).toHaveLength(1);
    expect(tokens[0].escalation_id).toBe("esc-new");
  });

  it("should handle corrupt file gracefully", () => {
    const path = tokenFilePath();

    // Write invalid JSON
    writeFileSync(path, "not valid json {{{", "utf-8");

    // Should not throw — overwrites with valid data
    deliverTokenToFile(makeToken("esc-recovery"), { tokenFilePath: path });

    const tokens = readTokens();
    expect(tokens).toHaveLength(1);
    expect((tokens[0] as Record<string, unknown>).escalation_id).toBe(
      "esc-recovery",
    );
  });
});
