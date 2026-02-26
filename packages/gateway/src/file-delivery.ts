/**
 * File-based token delivery.
 *
 * Writes escalation tokens to a JSON file for pickup by external automation.
 * Uses atomic writes, TTL pruning, and size caps.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

// ── Types ────────────────────────────────────────────────────────────

export interface FileDeliveryOptions {
  tokenFilePath: string;
  maxPendingTokens?: number;
}

interface PendingToken {
  escalation_id: string;
  tool_name: string;
  reason: string;
  token: string;
  expires_at: string;
  delivered_at: string;
  [key: string]: unknown;
}

// ── File delivery ────────────────────────────────────────────────────

/**
 * Append a token to the pending tokens file.
 * Prunes expired tokens and enforces size cap on every write.
 */
export function deliverTokenToFile(
  tokenInfo: Record<string, unknown>,
  options: FileDeliveryOptions,
): void {
  const maxTokens = options.maxPendingTokens ?? 100;

  // Read existing tokens
  let tokens: PendingToken[] = [];
  if (existsSync(options.tokenFilePath)) {
    try {
      const raw = JSON.parse(readFileSync(options.tokenFilePath, "utf-8"));
      if (Array.isArray(raw)) {
        tokens = raw;
      }
    } catch {
      // Corrupt file — start fresh
      tokens = [];
    }
  }

  // Append new token
  tokens.push({
    ...tokenInfo,
    delivered_at: new Date().toISOString(),
  } as PendingToken);

  // Prune expired tokens
  const nowMs = Date.now();
  tokens = tokens.filter((t) => {
    if (!t.expires_at) return true;
    return new Date(t.expires_at).getTime() > nowMs;
  });

  // Enforce size cap — keep newest entries
  if (tokens.length > maxTokens) {
    tokens = tokens.slice(tokens.length - maxTokens);
  }

  // Write atomically
  const dir = dirname(options.tokenFilePath);
  if (dir) mkdirSync(dir, { recursive: true });
  writeFileSync(options.tokenFilePath, JSON.stringify(tokens, null, 2) + "\n");
}
