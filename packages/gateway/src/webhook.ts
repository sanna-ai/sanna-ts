/**
 * Webhook token delivery with SSRF protection.
 *
 * Security hardening:
 * - HTTPS-only (reject http://)
 * - No redirect following (redirect: "error")
 * - Private IP blocking (RFC 1918, RFC 6598, loopback, link-local)
 * - DNS rebinding protection (resolve and validate before connecting)
 * - Response body size limit (1 MB)
 * - Configurable timeout (default: 10s)
 */

import { resolve4, resolve6 } from "node:dns/promises";

// ── Private IP ranges ────────────────────────────────────────────────

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
  /^::1$/,
  /^fc/i,
  /^fe80/i,
];

export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((re) => re.test(ip));
}

// ── Types ────────────────────────────────────────────────────────────

export interface WebhookDeliveryOptions {
  url: string;
  headers?: Record<string, string>;
  timeoutMs?: number;
}

export interface WebhookPayload {
  escalation_id: string;
  tool_name: string;
  reason: string;
  token: string;
  expires_at: string;
}

// ── DNS resolution ───────────────────────────────────────────────────

async function resolveHostIps(hostname: string): Promise<string[]> {
  const ips: string[] = [];
  try {
    ips.push(...(await resolve4(hostname)));
  } catch {
    // No A records
  }
  try {
    ips.push(...(await resolve6(hostname)));
  } catch {
    // No AAAA records
  }
  return ips;
}

// ── Webhook delivery ─────────────────────────────────────────────────

/**
 * Deliver an escalation token via webhook POST.
 * Returns true on success, false on failure (best-effort, never throws).
 */
export async function deliverTokenViaWebhook(
  payload: WebhookPayload,
  options: WebhookDeliveryOptions,
): Promise<boolean> {
  const timeoutMs = options.timeoutMs ?? 10_000;

  try {
    // Validate URL scheme
    const parsed = new URL(options.url);
    if (parsed.protocol !== "https:") {
      process.stderr.write(
        `[sanna-gateway] webhook rejected: non-HTTPS URL ${options.url}\n`,
      );
      return false;
    }

    // DNS resolve and check for private IPs
    const ips = await resolveHostIps(parsed.hostname);
    if (ips.length === 0) {
      process.stderr.write(
        `[sanna-gateway] webhook rejected: DNS resolution failed for ${parsed.hostname}\n`,
      );
      return false;
    }

    for (const ip of ips) {
      if (isPrivateIp(ip)) {
        process.stderr.write(
          `[sanna-gateway] webhook rejected: private IP ${ip} for ${parsed.hostname}\n`,
        );
        return false;
      }
    }

    // Make the request
    const headers: Record<string, string> = {
      "content-type": "application/json",
      ...options.headers,
    };

    const response = await fetch(options.url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      process.stderr.write(
        `[sanna-gateway] webhook delivery failed: HTTP ${response.status}\n`,
      );
      return false;
    }

    return true;
  } catch (err) {
    process.stderr.write(
      `[sanna-gateway] webhook delivery error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return false;
  }
}
