#!/usr/bin/env node

/**
 * Sanna Gateway — Entry Point
 *
 * Starts the MCP enforcement proxy.
 * Usage: sanna-gateway [--config <path>]
 */

import { resolve } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadGatewayConfig, GatewayConfigError } from "./config.js";
import { SannaGateway } from "./gateway.js";

// ── Re-exports ───────────────────────────────────────────────────────

export { SannaGateway } from "./gateway.js";
export {
  loadGatewayConfig,
  validateGatewayConfig,
  resolveToolPolicy,
  resolveEnvVar,
  GatewayConfigError,
} from "./config.js";
export type { GatewayConfig, DownstreamConfig } from "./config.js";
export { DownstreamConnection } from "./downstream.js";
export { EscalationStore } from "./escalation.js";
export type { Escalation, EscalationStatus, EscalationStoreOptions } from "./escalation.js";
export { CircuitBreaker, CircuitBreakerOpenError } from "./circuit-breaker.js";
export type { CircuitState, CircuitBreakerOptions } from "./circuit-breaker.js";
export { redactPII, redactInObject } from "./pii.js";
export type { PiiPattern, RedactionResult } from "./pii.js";
export {
  namespaceTool,
  parseNamespacedTool,
  namespaceToolList,
  denamespaceArgs,
} from "./tool-namespace.js";
export { injectJustificationParam, extractJustification } from "./schema-mutation.js";
export {
  computeInputHash,
  computeReasoningHash,
  computeActionHash,
  buildReceiptTriad,
} from "./receipt-v2.js";
export type { ReceiptTriad } from "./receipt-v2.js";
export { migrateClaudeConfig, migrateCursorConfig } from "./migrate.js";

// ── CLI ──────────────────────────────────────────────────────────────

function printUsage(): void {
  process.stderr.write(`
sanna-gateway — MCP enforcement proxy

Usage:
  sanna-gateway [--config <path>]

Options:
  --config <path>   Path to gateway.yaml (default: ./gateway.yaml)
  --help            Show this help message

The gateway proxies MCP tool calls through constitutional governance,
enforcing authority boundaries, generating receipts, and managing
escalations.
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printUsage();
    process.exit(0);
  }

  // Parse --config
  let configPath = resolve("gateway.yaml");
  const configIdx = args.indexOf("--config");
  if (configIdx >= 0 && args[configIdx + 1]) {
    configPath = resolve(args[configIdx + 1]);
  }

  try {
    const config = loadGatewayConfig(configPath);
    const gateway = new SannaGateway(config);

    // Graceful shutdown
    const shutdown = async () => {
      process.stderr.write("[sanna-gateway] shutting down...\n");
      await gateway.stop();
      process.exit(0);
    };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);

    await gateway.start();

    // Connect to stdio transport
    const transport = new StdioServerTransport();
    await gateway.getServer().connect(transport);
  } catch (err) {
    if (err instanceof GatewayConfigError) {
      process.stderr.write(`Configuration error: ${err.message}\n`);
      process.exit(1);
    }
    process.stderr.write(
      `Fatal error: ${err instanceof Error ? err.message : err}\n`,
    );
    process.exit(1);
  }
}

// Run if this is the entry point
const isEntryPoint =
  process.argv[1] &&
  (process.argv[1].endsWith("/sanna-gateway") ||
    process.argv[1].endsWith("/index.js") ||
    process.argv[1].includes("sanna-gateway"));

if (isEntryPoint) {
  main().catch((err) => {
    process.stderr.write(`Unhandled error: ${err}\n`);
    process.exit(1);
  });
}
