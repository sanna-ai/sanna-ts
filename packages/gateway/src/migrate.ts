/**
 * Sanna Gateway — Migration Utilities
 *
 * Convert existing MCP client configurations (Claude Desktop, Cursor)
 * into gateway.yaml format.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve, join } from "node:path";
import { homedir } from "node:os";
import yaml from "js-yaml";
import { safeWriteFile } from "@sanna-ai/core";

// ── Types ────────────────────────────────────────────────────────────

interface McpServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface ClaudeDesktopConfig {
  mcpServers?: Record<string, McpServerEntry>;
}

interface CursorConfig {
  mcpServers?: Record<string, McpServerEntry>;
}

// ── Default paths ────────────────────────────────────────────────────

function getClaudeDesktopConfigPath(): string {
  const home = homedir();
  if (process.platform === "darwin") {
    return join(
      home,
      "Library",
      "Application Support",
      "Claude",
      "claude_desktop_config.json",
    );
  }
  if (process.platform === "win32") {
    return join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json");
  }
  return join(home, ".config", "claude", "claude_desktop_config.json");
}

function getCursorConfigPath(): string {
  const home = homedir();
  if (process.platform === "darwin") {
    return join(
      home,
      "Library",
      "Application Support",
      "Cursor",
      "User",
      "globalStorage",
      "cursor.mcp",
      "config.json",
    );
  }
  return join(home, ".config", "cursor", "mcp.json");
}

// ── Migration ────────────────────────────────────────────────────────

/**
 * Convert Claude Desktop MCP config to gateway YAML config.
 */
export function migrateClaudeConfig(
  sourcePath?: string,
  outputPath?: string,
): string {
  const configPath = sourcePath ?? getClaudeDesktopConfigPath();
  if (!existsSync(configPath)) {
    throw new Error(`Claude Desktop config not found: ${configPath}`);
  }

  const raw = JSON.parse(readFileSync(configPath, "utf-8")) as ClaudeDesktopConfig;
  return _migrateFromMcpServers(raw.mcpServers ?? {}, outputPath ?? "gateway.yaml");
}

/**
 * Convert Cursor editor MCP config to gateway YAML config.
 */
export function migrateCursorConfig(
  sourcePath?: string,
  outputPath?: string,
): string {
  const configPath = sourcePath ?? getCursorConfigPath();
  if (!existsSync(configPath)) {
    throw new Error(`Cursor config not found: ${configPath}`);
  }

  const raw = JSON.parse(readFileSync(configPath, "utf-8")) as CursorConfig;
  return _migrateFromMcpServers(raw.mcpServers ?? {}, outputPath ?? "gateway.yaml");
}

function _migrateFromMcpServers(
  servers: Record<string, McpServerEntry>,
  outputPath: string,
): string {
  const downstreams: Record<string, unknown>[] = [];

  for (const [name, server] of Object.entries(servers)) {
    const ds: Record<string, unknown> = {
      name: name.replace(/[^a-zA-Z0-9_-]/g, "_"),
      command: server.command,
      args: server.args ?? [],
    };
    if (server.env && Object.keys(server.env).length > 0) {
      ds.env = server.env;
    }
    downstreams.push(ds);
  }

  const config = {
    gateway: {
      listen: { transport: "stdio" },
      constitution: {
        path: "./constitution.yaml",
      },
      enforcement: {
        mode: "advisory",
        default_policy: "allow",
      },
    },
    downstreams,
  };

  const yamlStr = yaml.dump(config, {
    lineWidth: -1,
    noRefs: true,
    quotingType: "'",
  });

  safeWriteFile(outputPath, yamlStr);

  // Also create a placeholder constitution
  const constitutionPath = resolve(
    outputPath.replace(/[^/\\]+$/, ""),
    "constitution.yaml",
  );
  if (!existsSync(constitutionPath)) {
    const placeholderConstitution = yaml.dump({
      schema_version: "1.0",
      identity: {
        agent_name: "my-agent",
        domain: "general",
        description: "Migrated from MCP client config",
        extensions: {},
      },
      provenance: {
        authored_by: "sanna-migrate",
        approved_by: [],
        approval_date: new Date().toISOString().split("T")[0],
        approval_method: "auto-generated",
        change_history: [],
        signature: null,
      },
      boundaries: [],
      trust_tiers: {
        autonomous: [],
        requires_approval: [],
        prohibited: [],
      },
      halt_conditions: [],
      invariants: [],
      authority_boundaries: null,
      trusted_sources: null,
    }, { lineWidth: -1, noRefs: true });
    safeWriteFile(constitutionPath, placeholderConstitution);
  }

  return outputPath;
}
