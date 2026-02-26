/**
 * Sanna Gateway — Configuration
 *
 * Parses gateway.yaml into validated config objects.
 * Resolves relative paths, validates required fields,
 * and provides a policy cascade resolver.
 */

import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { homedir, platform } from "node:os";
import yaml from "js-yaml";

// ── Types ────────────────────────────────────────────────────────────

export interface ToolPolicyOverride {
  policy: "allow" | "deny" | "escalate";
  reason?: string;
}

export interface DownstreamConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
  policy_overrides?: Record<string, "allow" | "deny" | "escalate">;
  timeout?: number;
}

export interface GatewayConfig {
  listen: { transport: "stdio" };
  constitution: {
    path: string;
    public_key_path?: string;
    signing_key_path?: string;
  };
  enforcement: {
    mode: "enforced" | "advisory" | "permissive";
    default_policy: "allow" | "deny" | "escalate";
  };
  downstreams: DownstreamConfig[];
  escalation?: {
    store_path?: string;
    ttl_seconds?: number;
    hmac_secret: string;
    delivery_methods?: Array<"inline" | "webhook" | "file">;
    webhook_url?: string;
    webhook_headers?: Record<string, string>;
    token_file_path?: string;
    max_pending_tokens?: number;
  };
  receipts?: {
    store_path?: string;
    sign: boolean;
  };
  pii?: {
    enabled: boolean;
    patterns?: string[];
  };
  circuit_breaker?: {
    failure_threshold: number;
    recovery_timeout_ms: number;
    half_open_max: number;
  };
}

// ── Validation ───────────────────────────────────────────────────────

export class GatewayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GatewayConfigError";
  }
}

const VALID_ENFORCEMENT_MODES = new Set(["enforced", "advisory", "permissive"]);
const VALID_DEFAULT_POLICIES = new Set(["allow", "deny", "escalate"]);
const VALID_TOOL_POLICIES = new Set(["allow", "deny", "escalate"]);

/**
 * Validate a parsed GatewayConfig, throwing on structural errors.
 */
export function validateGatewayConfig(config: GatewayConfig): void {
  // Constitution
  if (!config.constitution?.path) {
    throw new GatewayConfigError("Missing required field: constitution.path");
  }

  // Enforcement
  if (!config.enforcement) {
    throw new GatewayConfigError("Missing required field: enforcement");
  }
  if (!VALID_ENFORCEMENT_MODES.has(config.enforcement.mode)) {
    throw new GatewayConfigError(
      `Invalid enforcement.mode: '${config.enforcement.mode}'. ` +
      `Must be one of: enforced, advisory, permissive`,
    );
  }
  if (!VALID_DEFAULT_POLICIES.has(config.enforcement.default_policy)) {
    throw new GatewayConfigError(
      `Invalid enforcement.default_policy: '${config.enforcement.default_policy}'. ` +
      `Must be one of: allow, deny, escalate`,
    );
  }

  // Downstreams
  if (!config.downstreams || config.downstreams.length === 0) {
    throw new GatewayConfigError(
      "Missing required field: downstreams (need at least one entry)",
    );
  }

  const names = new Set<string>();
  for (let i = 0; i < config.downstreams.length; i++) {
    const ds = config.downstreams[i];
    const prefix = `downstreams[${i}]`;

    if (!ds.name) {
      throw new GatewayConfigError(`${prefix}: missing required field 'name'`);
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(ds.name)) {
      throw new GatewayConfigError(
        `${prefix}: name '${ds.name}' contains invalid characters. ` +
        `Use alphanumeric, hyphens, and underscores only.`,
      );
    }
    if (names.has(ds.name)) {
      throw new GatewayConfigError(
        `${prefix}: duplicate downstream name '${ds.name}'`,
      );
    }
    names.add(ds.name);

    if (!ds.command) {
      throw new GatewayConfigError(`${prefix}: missing required field 'command'`);
    }

    // Validate policy_overrides
    if (ds.policy_overrides) {
      for (const [tool, policy] of Object.entries(ds.policy_overrides)) {
        if (!VALID_TOOL_POLICIES.has(policy)) {
          throw new GatewayConfigError(
            `${prefix}.policy_overrides.${tool}: invalid policy '${policy}'. ` +
            `Must be one of: allow, deny, escalate`,
          );
        }
      }
    }
  }

  // Escalation
  if (config.escalation) {
    if (!config.escalation.hmac_secret) {
      throw new GatewayConfigError(
        "Missing required field: escalation.hmac_secret",
      );
    }
    const methods = config.escalation.delivery_methods ?? ["inline"];
    if (methods.includes("webhook")) {
      if (!config.escalation.webhook_url) {
        throw new GatewayConfigError(
          "escalation.webhook_url is required when 'webhook' is in delivery_methods",
        );
      }
      if (!config.escalation.webhook_url.startsWith("https://")) {
        throw new GatewayConfigError(
          "escalation.webhook_url must use HTTPS (https://)",
        );
      }
    }
  }

  // Circuit breaker
  if (config.circuit_breaker) {
    if (config.circuit_breaker.failure_threshold < 1) {
      throw new GatewayConfigError(
        "circuit_breaker.failure_threshold must be >= 1",
      );
    }
    if (config.circuit_breaker.recovery_timeout_ms < 0) {
      throw new GatewayConfigError(
        "circuit_breaker.recovery_timeout_ms must be >= 0",
      );
    }
  }
}

// ── Path resolution ──────────────────────────────────────────────────

function resolvePath(rawPath: string, configDir: string): string {
  // Expand ~ to home directory
  const expanded = rawPath.startsWith("~")
    ? rawPath.replace(/^~/, homedir())
    : rawPath;
  // Resolve relative paths against config directory
  return resolve(configDir, expanded);
}

// ── Environment variable interpolation ───────────────────────────────

/**
 * Resolve $ENV{VAR_NAME} references in string config values.
 * Returns the original string if no $ENV{} wrapper is present.
 * Throws GatewayConfigError if the env var is not set.
 */
export function resolveEnvVar(value: string): string {
  if (!value.startsWith("$ENV{") || !value.endsWith("}")) {
    return value;
  }
  const varName = value.slice(5, -1);
  const resolved = process.env[varName];
  if (resolved === undefined) {
    throw new GatewayConfigError(
      `Environment variable '${varName}' is not set (referenced in config as ${value})`,
    );
  }
  return resolved;
}

// ── Loading ──────────────────────────────────────────────────────────

/**
 * Load and validate a gateway YAML config file.
 */
export function loadGatewayConfig(configPath: string): GatewayConfig {
  if (!existsSync(configPath)) {
    throw new GatewayConfigError(`Config file not found: ${configPath}`);
  }

  // Permission check: warn if config file is group/world-readable (non-Windows only).
  // gateway.yaml should be permission-restricted (0o600) since it may contain secrets.
  if (platform() !== "win32") {
    try {
      const mode = statSync(resolve(configPath)).mode & 0o777;
      if (mode & 0o077) {
        const octal = "0o" + mode.toString(8);
        process.stderr.write(
          `[sanna-gateway] WARNING: ${configPath} has loose permissions (${octal}). Recommended: chmod 600 ${configPath}\n`,
        );
      }
    } catch {
      // Best-effort — don't fail on permission check errors
    }
  }

  const configDir = dirname(resolve(configPath));
  let raw: unknown;
  try {
    raw = yaml.load(readFileSync(configPath, "utf-8"));
  } catch (err) {
    throw new GatewayConfigError(
      `Invalid YAML in config file: ${err instanceof Error ? err.message : err}`,
    );
  }

  if (!raw || typeof raw !== "object") {
    throw new GatewayConfigError(
      "Config file must contain a YAML mapping",
    );
  }
  const data = raw as Record<string, unknown>;

  // Parse gateway section
  const gwRaw = (data.gateway ?? data) as Record<string, unknown>;

  // Constitution
  const constRaw = gwRaw.constitution as Record<string, unknown> | string | undefined;
  let constitutionPath: string;
  let publicKeyPath: string | undefined;
  let signingKeyPath: string | undefined;

  if (typeof constRaw === "string") {
    constitutionPath = resolvePath(constRaw, configDir);
  } else if (constRaw && typeof constRaw === "object") {
    if (!constRaw.path) {
      throw new GatewayConfigError("Missing required field: constitution.path");
    }
    constitutionPath = resolvePath(String(constRaw.path), configDir);
    if (constRaw.public_key_path) {
      publicKeyPath = resolvePath(String(constRaw.public_key_path), configDir);
    }
    if (constRaw.signing_key_path) {
      signingKeyPath = resolvePath(resolveEnvVar(String(constRaw.signing_key_path)), configDir);
    }
  } else {
    throw new GatewayConfigError("Missing required field: constitution");
  }

  // Enforcement
  const enfRaw = (gwRaw.enforcement ?? {}) as Record<string, unknown>;
  const enfMode = String(enfRaw.mode ?? "enforced") as GatewayConfig["enforcement"]["mode"];
  const enfDefault = String(enfRaw.default_policy ?? "deny") as GatewayConfig["enforcement"]["default_policy"];

  // Listen
  const listenRaw = (gwRaw.listen ?? {}) as Record<string, unknown>;
  const transport = String(listenRaw.transport ?? "stdio") as "stdio";

  // Downstreams
  const dsRaw = (data.downstreams ?? data.downstream ?? gwRaw.downstreams ?? []) as unknown[];
  if (!Array.isArray(dsRaw) || dsRaw.length === 0) {
    throw new GatewayConfigError(
      "Missing required field: downstreams (need at least one entry)",
    );
  }

  const downstreams: DownstreamConfig[] = dsRaw.map((ds, i) => {
    if (!ds || typeof ds !== "object") {
      throw new GatewayConfigError(
        `downstreams[${i}]: expected a mapping`,
      );
    }
    const d = ds as Record<string, unknown>;
    const args = Array.isArray(d.args) ? d.args.map(String) : [];

    // Parse env with interpolation
    let env: Record<string, string> | undefined;
    if (d.env && typeof d.env === "object") {
      env = {};
      for (const [key, val] of Object.entries(d.env as Record<string, unknown>)) {
        env[key] = String(val);
      }
    }

    // Parse policy_overrides
    let policyOverrides: Record<string, "allow" | "deny" | "escalate"> | undefined;
    if (d.policy_overrides && typeof d.policy_overrides === "object") {
      policyOverrides = {};
      for (const [tool, policy] of Object.entries(d.policy_overrides as Record<string, unknown>)) {
        policyOverrides[tool] = String(policy) as "allow" | "deny" | "escalate";
      }
    }
    // Also support "tools" format from Python config
    if (d.tools && typeof d.tools === "object") {
      policyOverrides = policyOverrides ?? {};
      for (const [tool, cfg] of Object.entries(d.tools as Record<string, unknown>)) {
        if (cfg && typeof cfg === "object") {
          const toolCfg = cfg as Record<string, unknown>;
          if (toolCfg.policy) {
            policyOverrides[tool] = String(toolCfg.policy) as "allow" | "deny" | "escalate";
          }
        }
      }
    }

    return {
      name: String(d.name ?? ""),
      command: String(d.command ?? ""),
      args,
      env,
      policy_overrides: policyOverrides,
      timeout: d.timeout ? Number(d.timeout) : undefined,
    };
  });

  // Escalation
  let escalation: GatewayConfig["escalation"];
  const escRaw = (gwRaw.escalation ?? data.escalation) as Record<string, unknown> | undefined;
  if (escRaw && typeof escRaw === "object") {
    // Parse delivery_methods
    let deliveryMethods: Array<"inline" | "webhook" | "file"> | undefined;
    if (Array.isArray(escRaw.delivery_methods)) {
      deliveryMethods = escRaw.delivery_methods.map(String) as Array<"inline" | "webhook" | "file">;
    }

    // Parse webhook_headers
    let webhookHeaders: Record<string, string> | undefined;
    if (escRaw.webhook_headers && typeof escRaw.webhook_headers === "object") {
      webhookHeaders = {};
      for (const [k, v] of Object.entries(escRaw.webhook_headers as Record<string, unknown>)) {
        webhookHeaders[k] = String(v);
      }
    }

    escalation = {
      hmac_secret: resolveEnvVar(String(escRaw.hmac_secret ?? "")),
      ttl_seconds: escRaw.ttl_seconds ? Number(escRaw.ttl_seconds) : undefined,
      store_path: escRaw.store_path
        ? resolvePath(String(escRaw.store_path), configDir)
        : undefined,
      delivery_methods: deliveryMethods,
      webhook_url: escRaw.webhook_url ? resolveEnvVar(String(escRaw.webhook_url)) : undefined,
      webhook_headers: webhookHeaders,
      token_file_path: escRaw.token_file_path
        ? resolvePath(String(escRaw.token_file_path), configDir)
        : undefined,
      max_pending_tokens: escRaw.max_pending_tokens ? Number(escRaw.max_pending_tokens) : undefined,
    };
  }

  // Receipts
  let receipts: GatewayConfig["receipts"];
  const rcpRaw = (gwRaw.receipts ?? data.receipts) as Record<string, unknown> | undefined;
  if (rcpRaw && typeof rcpRaw === "object") {
    receipts = {
      sign: rcpRaw.sign !== false,
      store_path: rcpRaw.store_path
        ? resolvePath(String(rcpRaw.store_path), configDir)
        : undefined,
    };
  }

  // PII
  let pii: GatewayConfig["pii"];
  const piiRaw = (gwRaw.pii ?? data.pii) as Record<string, unknown> | undefined;
  if (piiRaw && typeof piiRaw === "object") {
    pii = {
      enabled: Boolean(piiRaw.enabled),
      patterns: Array.isArray(piiRaw.patterns)
        ? piiRaw.patterns.map(String)
        : undefined,
    };
  }

  // Circuit breaker
  let circuitBreaker: GatewayConfig["circuit_breaker"];
  const cbRaw = (gwRaw.circuit_breaker ?? data.circuit_breaker) as Record<string, unknown> | undefined;
  if (cbRaw && typeof cbRaw === "object") {
    circuitBreaker = {
      failure_threshold: Number(cbRaw.failure_threshold ?? 3),
      recovery_timeout_ms: Number(cbRaw.recovery_timeout_ms ?? 60_000),
      half_open_max: Number(cbRaw.half_open_max ?? 1),
    };
  }

  const config: GatewayConfig = {
    listen: { transport },
    constitution: {
      path: constitutionPath,
      public_key_path: publicKeyPath,
      signing_key_path: signingKeyPath,
    },
    enforcement: {
      mode: enfMode,
      default_policy: enfDefault,
    },
    downstreams,
    escalation,
    receipts,
    pii,
    circuit_breaker: circuitBreaker,
  };

  validateGatewayConfig(config);
  return config;
}

// ── Policy cascade ───────────────────────────────────────────────────

/**
 * Resolve the effective policy for a tool using the cascade:
 *   1. Per-tool override in downstream config
 *   2. Gateway default_policy
 *
 * Returns null if no override applies (fall through to constitution).
 */
export function resolveToolPolicy(
  toolName: string,
  downstream: DownstreamConfig,
  gatewayDefault: GatewayConfig["enforcement"]["default_policy"],
): "allow" | "deny" | "escalate" | null {
  // 1. Per-tool override
  if (downstream.policy_overrides?.[toolName]) {
    return downstream.policy_overrides[toolName];
  }

  // 2. Gateway default (only if not "allow", since allow means fall through)
  if (gatewayDefault !== "allow") {
    return gatewayDefault;
  }

  // 3. No override — fall through to constitution evaluation
  return null;
}
