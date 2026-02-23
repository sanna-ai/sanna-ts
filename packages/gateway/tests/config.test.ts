import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir, homedir } from "node:os";
import yaml from "js-yaml";
import {
  loadGatewayConfig,
  validateGatewayConfig,
  resolveToolPolicy,
  resolveEnvVar,
  GatewayConfigError,
} from "../src/config.js";
import type { GatewayConfig, DownstreamConfig } from "../src/config.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "sanna-gw-config-test-"));
  // Create a dummy constitution file
  writeFileSync(
    join(tmpDir, "constitution.yaml"),
    yaml.dump({
      schema_version: "1.0",
      identity: { agent_name: "test", domain: "test", description: "test", extensions: {} },
      provenance: {
        authored_by: "test",
        approved_by: [],
        approval_date: "2025-01-01",
        approval_method: "manual",
        change_history: [],
        signature: null,
      },
      boundaries: [],
      trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
      halt_conditions: [],
      invariants: [],
      authority_boundaries: null,
      trusted_sources: null,
    }),
  );
});

afterEach(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

function writeConfig(data: unknown): string {
  const path = join(tmpDir, "gateway.yaml");
  writeFileSync(path, yaml.dump(data));
  return path;
}

describe("loadGatewayConfig", () => {
  it("should parse a valid config", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
        enforcement: { mode: "enforced", default_policy: "deny" },
      },
      downstreams: [
        { name: "test-server", command: "node", args: ["server.js"] },
      ],
    });
    const config = loadGatewayConfig(path);
    expect(config.constitution.path).toBe(join(tmpDir, "constitution.yaml"));
    expect(config.enforcement.mode).toBe("enforced");
    expect(config.enforcement.default_policy).toBe("deny");
    expect(config.downstreams).toHaveLength(1);
    expect(config.downstreams[0].name).toBe("test-server");
  });

  it("should throw for missing config file", () => {
    expect(() => loadGatewayConfig("/nonexistent/path.yaml")).toThrow(
      "Config file not found",
    );
  });

  it("should throw for missing constitution", () => {
    const path = writeConfig({
      gateway: {},
      downstreams: [{ name: "s", command: "node" }],
    });
    expect(() => loadGatewayConfig(path)).toThrow("constitution");
  });

  it("should throw for missing downstreams", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
      },
    });
    expect(() => loadGatewayConfig(path)).toThrow("downstreams");
  });

  it("should resolve relative paths against config directory", () => {
    const subDir = join(tmpDir, "sub");
    mkdirSync(subDir);
    writeFileSync(join(subDir, "const.yaml"), "schema_version: '1.0'\nidentity:\n  agent_name: x\n  domain: x\n  description: x\n  extensions: {}\nprovenance:\n  authored_by: x\n  approved_by: []\n  approval_date: '2025-01-01'\n  approval_method: manual\n  change_history: []\n  signature: null\nboundaries: []\ntrust_tiers:\n  autonomous: []\n  requires_approval: []\n  prohibited: []\nhalt_conditions: []\ninvariants: []\nauthority_boundaries: null\ntrusted_sources: null\n");
    const path = join(subDir, "gw.yaml");
    writeFileSync(
      path,
      yaml.dump({
        gateway: {
          constitution: { path: "./const.yaml" },
        },
        downstreams: [{ name: "s", command: "node" }],
      }),
    );
    const config = loadGatewayConfig(path);
    expect(config.constitution.path).toBe(join(subDir, "const.yaml"));
  });

  it("should parse multiple downstreams", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
      },
      downstreams: [
        { name: "server-a", command: "node", args: ["a.js"] },
        { name: "server-b", command: "python", args: ["b.py"] },
      ],
    });
    const config = loadGatewayConfig(path);
    expect(config.downstreams).toHaveLength(2);
    expect(config.downstreams[0].name).toBe("server-a");
    expect(config.downstreams[1].name).toBe("server-b");
  });

  it("should parse policy_overrides", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
      },
      downstreams: [
        {
          name: "s",
          command: "node",
          policy_overrides: { "dangerous-tool": "deny" },
        },
      ],
    });
    const config = loadGatewayConfig(path);
    expect(config.downstreams[0].policy_overrides).toEqual({
      "dangerous-tool": "deny",
    });
  });

  it("should parse escalation config", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
        escalation: { hmac_secret: "test-secret", ttl_seconds: 600 },
      },
      downstreams: [{ name: "s", command: "node" }],
    });
    const config = loadGatewayConfig(path);
    expect(config.escalation).toBeDefined();
    expect(config.escalation!.hmac_secret).toBe("test-secret");
    expect(config.escalation!.ttl_seconds).toBe(600);
  });

  it("should parse circuit breaker config", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
        circuit_breaker: {
          failure_threshold: 5,
          recovery_timeout_ms: 30000,
          half_open_max: 2,
        },
      },
      downstreams: [{ name: "s", command: "node" }],
    });
    const config = loadGatewayConfig(path);
    expect(config.circuit_breaker).toBeDefined();
    expect(config.circuit_breaker!.failure_threshold).toBe(5);
  });

  it("should use default enforcement values", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
      },
      downstreams: [{ name: "s", command: "node" }],
    });
    const config = loadGatewayConfig(path);
    expect(config.enforcement.mode).toBe("enforced");
    expect(config.enforcement.default_policy).toBe("deny");
  });
});

describe("validateGatewayConfig", () => {
  it("should reject invalid enforcement mode", () => {
    const config = {
      listen: { transport: "stdio" as const },
      constitution: { path: "/some/path" },
      enforcement: { mode: "invalid" as any, default_policy: "deny" as const },
      downstreams: [{ name: "s", command: "node", args: [] }],
    };
    expect(() => validateGatewayConfig(config)).toThrow("enforcement.mode");
  });

  it("should reject duplicate downstream names", () => {
    const config = {
      listen: { transport: "stdio" as const },
      constitution: { path: "/some/path" },
      enforcement: { mode: "enforced" as const, default_policy: "deny" as const },
      downstreams: [
        { name: "same", command: "node", args: [] },
        { name: "same", command: "python", args: [] },
      ],
    };
    expect(() => validateGatewayConfig(config)).toThrow("duplicate");
  });

  it("should reject invalid downstream name characters", () => {
    const config = {
      listen: { transport: "stdio" as const },
      constitution: { path: "/some/path" },
      enforcement: { mode: "enforced" as const, default_policy: "deny" as const },
      downstreams: [{ name: "has spaces", command: "node", args: [] }],
    };
    expect(() => validateGatewayConfig(config)).toThrow("invalid characters");
  });
});

describe("resolveToolPolicy", () => {
  it("should return per-tool override if set", () => {
    const ds: DownstreamConfig = {
      name: "s",
      command: "node",
      args: [],
      policy_overrides: { "delete-all": "deny" },
    };
    expect(resolveToolPolicy("delete-all", ds, "allow")).toBe("deny");
  });

  it("should return gateway default when not allow", () => {
    const ds: DownstreamConfig = {
      name: "s",
      command: "node",
      args: [],
    };
    expect(resolveToolPolicy("some-tool", ds, "escalate")).toBe("escalate");
  });

  it("should return null when no override applies", () => {
    const ds: DownstreamConfig = {
      name: "s",
      command: "node",
      args: [],
    };
    expect(resolveToolPolicy("some-tool", ds, "allow")).toBeNull();
  });
});

describe("resolveEnvVar", () => {
  it("should resolve $ENV{} references when env var is set", () => {
    process.env.TEST_HMAC_SECRET = "my-secret-value";
    try {
      expect(resolveEnvVar("$ENV{TEST_HMAC_SECRET}")).toBe("my-secret-value");
    } finally {
      delete process.env.TEST_HMAC_SECRET;
    }
  });

  it("should throw when env var is missing", () => {
    delete process.env.SANNA_NONEXISTENT_VAR_12345;
    expect(() => resolveEnvVar("$ENV{SANNA_NONEXISTENT_VAR_12345}")).toThrow(
      "SANNA_NONEXISTENT_VAR_12345",
    );
  });

  it("should pass through plain strings unchanged", () => {
    expect(resolveEnvVar("plain-secret")).toBe("plain-secret");
    expect(resolveEnvVar("")).toBe("");
    expect(resolveEnvVar("$ENV{incomplete")).toBe("$ENV{incomplete");
  });
});

describe("loadGatewayConfig env var interpolation", () => {
  it("should resolve $ENV{} in escalation.hmac_secret", () => {
    process.env.TEST_GW_HMAC = "resolved-hmac-secret";
    try {
      const path = writeConfig({
        gateway: {
          constitution: { path: "./constitution.yaml" },
          escalation: { hmac_secret: "$ENV{TEST_GW_HMAC}" },
        },
        downstreams: [{ name: "s", command: "node" }],
      });
      const config = loadGatewayConfig(path);
      expect(config.escalation!.hmac_secret).toBe("resolved-hmac-secret");
    } finally {
      delete process.env.TEST_GW_HMAC;
    }
  });

  it("should throw when referenced env var is missing", () => {
    delete process.env.MISSING_GW_SECRET;
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
        escalation: { hmac_secret: "$ENV{MISSING_GW_SECRET}" },
      },
      downstreams: [{ name: "s", command: "node" }],
    });
    expect(() => loadGatewayConfig(path)).toThrow("MISSING_GW_SECRET");
  });
});

describe("loadGatewayConfig file permission warning", () => {
  it("should warn on loose file permissions", () => {
    const path = writeConfig({
      gateway: {
        constitution: { path: "./constitution.yaml" },
      },
      downstreams: [{ name: "s", command: "node" }],
    });
    // Set world-readable permissions
    chmodSync(path, 0o644);

    // Capture stderr
    const chunks: string[] = [];
    const origWrite = process.stderr.write;
    process.stderr.write = ((chunk: string) => {
      chunks.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;

    try {
      loadGatewayConfig(path);
    } finally {
      process.stderr.write = origWrite;
    }

    const stderr = chunks.join("");
    expect(stderr).toContain("WARNING");
    expect(stderr).toContain("loose permissions");
  });
});
