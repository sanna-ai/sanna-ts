import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  generateManifest,
  hashContent,
  MANIFEST_VERSION,
} from "../src/index.js";
import { parseConstitution } from "../src/constitution.js";
import type { Constitution } from "../src/types.js";

const SCHEMA_PATH = resolve(import.meta.dirname, "../../../spec/schemas/receipt.schema.json");
const RECEIPT_SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, "utf-8"));

const ajv = new Ajv2020({ allErrors: true, strict: false });
addFormats(ajv as any);
const validateReceipt = ajv.compile(RECEIPT_SCHEMA);

// ── Helpers ──────────────────────────────────────────────────────────

function makeMinimalConstitutionDict(opts: {
  cannot_execute?: string[];
  must_escalate?: Array<{ condition: string }>;
  escalation_visibility?: "visible" | "suppressed";
} = {}): Record<string, unknown> {
  return {
    sanna_constitution: "1.0.0",
    identity: { agent_name: "mode-test-agent", domain: "testing" },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-04-30",
      approval_method: "test",
    },
    boundaries: [{ id: "B001", description: "test", category: "scope", severity: "high" }],
    authority_boundaries: {
      cannot_execute: opts.cannot_execute ?? [],
      must_escalate: opts.must_escalate ?? [],
      can_execute: [],
      escalation_visibility: opts.escalation_visibility ?? "visible",
    },
  };
}

function wrapInSessionManifestReceipt(manifestExt: Record<string, unknown>): Record<string, unknown> {
  return {
    spec_version: "1.5",
    tool_version: "1.5.0",
    tool_name: "sanna-ts",
    checks_version: "9",
    receipt_id: "12345678-1234-4234-8234-123456789012",
    receipt_fingerprint: "a".repeat(16),
    full_fingerprint: "a".repeat(64),
    correlation_id: "manifest-mode-test",
    timestamp: "2026-04-30T12:00:00Z",
    inputs: { query: "session_manifest" },
    outputs: { response: "" },
    context_hash: "a".repeat(64),
    output_hash: "a".repeat(64),
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "PASS",
    invariants_scope: "none",
    enforcement_surface: "gateway",
    event_type: "session_manifest",
    enforcement: null,
    extensions: { "com.sanna.manifest": manifestExt },
  };
}

function parseTestConstitution(dict: Record<string, unknown>): Constitution {
  return parseConstitution(dict);
}

// ── Tests: redacted mode ──────────────────────────────────────────────

describe("SAN-209 manifest content_mode=redacted", () => {
  it("tool names become <redacted>, suppression_reasons omitted, aggregate added", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict({ cannot_execute: ["delete_all"] }));
    const manifest = generateManifest(c, ["read_data", "delete_all"], undefined, "redacted") as any;

    const mcp = manifest.surfaces.mcp;
    expect(mcp.tools_delivered).toEqual(["<redacted>"]);
    expect(mcp.tools_suppressed).toEqual(["<redacted>"]);
    expect(mcp.suppression_reasons).toBeUndefined();
    expect(mcp.aggregate_suppression_reasons).toEqual(["cannot_execute"]);

    const wrapped = wrapInSessionManifestReceipt(manifest as unknown as Record<string, unknown>);
    wrapped.content_mode = "redacted";
    wrapped.content_mode_source = "local_config";
    const valid = validateReceipt(wrapped);
    expect(valid, JSON.stringify(validateReceipt.errors)).toBe(true);
  });

  it("no aggregate_suppression_reasons when no suppressions", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict());
    const manifest = generateManifest(c, ["read_data"], undefined, "redacted") as any;

    const mcp = manifest.surfaces.mcp;
    expect(mcp.tools_delivered).toEqual(["<redacted>"]);
    expect(mcp.tools_suppressed).toEqual([]);
    expect(mcp.aggregate_suppression_reasons).toBeUndefined();

    const wrapped = wrapInSessionManifestReceipt(manifest as unknown as Record<string, unknown>);
    wrapped.content_mode = "redacted";
    wrapped.content_mode_source = "local_config";
    const valid = validateReceipt(wrapped);
    expect(valid, JSON.stringify(validateReceipt.errors)).toBe(true);
  });

  it("aggregate aligned by index with sorted suppressed list", () => {
    const c = parseTestConstitution(
      makeMinimalConstitutionDict({ cannot_execute: ["alpha", "zebra"] })
    );
    const manifest = generateManifest(c, ["alpha", "read_data", "zebra"], undefined, "redacted") as any;

    const mcp = manifest.surfaces.mcp;
    // Suppressed list is sorted: ["alpha", "zebra"]
    // aggregate aligned by index: both are cannot_execute
    expect(mcp.tools_suppressed).toHaveLength(2);
    expect(mcp.aggregate_suppression_reasons).toEqual(["cannot_execute", "cannot_execute"]);
  });

  it("full mode: cleartext preserved, suppression_reasons present, no aggregate", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict({ cannot_execute: ["delete_all"] }));
    const manifest = generateManifest(c, ["read_data", "delete_all"], undefined, "full") as any;

    const mcp = manifest.surfaces.mcp;
    expect(mcp.tools_delivered).toContain("read_data");
    expect(mcp.tools_suppressed).toContain("delete_all");
    expect(mcp.suppression_reasons).toBeDefined();
    expect(mcp.suppression_reasons["delete_all"]).toBe("cannot_execute");
    expect(mcp.aggregate_suppression_reasons).toBeUndefined();
  });
});

// ── Tests: hashes_only mode ───────────────────────────────────────────

describe("SAN-209 manifest content_mode=hashes_only", () => {
  it("tool names become SHA-256 hex, suppression_reasons keys also hashed", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict({ cannot_execute: ["delete_all"] }));
    const manifest = generateManifest(c, ["read_data", "delete_all"], undefined, "hashes_only") as any;

    const mcp = manifest.surfaces.mcp;
    const expectedReadHash = hashContent("read_data");
    const expectedDeleteHash = hashContent("delete_all");

    expect(mcp.tools_delivered).toContain(expectedReadHash);
    expect(mcp.tools_suppressed).toContain(expectedDeleteHash);
    expect(mcp.suppression_reasons[expectedDeleteHash]).toBe("cannot_execute");
    expect(mcp.suppression_reasons["delete_all"]).toBeUndefined();

    const wrapped = wrapInSessionManifestReceipt(manifest as unknown as Record<string, unknown>);
    wrapped.content_mode = "hashes_only";
    wrapped.content_mode_source = "local_config";
    const valid = validateReceipt(wrapped);
    expect(valid, JSON.stringify(validateReceipt.errors)).toBe(true);
  });

  it("hashed lists are sorted alphabetically by hash value", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict({ cannot_execute: ["alpha", "zebra"] }));
    const manifest = generateManifest(c, ["alpha", "zebra"], undefined, "hashes_only") as any;

    const mcp = manifest.surfaces.mcp;
    const suppressed = mcp.tools_suppressed as string[];
    expect(suppressed).toEqual([...suppressed].sort());
  });
});

// ── Tests: surfaces filter ────────────────────────────────────────────

describe("SAN-209 manifest surfaces filter", () => {
  it("surfaces=['mcp'] drops cli and http from output", () => {
    const dict = makeMinimalConstitutionDict();
    (dict as any).cli_permissions = {
      mode: "strict",
      justification_required: false,
      commands: [{ id: "CLI001", binary: "git", authority: "can_execute" }],
      invariants: [],
    };
    (dict as any).api_permissions = {
      mode: "strict",
      justification_required: false,
      endpoints: [{ id: "EP001", url_pattern: "https://api.example.com/*", authority: "can_execute" }],
      invariants: [],
    };

    const c = parseTestConstitution(dict);
    const manifest = generateManifest(c, ["read_data"], ["mcp"]) as any;

    expect(manifest.surfaces.mcp).toBeDefined();
    expect(manifest.surfaces.cli).toBeUndefined();
    expect(manifest.surfaces.http).toBeUndefined();
  });
});

// ── Tests: version and composition_basis ─────────────────────────────

describe("SAN-209 manifest output structure", () => {
  it("version and composition_basis are preserved across all content modes", () => {
    const c = parseTestConstitution(makeMinimalConstitutionDict());

    for (const mode of ["full", "redacted", "hashes_only"] as const) {
      const manifest = generateManifest(c, ["read_data"], undefined, mode) as any;
      expect(manifest.version).toBe(MANIFEST_VERSION);
      expect(manifest.composition_basis).toBe("static");
    }
  });
});
