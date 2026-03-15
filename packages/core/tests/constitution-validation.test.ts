/**
 * Tests for cli_permissions and api_permissions validation in validateConstitutionData().
 */

import { describe, it, expect } from "vitest";
import { validateConstitutionData } from "../src/constitution.js";

// Minimal valid constitution base for testing
function validBase(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    identity: { agent_name: "test", domain: "test", description: "test" },
    provenance: {
      authored_by: "test",
      approved_by: ["test"],
      approval_date: "2026-01-01",
      approval_method: "manual",
    },
    boundaries: [{ id: "B001", description: "test", category: "safety", severity: "critical" }],
    ...extra,
  };
}

// ── cli_permissions validation ───────────────────────────────────────

describe("validateConstitutionData — cli_permissions", () => {
  it("valid cli_permissions passes", () => {
    const data = validBase({
      cli_permissions: {
        mode: "strict",
        justification_required: true,
        commands: [
          { id: "CLI001", binary: "git", authority: "can_execute" },
          { id: "CLI002", binary: "rm", authority: "cannot_execute" },
        ],
        invariants: [
          { id: "CLINV001", description: "No sudo", verdict: "halt", pattern: "sudo" },
        ],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });

  it("cli_permissions not object fails", () => {
    const data = validBase({ cli_permissions: "bad" });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("cli_permissions must be an object"));
  });

  it("cli_permissions invalid mode fails", () => {
    const data = validBase({
      cli_permissions: { mode: "relaxed", commands: [], invariants: [] },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("must be 'strict' or 'permissive'"));
  });

  it("cli_permissions missing binary fails", () => {
    const data = validBase({
      cli_permissions: {
        commands: [{ id: "CLI001", authority: "can_execute" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("binary is required"));
  });

  it("cli_permissions invalid authority fails", () => {
    const data = validBase({
      cli_permissions: {
        commands: [{ id: "CLI001", binary: "git", authority: "allow" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("authority"));
  });

  it("cli_permissions duplicate command ID fails", () => {
    const data = validBase({
      cli_permissions: {
        commands: [
          { id: "CLI001", binary: "git", authority: "can_execute" },
          { id: "CLI001", binary: "npm", authority: "can_execute" },
        ],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("Duplicate cli_permissions command ID: CLI001"));
  });

  it("cli_permissions binary with path separator fails", () => {
    const data = validBase({
      cli_permissions: {
        commands: [{ id: "CLI001", binary: "/usr/bin/git", authority: "can_execute" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("must not contain path separators or wildcards"));
  });

  it("cli_permissions invariant invalid verdict fails", () => {
    const data = validBase({
      cli_permissions: {
        commands: [],
        invariants: [{ id: "INV1", description: "test", verdict: "block" }],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("verdict 'block' must be 'halt' or 'warn'"));
  });
});

// ── api_permissions validation ───────────────────────────────────────

describe("validateConstitutionData — api_permissions", () => {
  it("valid api_permissions passes", () => {
    const data = validBase({
      api_permissions: {
        mode: "permissive",
        justification_required: false,
        endpoints: [
          { id: "API001", url_pattern: "https://api.example.com/*", authority: "can_execute", methods: ["GET", "POST"] },
        ],
        invariants: [
          { id: "APINV001", description: "No API keys in URLs", verdict: "halt", pattern: "api_key=" },
        ],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });

  it("api_permissions not object fails", () => {
    const data = validBase({ api_permissions: [1, 2, 3] });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("api_permissions must be an object"));
  });

  it("api_permissions invalid mode fails", () => {
    const data = validBase({
      api_permissions: { mode: "open", endpoints: [], invariants: [] },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("must be 'strict' or 'permissive'"));
  });

  it("api_permissions missing url_pattern fails", () => {
    const data = validBase({
      api_permissions: {
        endpoints: [{ id: "API001", authority: "can_execute" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("url_pattern is required"));
  });

  it("api_permissions invalid authority fails", () => {
    const data = validBase({
      api_permissions: {
        endpoints: [{ id: "API001", url_pattern: "https://*", authority: "deny" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("authority"));
  });

  it("api_permissions invalid method fails", () => {
    const data = validBase({
      api_permissions: {
        endpoints: [{ id: "API001", url_pattern: "https://*", authority: "can_execute", methods: ["GET", "YEET"] }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("'YEET' is not a valid HTTP method"));
  });

  it("api_permissions duplicate endpoint ID fails", () => {
    const data = validBase({
      api_permissions: {
        endpoints: [
          { id: "API001", url_pattern: "https://a.com/*", authority: "can_execute" },
          { id: "API001", url_pattern: "https://b.com/*", authority: "can_execute" },
        ],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("Duplicate api_permissions endpoint ID: API001"));
  });

  it("api_permissions invariant invalid verdict fails", () => {
    const data = validBase({
      api_permissions: {
        endpoints: [],
        invariants: [{ id: "INV1", description: "test", verdict: "deny" }],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toContainEqual(expect.stringContaining("verdict 'deny' must be 'halt' or 'warn'"));
  });
});

// ── Cross-block tests ────────────────────────────────────────────────

describe("validateConstitutionData — cross-block", () => {
  it("all three blocks valid", () => {
    const data = validBase({
      authority_boundaries: {
        cannot_execute: ["dangerous_tool"],
        must_escalate: [{ condition: "sensitive" }],
        can_execute: ["safe_tool"],
      },
      cli_permissions: {
        mode: "strict",
        commands: [{ id: "CLI001", binary: "git", authority: "can_execute" }],
        invariants: [],
      },
      api_permissions: {
        mode: "permissive",
        endpoints: [{ id: "API001", url_pattern: "https://*", authority: "can_execute" }],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });

  it("cli and api without authority_boundaries valid", () => {
    const data = validBase({
      cli_permissions: {
        mode: "permissive",
        commands: [],
        invariants: [],
      },
      api_permissions: {
        mode: "strict",
        endpoints: [],
        invariants: [],
      },
    });
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });

  it("absent cli/api still valid (backward compat)", () => {
    const data = validBase();
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });
});
