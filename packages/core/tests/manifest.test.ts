import { describe, it, expect } from "vitest";
import {
  generateManifest,
  MANIFEST_VERSION,
  VALID_SUPPRESSION_REASONS,
  SUPPRESSION_REASON_CANNOT_EXECUTE,
  SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
  SUPPRESSION_REASON_CONSTITUTION_INVALID,
} from "../src/manifest.js";
import type {
  Constitution,
  AuthorityBoundaries,
  EscalationRule,
  CliPermissions,
  CliCommand,
  ApiPermissions,
  ApiEndpoint,
} from "../src/types.js";

// -- Helper: build a minimal Constitution for manifest tests --

function bareConstitution(opts: {
  cannot_execute?: string[];
  must_escalate?: EscalationRule[];
  can_execute?: string[];
  escalation_visibility?: "visible" | "suppressed";
  cli_permissions?: CliPermissions | null;
  api_permissions?: ApiPermissions | null;
  no_authority_boundaries?: boolean;
} = {}): Constitution {
  const ab: AuthorityBoundaries | null = opts.no_authority_boundaries
    ? null
    : {
        cannot_execute: opts.cannot_execute ?? [],
        must_escalate: opts.must_escalate ?? [],
        can_execute: opts.can_execute ?? [],
        default_escalation: "log",
        escalation_visibility: opts.escalation_visibility ?? "visible",
      };

  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "manifest test constitution",
      extensions: {},
    },
    provenance: {
      authored_by: "tester@test.com",
      approved_by: ["approver@test.com"],
      approval_date: "2026-01-01",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants: [],
    policy_hash: null,
    authority_boundaries: ab,
    cli_permissions: opts.cli_permissions ?? null,
    api_permissions: opts.api_permissions ?? null,
    trusted_sources: null,
  };
}

function makeEscalationRule(condition: string): EscalationRule {
  return { condition, target: null };
}

function makeCliCommand(
  binary: string,
  authority: "can_execute" | "must_escalate" | "cannot_execute",
): CliCommand {
  return { id: `cli-${binary}`, binary, authority };
}

function makeCliPermissions(
  commands: CliCommand[],
  mode: "strict" | "permissive" = "strict",
): CliPermissions {
  return { mode, justification_required: false, commands, invariants: [] };
}

function makeApiEndpoint(
  url_pattern: string,
  authority: "can_execute" | "must_escalate" | "cannot_execute",
): ApiEndpoint {
  return { id: `ep-${url_pattern}`, url_pattern, authority };
}

function makeApiPermissions(
  endpoints: ApiEndpoint[],
  mode: "strict" | "permissive" = "strict",
): ApiPermissions {
  return { mode, justification_required: false, endpoints, invariants: [] };
}

// =============================================================================
// 1. Top-level structure
// =============================================================================

describe("SAN-203 manifest: top-level structure", () => {
  it("version and composition_basis match v1.5 spec", () => {
    const out = generateManifest(bareConstitution());
    expect(out.version).toBe(MANIFEST_VERSION);
    expect(out.composition_basis).toBe("static");
    expect(out.surfaces).toBeDefined();
  });

  it("omits mcp surface when mcpTools is undefined", () => {
    const out = generateManifest(bareConstitution());
    expect(out.surfaces.mcp).toBeUndefined();
  });

  it("includes mcp surface for empty mcpTools list", () => {
    const out = generateManifest(bareConstitution(), []);
    expect(out.surfaces.mcp).toBeDefined();
    expect(out.surfaces.mcp!.tools_delivered).toEqual([]);
    expect(out.surfaces.mcp!.tools_suppressed).toEqual([]);
  });

  it("omits cli surface when cli_permissions is null", () => {
    const out = generateManifest(bareConstitution());
    expect(out.surfaces.cli).toBeUndefined();
  });

  it("omits http surface when api_permissions is null", () => {
    const out = generateManifest(bareConstitution());
    expect(out.surfaces.http).toBeUndefined();
  });
});

// =============================================================================
// 2. MCP surface -- cannot_execute suppression
// =============================================================================

describe("SAN-203 manifest: MCP cannot_execute suppression", () => {
  it("suppresses cannot_execute tool and delivers others", () => {
    const c = bareConstitution({ cannot_execute: ["delete_all"] });
    const out = generateManifest(c, ["delete_all", "read_data"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_delivered).toContain("read_data");
    expect(mcp.tools_suppressed).toContain("delete_all");
    expect(mcp.tools_delivered).not.toContain("delete_all");
  });

  it("suppression_reason for cannot_execute is cannot_execute enum value", () => {
    const c = bareConstitution({ cannot_execute: ["nuke_db"] });
    const out = generateManifest(c, ["nuke_db"]);
    expect(out.surfaces.mcp!.suppression_reasons["nuke_db"]).toBe(
      SUPPRESSION_REASON_CANNOT_EXECUTE,
    );
  });

  it("suppression_reason value is in VALID_SUPPRESSION_REASONS", () => {
    const c = bareConstitution({ cannot_execute: ["forbidden"] });
    const out = generateManifest(c, ["forbidden"]);
    const reason = out.surfaces.mcp!.suppression_reasons["forbidden"];
    expect(VALID_SUPPRESSION_REASONS.has(reason)).toBe(true);
  });
});

// =============================================================================
// 3. MCP surface -- escalation_visibility
// =============================================================================

describe("SAN-203 manifest: MCP escalation_visibility", () => {
  it("escalation_visibility=visible includes must_escalate in delivered", () => {
    const c = bareConstitution({
      must_escalate: [makeEscalationRule("anything")],
      escalation_visibility: "visible",
    });
    const out = generateManifest(c, ["anything"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_delivered).toContain("anything");
    expect(mcp.tools_suppressed).not.toContain("anything");
  });

  it("escalation_visibility=suppressed hides must_escalate in suppressed", () => {
    const c = bareConstitution({
      must_escalate: [makeEscalationRule("anything")],
      escalation_visibility: "suppressed",
    });
    const out = generateManifest(c, ["anything"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_suppressed).toContain("anything");
    expect(mcp.tools_delivered).not.toContain("anything");
    expect(mcp.suppression_reasons["anything"]).toBe(
      SUPPRESSION_REASON_ESCALATION_SUPPRESSED,
    );
  });

  it("default escalation_visibility is visible (must_escalate delivered)", () => {
    const c = bareConstitution({
      must_escalate: [makeEscalationRule("review_data")],
    });
    const out = generateManifest(c, ["review_data"]);
    expect(out.surfaces.mcp!.tools_delivered).toContain("review_data");
  });
});

// =============================================================================
// 4. Fail-closed on null constitution or null authority_boundaries
// =============================================================================

describe("SAN-203 manifest: fail-closed", () => {
  it("null constitution suppresses all mcp tools", () => {
    const out = generateManifest(null, ["x", "y"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_delivered).toEqual([]);
    expect([...mcp.tools_suppressed].sort()).toEqual(["x", "y"]);
  });

  it("null constitution gives constitution_invalid suppression reason", () => {
    const out = generateManifest(null, ["x"]);
    expect(out.surfaces.mcp!.suppression_reasons["x"]).toBe(
      SUPPRESSION_REASON_CONSTITUTION_INVALID,
    );
  });

  it("null authority_boundaries suppresses all mcp tools", () => {
    const c = bareConstitution({ no_authority_boundaries: true });
    const out = generateManifest(c, ["a", "b"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_delivered).toEqual([]);
    for (const name of ["a", "b"]) {
      expect(mcp.tools_suppressed).toContain(name);
      expect(mcp.suppression_reasons[name]).toBe(SUPPRESSION_REASON_CONSTITUTION_INVALID);
    }
  });

  it("null constitution omits cli and http surfaces", () => {
    const out = generateManifest(null);
    expect(out.surfaces.cli).toBeUndefined();
    expect(out.surfaces.http).toBeUndefined();
  });
});

// =============================================================================
// 5. Determinism and no-overlap invariants
// =============================================================================

describe("SAN-203 manifest: determinism and overlap invariants", () => {
  it("tools_delivered is sorted alphabetically", () => {
    const c = bareConstitution({ can_execute: ["aaa", "mmm", "zzz"] });
    const out = generateManifest(c, ["zzz", "mmm", "aaa"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_delivered).toEqual([...mcp.tools_delivered].sort());
  });

  it("tools_suppressed is sorted alphabetically", () => {
    const c = bareConstitution({ cannot_execute: ["zzz", "mmm"] });
    const out = generateManifest(c, ["zzz", "mmm", "aaa"]);
    const mcp = out.surfaces.mcp!;
    expect(mcp.tools_suppressed).toEqual([...mcp.tools_suppressed].sort());
  });

  it("no tool appears in both delivered and suppressed", () => {
    const c = bareConstitution({
      cannot_execute: ["x"],
      can_execute: ["y"],
    });
    const out = generateManifest(c, ["x", "y"]);
    const mcp = out.surfaces.mcp!;
    const deliveredSet = new Set(mcp.tools_delivered);
    const suppressedSet = new Set(mcp.tools_suppressed);
    for (const name of deliveredSet) {
      expect(suppressedSet.has(name)).toBe(false);
    }
  });

  it("identical inputs produce identical output (idempotent)", () => {
    const c = bareConstitution({ cannot_execute: ["del"], can_execute: ["get"] });
    const tools = ["get", "del", "set"];
    const out1 = generateManifest(c, tools);
    const out2 = generateManifest(c, tools);
    expect(out1).toEqual(out2);
  });
});

// =============================================================================
// 6. CLI surface
// =============================================================================

describe("SAN-203 manifest: CLI surface", () => {
  it("can_execute command appears in patterns_delivered", () => {
    const cli = makeCliPermissions([makeCliCommand("ls", "can_execute")]);
    const c = bareConstitution({ cli_permissions: cli });
    const out = generateManifest(c);
    expect(out.surfaces.cli!.patterns_delivered).toContain("ls");
  });

  it("cannot_execute command appears in patterns_suppressed", () => {
    const cli = makeCliPermissions([makeCliCommand("rm", "cannot_execute")]);
    const c = bareConstitution({ cli_permissions: cli });
    const out = generateManifest(c);
    expect(out.surfaces.cli!.patterns_suppressed).toContain("rm");
    expect(out.surfaces.cli!.patterns_delivered).not.toContain("rm");
  });

  it("must_escalate with visible delivers the command", () => {
    const cli = makeCliPermissions([makeCliCommand("sudo", "must_escalate")]);
    const c = bareConstitution({ cli_permissions: cli, escalation_visibility: "visible" });
    const out = generateManifest(c);
    expect(out.surfaces.cli!.patterns_delivered).toContain("sudo");
  });

  it("must_escalate with suppressed hides the command", () => {
    const cli = makeCliPermissions([makeCliCommand("sudo", "must_escalate")]);
    const c = bareConstitution({ cli_permissions: cli, escalation_visibility: "suppressed" });
    const out = generateManifest(c);
    expect(out.surfaces.cli!.patterns_suppressed).toContain("sudo");
    expect(out.surfaces.cli!.patterns_delivered).not.toContain("sudo");
  });

  it("mode is passed through to cli surface", () => {
    const cli = makeCliPermissions([], "permissive");
    const c = bareConstitution({ cli_permissions: cli });
    const out = generateManifest(c);
    expect(out.surfaces.cli!.mode).toBe("permissive");
  });

  it("patterns_delivered is sorted alphabetically", () => {
    const cli = makeCliPermissions([
      makeCliCommand("zzz", "can_execute"),
      makeCliCommand("aaa", "can_execute"),
    ]);
    const c = bareConstitution({ cli_permissions: cli });
    const delivered = generateManifest(c).surfaces.cli!.patterns_delivered;
    expect(delivered).toEqual([...delivered].sort());
  });
});

// =============================================================================
// 7. HTTP surface
// =============================================================================

describe("SAN-203 manifest: HTTP surface", () => {
  it("can_execute endpoint appears in patterns_delivered", () => {
    const api = makeApiPermissions([makeApiEndpoint("/api/read", "can_execute")]);
    const c = bareConstitution({ api_permissions: api });
    const out = generateManifest(c);
    expect(out.surfaces.http!.patterns_delivered).toContain("/api/read");
  });

  it("cannot_execute endpoint appears in patterns_suppressed", () => {
    const api = makeApiPermissions([makeApiEndpoint("/admin/*", "cannot_execute")]);
    const c = bareConstitution({ api_permissions: api });
    const out = generateManifest(c);
    expect(out.surfaces.http!.patterns_suppressed).toContain("/admin/*");
    expect(out.surfaces.http!.patterns_delivered).not.toContain("/admin/*");
  });

  it("must_escalate with visible delivers the endpoint", () => {
    const api = makeApiPermissions([makeApiEndpoint("/api/delete", "must_escalate")]);
    const c = bareConstitution({ api_permissions: api, escalation_visibility: "visible" });
    const out = generateManifest(c);
    expect(out.surfaces.http!.patterns_delivered).toContain("/api/delete");
  });

  it("must_escalate with suppressed hides the endpoint", () => {
    const api = makeApiPermissions([makeApiEndpoint("/api/delete", "must_escalate")]);
    const c = bareConstitution({ api_permissions: api, escalation_visibility: "suppressed" });
    const out = generateManifest(c);
    expect(out.surfaces.http!.patterns_suppressed).toContain("/api/delete");
    expect(out.surfaces.http!.patterns_delivered).not.toContain("/api/delete");
  });

  it("mode is passed through to http surface", () => {
    const api = makeApiPermissions([], "permissive");
    const c = bareConstitution({ api_permissions: api });
    const out = generateManifest(c);
    expect(out.surfaces.http!.mode).toBe("permissive");
  });
});
