/**
 * SAN-358: Tests for verifier-manifest.ts -- session_manifest and invocation_anomaly checks.
 *
 * Positive + negative cases for each of the 12 checks. FAIL/WARN message assertions
 * use the exact string from verify_manifest.py so cross-SDK byte-equal equivalence is
 * enforced here.
 */

import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import {
  verifySessionManifestReceipt,
  verifyInvocationAnomalyReceipt,
} from "../src/verifier-manifest.js";
import { verifyReceiptSet } from "../src/verifier.js";
import type { Check } from "../src/types.js";

// ===========================================================================
// Helpers
// ===========================================================================

const HASH_64 = "a".repeat(64);
const HASH_16 = "b".repeat(16);
const POLICY_HASH = "c".repeat(64);

function baseManifestExt(opts?: {
  surfaces?: Record<string, unknown>;
  version?: string;
  composition_basis?: string;
}): Record<string, unknown> {
  const surfaces = opts?.surfaces ?? {
    mcp: {
      tools_delivered: ["read_data"],
      tools_suppressed: ["delete_all"],
      suppression_reasons: { delete_all: "cannot_execute" },
    },
  };
  return {
    version: opts?.version ?? "0.1",
    composition_basis: opts?.composition_basis ?? "static",
    surfaces,
  };
}

function baseReceipt(opts?: {
  manifestExt?: Record<string, unknown>;
  enforcementSurface?: string;
  eventType?: string;
  constitutionRef?: Record<string, unknown> | null;
  contentMode?: string;
}): Record<string, unknown> {
  const manifestExt = opts?.manifestExt ?? baseManifestExt();
  const r: Record<string, unknown> = {
    spec_version: "1.5",
    tool_version: "1.5.0",
    tool_name: "sanna",
    checks_version: "10",
    receipt_id: randomUUID(),
    receipt_fingerprint: HASH_16,
    full_fingerprint: HASH_64,
    correlation_id: "test-001",
    timestamp: "2026-05-02T12:00:00Z",
    inputs: { query: "session_manifest" },
    outputs: { response: "" },
    context_hash: HASH_64,
    output_hash: HASH_64,
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "PASS",
    invariants_scope: "none",
    event_type: opts?.eventType ?? "session_manifest",
    enforcement: null,
    enforcement_surface: opts?.enforcementSurface ?? "gateway",
    extensions: { "com.sanna.manifest": manifestExt },
    constitution_ref: opts?.constitutionRef !== undefined
      ? opts.constitutionRef
      : { policy_hash: POLICY_HASH },
    agent_identity: { agent_session_id: "sess-001" },
  };
  if (opts?.contentMode) {
    r.content_mode = opts.contentMode;
    r.content_mode_source = "local_config";
  }
  return r;
}

function findCheck(checks: Check[], name: string): Check {
  const match = checks.find((c) => c.name === name);
  if (!match) {
    throw new Error(`No check named '${name}' found. Got: ${checks.map((c) => c.name).join(", ")}`);
  }
  return match;
}

// ===========================================================================
// Check 1: manifest_extension_present
// ===========================================================================

describe("Check 1: manifest_extension_present", () => {
  it("PASS when extension is dict", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_extension_present");
    expect(c.status).toBe("PASS");
  });

  it("FAIL when extension absent -- exact message", () => {
    const r = baseReceipt();
    delete (r.extensions as Record<string, unknown>)["com.sanna.manifest"];
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_extension_present");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "session_manifest receipt missing required extension 'com.sanna.manifest'"
    );
  });

  it("FAIL when extensions key missing -- exact message", () => {
    const r = baseReceipt();
    delete r.extensions;
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_extension_present");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "session_manifest receipt missing required extension 'com.sanna.manifest'"
    );
  });

  it("FAIL when extension is not a dict", () => {
    const r = baseReceipt();
    (r.extensions as Record<string, unknown>)["com.sanna.manifest"] = "not-a-dict";
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_extension_present");
    expect(c.status).toBe("FAIL");
  });
});

// ===========================================================================
// Check 2: manifest_version_supported
// ===========================================================================

describe("Check 2: manifest_version_supported", () => {
  it("PASS on 0.1", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_version_supported");
    expect(c.status).toBe("PASS");
  });

  it("FAIL on unknown version -- exact message", () => {
    const r = baseReceipt({ manifestExt: baseManifestExt({ version: "9.9" }) });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_version_supported");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("manifest version '9.9' not in supported set {'0.1'}");
  });

  it("FAIL on missing version -- exact message matches Python 'None'", () => {
    const ext = baseManifestExt();
    delete ext.version;
    const r = baseReceipt({ manifestExt: ext });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_version_supported");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("manifest version 'None' not in supported set {'0.1'}");
  });
});

// ===========================================================================
// Check 3: manifest_has_at_least_one_surface
// ===========================================================================

describe("Check 3: manifest_has_at_least_one_surface", () => {
  it("PASS with mcp surface", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_has_at_least_one_surface");
    expect(c.status).toBe("PASS");
  });

  it("FAIL on empty surfaces -- exact message", () => {
    const r = baseReceipt({ manifestExt: baseManifestExt({ surfaces: {} }) });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_has_at_least_one_surface");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("manifest 'surfaces' must contain at least one of {'mcp', 'cli', 'http'}");
  });

  it("FAIL on missing surfaces key", () => {
    const ext = baseManifestExt();
    delete ext.surfaces;
    const r = baseReceipt({ manifestExt: ext });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_has_at_least_one_surface");
    expect(c.status).toBe("FAIL");
  });
});

// ===========================================================================
// Check 4: manifest_lists_sorted
// ===========================================================================

describe("Check 4: manifest_lists_sorted", () => {
  it("PASS when sorted", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_lists_sorted");
    expect(c.status).toBe("PASS");
  });

  it("FAIL when delivered unsorted -- exact message", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["z_tool", "a_tool"],
            tools_suppressed: [],
            suppression_reasons: {},
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_lists_sorted");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "manifest surface 'mcp' field 'tools_delivered' is not sorted alphabetically (determinism violated)"
    );
  });

  it("FAIL when suppressed unsorted -- message includes tools_suppressed", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["a_tool"],
            tools_suppressed: ["z_suppress", "a_suppress"],
            suppression_reasons: { z_suppress: "cannot_execute", a_suppress: "policy_denied" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_lists_sorted");
    expect(c.status).toBe("FAIL");
    expect(c.message).toContain("tools_suppressed");
  });

  it("PASS for cli patterns already sorted", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          cli: {
            patterns_delivered: ["git", "ls"],
            patterns_suppressed: ["rm"],
            suppression_reasons: { rm: "cannot_execute" },
            mode: "strict",
          },
        },
      }),
      enforcementSurface: "cli_interceptor",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_lists_sorted");
    expect(c.status).toBe("PASS");
  });
});

// ===========================================================================
// Check 5: manifest_suppression_reasons_in_enum
// ===========================================================================

describe("Check 5: manifest_suppression_reasons_in_enum", () => {
  it("PASS on valid reasons", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_in_enum");
    expect(c.status).toBe("PASS");
  });

  it("FAIL on invalid reason -- exact message", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: [],
            tools_suppressed: ["bad_tool"],
            suppression_reasons: { bad_tool: "not_a_real_reason" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_in_enum");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "manifest surface 'mcp' suppression_reason 'not_a_real_reason' not in stable enum (Section 2.21)"
    );
  });

  it("WARN on 'unknown' reason -- exact message", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: [],
            tools_suppressed: ["some_tool"],
            suppression_reasons: { some_tool: "unknown" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_in_enum");
    expect(c.status).toBe("WARN");
    expect(c.message).toBe(
      "manifest surface 'mcp' uses 'unknown' suppression_reason (documented fallback per Section 2.21)"
    );
  });

  it("PASS when suppression_reasons absent (redacted mode)", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["<redacted>"],
            tools_suppressed: ["<redacted>"],
            aggregate_suppression_reasons: ["cannot_execute"],
          },
        },
      }),
      contentMode: "redacted",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_in_enum");
    expect(c.status).toBe("PASS");
  });
});

// ===========================================================================
// Check 6: manifest_no_overlap_delivered_suppressed
// ===========================================================================

describe("Check 6: manifest_no_overlap_delivered_suppressed", () => {
  it("PASS when disjoint", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_no_overlap_delivered_suppressed");
    expect(c.status).toBe("PASS");
  });

  it("FAIL when overlap -- exact message", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["shared_tool"],
            tools_suppressed: ["shared_tool"],
            suppression_reasons: { shared_tool: "cannot_execute" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_no_overlap_delivered_suppressed");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "manifest surface 'mcp' has 'shared_tool' in BOTH delivered and suppressed (anti-enumeration integrity violated)"
    );
  });

  it("PASS (skip overlap check) in redacted mode", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["<redacted>"],
            tools_suppressed: ["<redacted>"],
            aggregate_suppression_reasons: ["cannot_execute"],
          },
        },
      }),
      contentMode: "redacted",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_no_overlap_delivered_suppressed");
    expect(c.status).toBe("PASS");
  });
});

// ===========================================================================
// Check 7: manifest_suppression_reasons_keys_match
// ===========================================================================

describe("Check 7: manifest_suppression_reasons_keys_match", () => {
  it("PASS when keys match", () => {
    const r = baseReceipt();
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_keys_match");
    expect(c.status).toBe("PASS");
  });

  it("FAIL when extra key -- exact message format", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: [],
            tools_suppressed: ["beta"],
            suppression_reasons: { alpha: "cannot_execute" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_keys_match");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "manifest surface 'mcp' suppression_reasons keys ['alpha'] do not match suppressed names ['beta']"
    );
  });

  it("FAIL when missing key -- message contains tool_b", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: [],
            tools_suppressed: ["tool_a", "tool_b"],
            suppression_reasons: { tool_a: "cannot_execute" },
          },
        },
      }),
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_suppression_reasons_keys_match");
    expect(c.status).toBe("FAIL");
    expect(c.message).toContain("tool_b");
  });
});

// ===========================================================================
// Check 8: manifest_constitution_ref_present
// ===========================================================================

describe("Check 8: manifest_constitution_ref_present", () => {
  it("PASS when policy_hash present", () => {
    const r = baseReceipt({ constitutionRef: { policy_hash: POLICY_HASH } });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_constitution_ref_present");
    expect(c.status).toBe("PASS");
  });

  it("FAIL when constitution_ref absent -- exact message", () => {
    const r = baseReceipt();
    delete r.constitution_ref;
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_constitution_ref_present");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "session_manifest receipt requires constitution_ref.policy_hash (manifest is meaningless without constitution binding)"
    );
  });

  it("FAIL when policy_hash empty", () => {
    const r = baseReceipt({ constitutionRef: { policy_hash: "" } });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_constitution_ref_present");
    expect(c.status).toBe("FAIL");
  });

  it("FAIL when constitution_ref is null", () => {
    const r = baseReceipt({ constitutionRef: null });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_constitution_ref_present");
    expect(c.status).toBe("FAIL");
  });
});

// ===========================================================================
// Check 9: manifest_enforcement_surface_consistent
// ===========================================================================

describe("Check 9: manifest_enforcement_surface_consistent", () => {
  it("PASS gateway with mcp", () => {
    const r = baseReceipt({ enforcementSurface: "gateway" });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("PASS");
  });

  it("FAIL invalid enforcement_surface -- exact message", () => {
    const r = baseReceipt({ enforcementSurface: "middleware" });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "session_manifest enforcement_surface 'middleware' not in valid set {gateway, cli_interceptor, http_interceptor, mixed}"
    );
  });

  it("FAIL gateway missing mcp surface -- exact message", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          cli: {
            patterns_delivered: [],
            patterns_suppressed: [],
            suppression_reasons: {},
            mode: "strict",
          },
        },
      }),
      enforcementSurface: "gateway",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("session_manifest with enforcement_surface='gateway' missing 'mcp' surface");
  });

  it("FAIL mixed needs two surfaces -- exact message", () => {
    const r = baseReceipt({ enforcementSurface: "mixed" });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "session_manifest with enforcement_surface='mixed' requires surfaces dict with at least 2 entries; got 1"
    );
  });

  it("PASS mixed with two surfaces", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: { tools_delivered: [], tools_suppressed: [], suppression_reasons: {} },
          cli: { patterns_delivered: [], patterns_suppressed: [], suppression_reasons: {}, mode: "strict" },
        },
      }),
      enforcementSurface: "mixed",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("PASS");
  });

  it("FAIL cli_interceptor missing cli surface -- exact message", () => {
    const r = baseReceipt({ enforcementSurface: "cli_interceptor" });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("session_manifest with enforcement_surface='cli_interceptor' missing 'cli' surface");
  });

  it("FAIL http_interceptor missing http surface -- exact message", () => {
    const r = baseReceipt({ enforcementSurface: "http_interceptor" });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("session_manifest with enforcement_surface='http_interceptor' missing 'http' surface");
  });

  it("PASS cli_interceptor with cli surface", () => {
    const r = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          cli: { patterns_delivered: [], patterns_suppressed: [], suppression_reasons: {}, mode: "strict" },
        },
      }),
      enforcementSurface: "cli_interceptor",
    });
    const c = findCheck(verifySessionManifestReceipt(r), "manifest_enforcement_surface_consistent");
    expect(c.status).toBe("PASS");
  });
});

// ===========================================================================
// Production-shape manifest: zero FAIL checks
// ===========================================================================

describe("Production-shape session_manifest produces zero FAIL checks", () => {
  it("all 9 checks PASS for well-formed gateway manifest", () => {
    const r = baseReceipt();
    const checks = verifySessionManifestReceipt(r);
    expect(checks).toHaveLength(9);
    const fails = checks.filter((c) => c.status === "FAIL");
    expect(fails).toHaveLength(0);
  });
});

// ===========================================================================
// Check 10: anomaly_event_type_in_valid_set
// ===========================================================================

function baseAnomalyReceipt(opts?: {
  eventType?: string;
  parentReceipts?: string[];
  attemptedTool?: string;
}): Record<string, unknown> {
  const eventType = opts?.eventType ?? "invocation_anomaly";
  const attemptedTool = opts?.attemptedTool ?? "delete_all";
  const parentReceipts = opts?.parentReceipts !== undefined ? opts.parentReceipts : [HASH_64];
  return {
    spec_version: "1.5",
    tool_version: "1.5.0",
    tool_name: "sanna",
    checks_version: "10",
    receipt_id: randomUUID(),
    receipt_fingerprint: HASH_16,
    full_fingerprint: "d".repeat(64),
    correlation_id: "anomaly-001",
    timestamp: "2026-05-02T12:01:00Z",
    inputs: { query: `tools/call name=${attemptedTool}` },
    outputs: { response: "" },
    context_hash: HASH_64,
    output_hash: HASH_64,
    checks: [],
    checks_passed: 0,
    checks_failed: 0,
    status: "FAIL",
    invariants_scope: "authority_only",
    event_type: eventType,
    enforcement: {
      action: "halted",
      halted: true,
      reason: "tool_suppressed_by_constitution",
      failed_checks: [],
      enforcement_mode: "halt",
      timestamp: "2026-05-02T12:01:00Z",
    },
    enforcement_surface: "gateway",
    extensions: {
      "com.sanna.anomaly": {
        attempted_tool: attemptedTool,
        suppression_basis: "session_manifest",
      },
    },
    parent_receipts: parentReceipts,
    constitution_ref: { policy_hash: POLICY_HASH },
    agent_identity: { agent_session_id: "sess-001" },
  };
}

describe("Check 10: anomaly_event_type_in_valid_set", () => {
  it("PASS for invocation_anomaly", () => {
    const r = baseAnomalyReceipt();
    const c = findCheck(verifyInvocationAnomalyReceipt(r, null), "anomaly_event_type_in_valid_set");
    expect(c.status).toBe("PASS");
  });

  it("PASS for cli_invocation_anomaly", () => {
    const r = baseAnomalyReceipt({ eventType: "cli_invocation_anomaly" });
    (r.extensions as Record<string, unknown>)["com.sanna.anomaly"] = { attempted_command: "rm -rf /" };
    const c = findCheck(verifyInvocationAnomalyReceipt(r, null), "anomaly_event_type_in_valid_set");
    expect(c.status).toBe("PASS");
  });

  it("PASS for api_invocation_anomaly", () => {
    const r = baseAnomalyReceipt({ eventType: "api_invocation_anomaly" });
    (r.extensions as Record<string, unknown>)["com.sanna.anomaly"] = { attempted_endpoint: "/api/delete" };
    const c = findCheck(verifyInvocationAnomalyReceipt(r, null), "anomaly_event_type_in_valid_set");
    expect(c.status).toBe("PASS");
  });

  it("FAIL for unknown event_type -- exact message", () => {
    const r = baseAnomalyReceipt({ eventType: "bad_event" });
    const c = findCheck(verifyInvocationAnomalyReceipt(r, null), "anomaly_event_type_in_valid_set");
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe("anomaly receipt event_type 'bad_event' not in valid set");
  });
});

// ===========================================================================
// Check 11: anomaly_parent_receipts_resolves_to_session_manifest
// ===========================================================================

describe("Check 11: anomaly_parent_receipts_resolves_to_session_manifest", () => {
  function manifestReceiptFor(fp: string): Record<string, unknown> {
    const r = baseReceipt();
    r.full_fingerprint = fp;
    return r;
  }

  it("WARN in single-receipt mode -- exact message", () => {
    const r = baseAnomalyReceipt();
    const c = findCheck(
      verifyInvocationAnomalyReceipt(r, null),
      "anomaly_parent_receipts_resolves_to_session_manifest"
    );
    expect(c.status).toBe("WARN");
    expect(c.message).toBe("Cross-receipt parent resolution requires receipt set; use verify_receipt_set");
  });

  it("FAIL when parent_receipts empty -- exact message", () => {
    const r = baseAnomalyReceipt({ parentReceipts: [] });
    const manifest = manifestReceiptFor(HASH_64);
    const c = findCheck(
      verifyInvocationAnomalyReceipt(r, [manifest]),
      "anomaly_parent_receipts_resolves_to_session_manifest"
    );
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "anomaly receipt requires non-empty parent_receipts containing the active session_manifest's full_fingerprint (spec Section 2.12)"
    );
  });

  it("FAIL when no matching manifest in set -- message contains substring", () => {
    const r = baseAnomalyReceipt({ parentReceipts: ["aaaa" + "0".repeat(60)] });
    const manifest = manifestReceiptFor(HASH_64);
    const c = findCheck(
      verifyInvocationAnomalyReceipt(r, [manifest]),
      "anomaly_parent_receipts_resolves_to_session_manifest"
    );
    expect(c.status).toBe("FAIL");
    expect(c.message).toContain("do not resolve to a session_manifest");
  });

  it("PASS when parent resolves", () => {
    const manifestFp = "e".repeat(64);
    const r = baseAnomalyReceipt({ parentReceipts: [manifestFp] });
    const manifest = manifestReceiptFor(manifestFp);
    const c = findCheck(
      verifyInvocationAnomalyReceipt(r, [manifest, r]),
      "anomaly_parent_receipts_resolves_to_session_manifest"
    );
    expect(c.status).toBe("PASS");
  });
});

// ===========================================================================
// Check 12: anomaly_attempted_capability_in_parent_suppressed_or_absent
// ===========================================================================

describe("Check 12: anomaly_attempted_capability_in_parent_suppressed_or_absent", () => {
  const MANIFEST_FP = "f".repeat(64);

  function manifestWithMcp(toolsDelivered: string[], toolsSuppressed: string[]): Record<string, unknown> {
    const surfaces = {
      mcp: {
        tools_delivered: [...toolsDelivered].sort(),
        tools_suppressed: [...toolsSuppressed].sort(),
        suppression_reasons: Object.fromEntries(toolsSuppressed.map((t) => [t, "cannot_execute"])),
      },
    };
    const r = baseReceipt({ manifestExt: baseManifestExt({ surfaces }) });
    r.full_fingerprint = MANIFEST_FP;
    return r;
  }

  function anomalyFor(tool: string): Record<string, unknown> {
    return baseAnomalyReceipt({ parentReceipts: [MANIFEST_FP], attemptedTool: tool });
  }

  it("WARN in single-receipt mode -- exact message", () => {
    const r = baseAnomalyReceipt();
    const c = findCheck(
      verifyInvocationAnomalyReceipt(r, null),
      "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(c.status).toBe("WARN");
    expect(c.message).toBe("Cross-receipt parent resolution requires receipt set; use verify_receipt_set");
  });

  it("PASS when capability in suppressed -- exact message", () => {
    const manifest = manifestWithMcp(["read_data"], ["delete_all"]);
    const anomaly = anomalyFor("delete_all");
    const c = findCheck(
      verifyInvocationAnomalyReceipt(anomaly, [manifest, anomaly]),
      "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(c.status).toBe("PASS");
    expect(c.message).toBe(
      "anomaly capability 'delete_all' was suppressed in parent session_manifest (spec-conformant anti-enumeration signal)"
    );
  });

  it("FAIL when capability in delivered -- exact message", () => {
    const manifest = manifestWithMcp(["read_data"], []);
    const anomaly = anomalyFor("read_data");
    const c = findCheck(
      verifyInvocationAnomalyReceipt(anomaly, [manifest, anomaly]),
      "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(c.status).toBe("FAIL");
    expect(c.message).toBe(
      "anomaly receipt for capability 'read_data' that parent session_manifest declares as DELIVERED -- inconsistent receipt set"
    );
  });

  it("PASS informational when capability absent -- message contains substring", () => {
    const manifest = manifestWithMcp(["read_data"], ["delete_all"]);
    const anomaly = anomalyFor("completely_unknown_tool");
    const c = findCheck(
      verifyInvocationAnomalyReceipt(anomaly, [manifest, anomaly]),
      "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(c.status).toBe("PASS");
    expect(c.message).toContain("was not declared in constitution at all");
  });
});

// ===========================================================================
// verifyReceiptSet: cross-receipt parent resolution
// ===========================================================================

describe("verifyReceiptSet", () => {
  const MANIFEST_FP = "f".repeat(64);

  it("resolves cross-receipt checks: suppressed capability -> PASS", () => {
    const manifest = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["read_data"],
            tools_suppressed: ["delete_all"],
            suppression_reasons: { delete_all: "cannot_execute" },
          },
        },
      }),
    });
    manifest.full_fingerprint = MANIFEST_FP;

    const anomaly = baseAnomalyReceipt({ parentReceipts: [MANIFEST_FP], attemptedTool: "delete_all" });

    const manifestId = String(manifest.receipt_id);
    const anomalyId = String(anomaly.receipt_id);

    const results = verifyReceiptSet([manifest, anomaly]);
    expect(results[manifestId]).toBeDefined();
    expect(results[anomalyId]).toBeDefined();

    const anomalyResult = results[anomalyId];
    const check12 = anomalyResult.checks?.find(
      (c) => c.name === "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(check12?.status).toBe("PASS");
  });

  it("resolves cross-receipt checks: delivered capability -> FAIL", () => {
    const manifest = baseReceipt({
      manifestExt: baseManifestExt({
        surfaces: {
          mcp: {
            tools_delivered: ["read_data"],
            tools_suppressed: [],
            suppression_reasons: {},
          },
        },
      }),
    });
    manifest.full_fingerprint = MANIFEST_FP;

    const anomaly = baseAnomalyReceipt({ parentReceipts: [MANIFEST_FP], attemptedTool: "read_data" });

    const anomalyId = String(anomaly.receipt_id);
    const results = verifyReceiptSet([manifest, anomaly]);
    const anomalyResult = results[anomalyId];

    const check12 = anomalyResult.checks?.find(
      (c) => c.name === "anomaly_attempted_capability_in_parent_suppressed_or_absent"
    );
    expect(check12?.status).toBe("FAIL");
    expect(anomalyResult.valid).toBe(false);
  });

  it("replaces single-receipt WARN with cross-receipt result", () => {
    const manifest = baseReceipt();
    manifest.full_fingerprint = MANIFEST_FP;

    const anomaly = baseAnomalyReceipt({ parentReceipts: [MANIFEST_FP] });
    const anomalyId = String(anomaly.receipt_id);

    const results = verifyReceiptSet([manifest, anomaly]);
    const anomalyResult = results[anomalyId];

    const warnMsgs = anomalyResult.warnings.filter(
      (w) => w === "Cross-receipt parent resolution requires receipt set; use verify_receipt_set"
    );
    expect(warnMsgs).toHaveLength(0);
  });
});
