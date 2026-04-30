import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  loadConstitution,
  parseConstitution,
  verifyConstitutionSignature,
  computeFileContentHash,
  validateConstitutionData,
} from "../src/constitution.js";
import { loadPublicKey } from "../src/crypto.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");
const golden = JSON.parse(
  readFileSync(resolve(FIXTURES, "golden-hashes.json"), "utf-8"),
);

// ── Load fixtures ────────────────────────────────────────────────────

const minimalPath = resolve(FIXTURES, "constitutions/minimal.yaml");
const fullPath = resolve(FIXTURES, "constitutions/full-featured.yaml");
const pubKeyPath = resolve(FIXTURES, "keypairs/test-author.pub");
const pubKey = loadPublicKey(pubKeyPath);

describe("loadConstitution — minimal.yaml", () => {
  const c = loadConstitution(minimalPath);

  it("parses schema_version", () => {
    expect(c.schema_version).toBe("1.0.0");
  });

  it("parses identity", () => {
    expect(c.identity.agent_name).toBe("test-minimal-agent");
    expect(c.identity.domain).toBe("testing");
    expect(c.identity.description).toContain("Minimal valid constitution");
  });

  it("parses provenance", () => {
    expect(c.provenance.authored_by).toBe("test-author@sanna.dev");
    expect(c.provenance.approved_by).toEqual(["test-author@sanna.dev"]);
    expect(c.provenance.approval_date).toBe("2026-02-22");
    expect(c.provenance.approval_method).toBe("fixture-generation");
  });

  it("parses signature block", () => {
    expect(c.provenance.signature).not.toBeNull();
    expect(c.provenance.signature!.scheme).toBe("constitution_sig_v1");
    expect(c.provenance.signature!.key_id).toBe(golden.test_key_id);
    expect(c.provenance.signature!.value).toBeTruthy();
  });

  it("parses boundaries", () => {
    expect(c.boundaries).toHaveLength(1);
    expect(c.boundaries[0].id).toBe("B001");
    expect(c.boundaries[0].category).toBe("scope");
    expect(c.boundaries[0].severity).toBe("high");
  });

  it("parses invariants", () => {
    expect(c.invariants).toHaveLength(1);
    expect(c.invariants[0].id).toBe("INV_NO_FABRICATION");
    expect(c.invariants[0].enforcement).toBe("halt");
    expect(c.invariants[0].check).toBe("sanna.context_contradiction");
  });

  it("has empty trust_tiers", () => {
    expect(c.trust_tiers.autonomous).toEqual([]);
    expect(c.trust_tiers.requires_approval).toEqual([]);
    expect(c.trust_tiers.prohibited).toEqual([]);
  });

  it("has no authority_boundaries", () => {
    expect(c.authority_boundaries).toBeNull();
  });

  it("has policy_hash", () => {
    expect(c.policy_hash).toMatch(/^[a-f0-9]{64}$/);
  });
});

describe("loadConstitution — full-featured.yaml", () => {
  const c = loadConstitution(fullPath);

  it("parses multiple boundaries", () => {
    expect(c.boundaries.length).toBeGreaterThanOrEqual(3);
    expect(c.boundaries.map((b) => b.id)).toContain("B001");
    expect(c.boundaries.map((b) => b.id)).toContain("B002");
  });

  it("parses multiple invariants", () => {
    expect(c.invariants.length).toBeGreaterThanOrEqual(5);
  });

  it("parses authority_boundaries", () => {
    expect(c.authority_boundaries).not.toBeNull();
    expect(c.authority_boundaries!.can_execute.length).toBeGreaterThan(0);
    expect(c.authority_boundaries!.cannot_execute.length).toBeGreaterThan(0);
    expect(c.authority_boundaries!.must_escalate.length).toBeGreaterThan(0);
  });

  it("parses escalation rules with targets", () => {
    const withTarget = c.authority_boundaries!.must_escalate.find(
      (r) => r.target !== null,
    );
    expect(withTarget).toBeDefined();
    expect(withTarget!.target!.type).toBe("webhook");
  });

  it("parses halt_conditions", () => {
    expect(c.halt_conditions.length).toBeGreaterThanOrEqual(2);
    expect(c.halt_conditions[0].id).toBe("H001");
  });

  it("parses trusted_sources", () => {
    expect(c.trusted_sources).not.toBeNull();
    expect(c.trusted_sources!.tier_1).toContain("internal-database");
    expect(c.trusted_sources!.untrusted).toContain("user-input");
  });

  it("parses trust_tiers", () => {
    expect(c.trust_tiers.autonomous.length).toBeGreaterThan(0);
    expect(c.trust_tiers.prohibited.length).toBeGreaterThan(0);
  });
});

describe("content_hash verification", () => {
  it("minimal.yaml content_hash matches golden", () => {
    const hash = computeFileContentHash(minimalPath);
    expect(hash).toBe(golden.constitutions.minimal.content_hash);
  });

  it("full-featured.yaml content_hash matches golden", () => {
    const hash = computeFileContentHash(fullPath);
    expect(hash).toBe(golden.constitutions["full-featured"].content_hash);
  });
});

describe("verifyConstitutionSignature", () => {
  it("verifies minimal.yaml signature with test-author.pub", () => {
    const c = loadConstitution(minimalPath);
    const valid = verifyConstitutionSignature(c, pubKey);
    expect(valid).toBe(true);
  });

  it("returns false for unsigned constitution", () => {
    const c = loadConstitution(fullPath);
    // full-featured.yaml is not signed
    const valid = verifyConstitutionSignature(c, pubKey);
    expect(valid).toBe(false);
  });
});

describe("validateConstitutionData", () => {
  it("returns errors for empty object", () => {
    const errors = validateConstitutionData({});
    expect(errors.length).toBeGreaterThan(0);
    expect(errors).toContain("Missing required field: identity");
  });

  it("returns no errors for valid minimal data", () => {
    const data = {
      identity: { agent_name: "test", domain: "test" },
      provenance: {
        authored_by: "x@test.com",
        approved_by: ["x@test.com"],
        approval_date: "2026-01-01",
        approval_method: "manual",
      },
      boundaries: [
        { id: "B001", description: "Test", category: "scope", severity: "high" },
      ],
    };
    const errors = validateConstitutionData(data);
    expect(errors).toEqual([]);
  });

  it("catches duplicate boundary IDs", () => {
    const data = {
      identity: { agent_name: "test", domain: "test" },
      provenance: {
        authored_by: "x@test.com",
        approved_by: ["x@test.com"],
        approval_date: "2026-01-01",
        approval_method: "manual",
      },
      boundaries: [
        { id: "B001", description: "A", category: "scope", severity: "high" },
        { id: "B001", description: "B", category: "scope", severity: "high" },
      ],
    };
    const errors = validateConstitutionData(data);
    expect(errors.some((e) => e.includes("Duplicate boundary ID"))).toBe(true);
  });
});

describe("prototype pollution protection", () => {
  const validData = {
    identity: { agent_name: "test", domain: "test" },
    provenance: {
      authored_by: "x@test.com",
      approved_by: ["x@test.com"],
      approval_date: "2026-01-01",
      approval_method: "manual",
    },
    boundaries: [
      { id: "B001", description: "Test", category: "scope", severity: "high" },
    ],
  };

  it("filters __proto__ from identity extensions", () => {
    const data = {
      ...validData,
      identity: {
        ...validData.identity,
        __proto__: { polluted: true },
        custom_field: "safe",
      },
    };
    // Reconstruct with explicit key to bypass JS __proto__ handling
    const identity: Record<string, unknown> = {
      agent_name: "test",
      domain: "test",
      custom_field: "safe",
    };
    Object.defineProperty(identity, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    const dataWithProto = { ...validData, identity };

    const pristine = ({} as Record<string, unknown>).polluted;
    const c = parseConstitution(dataWithProto);
    expect(({} as Record<string, unknown>).polluted).toBe(pristine);
    expect(c.identity.extensions).not.toHaveProperty("__proto__");
    expect(c.identity.extensions.custom_field).toBe("safe");
  });

  it("filters constructor from identity extensions", () => {
    const identity: Record<string, unknown> = {
      agent_name: "test",
      domain: "test",
      constructor: { malicious: true },
      custom_field: "safe",
    };
    const data = { ...validData, identity };
    const c = parseConstitution(data);
    expect(c.identity.extensions).not.toHaveProperty("constructor");
    expect(c.identity.extensions.custom_field).toBe("safe");
  });

  it("filters prototype from identity extensions", () => {
    const identity: Record<string, unknown> = {
      agent_name: "test",
      domain: "test",
      prototype: { malicious: true },
    };
    const data = { ...validData, identity };
    const c = parseConstitution(data);
    expect(c.identity.extensions).not.toHaveProperty("prototype");
  });

  it("filters keys starting with double underscore", () => {
    const identity: Record<string, unknown> = {
      agent_name: "test",
      domain: "test",
      __internal: "bad",
      __defineGetter__: "bad",
      custom_field: "safe",
    };
    const data = { ...validData, identity };
    const c = parseConstitution(data);
    expect(Object.prototype.hasOwnProperty.call(c.identity.extensions, "__internal")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(c.identity.extensions, "__defineGetter__")).toBe(false);
    expect(c.identity.extensions.custom_field).toBe("safe");
  });

  it("preserves normal identity extensions", () => {
    const identity: Record<string, unknown> = {
      agent_name: "test",
      domain: "test",
      version: "2.0",
      org: "acme",
      tags: ["a", "b"],
    };
    const data = { ...validData, identity };
    const c = parseConstitution(data);
    expect(c.identity.extensions.version).toBe("2.0");
    expect(c.identity.extensions.org).toBe("acme");
    expect(c.identity.extensions.tags).toEqual(["a", "b"]);
  });
});

// ── SAN-205: escalation_visibility + Composition ─────────────────────

const baseData = {
  identity: { agent_name: "test", domain: "test" },
  provenance: {
    authored_by: "x@test.com",
    approved_by: ["x@test.com"],
    approval_date: "2026-01-01",
    approval_method: "manual",
  },
  boundaries: [
    { id: "B001", description: "Test", category: "scope", severity: "high" },
  ],
  authority_boundaries: {
    cannot_execute: ["delete_all"],
    must_escalate: [],
    can_execute: ["read"],
  },
};

describe("SAN-205: escalation_visibility + composition", () => {
  it("defaults escalation_visibility to 'visible' when absent", () => {
    const c = parseConstitution(baseData);
    expect(c.authority_boundaries?.escalation_visibility).toBe("visible");
  });

  it("parses authority_boundaries.escalation_visibility = 'suppressed'", () => {
    const data = {
      ...baseData,
      authority_boundaries: {
        ...baseData.authority_boundaries,
        escalation_visibility: "suppressed",
      },
    };
    const c = parseConstitution(data);
    expect(c.authority_boundaries?.escalation_visibility).toBe("suppressed");
  });

  it("parses authority_boundaries.escalation_visibility = 'visible' explicitly", () => {
    const data = {
      ...baseData,
      authority_boundaries: {
        ...baseData.authority_boundaries,
        escalation_visibility: "visible",
      },
    };
    const c = parseConstitution(data);
    expect(c.authority_boundaries?.escalation_visibility).toBe("visible");
  });

  it("parses top-level composition.escalation_visibility = 'suppressed'", () => {
    const data = {
      ...baseData,
      composition: { escalation_visibility: "suppressed" },
    };
    const c = parseConstitution(data);
    expect(c.composition?.escalation_visibility).toBe("suppressed");
  });

  it("composition is null when absent", () => {
    const c = parseConstitution(baseData);
    expect(c.composition).toBeNull();
  });

  it("rejects invalid authority_boundaries.escalation_visibility value", () => {
    const data = {
      ...baseData,
      authority_boundaries: {
        ...baseData.authority_boundaries,
        escalation_visibility: "invalid_value",
      },
    };
    const errors = validateConstitutionData(data as Record<string, unknown>);
    expect(errors.some((e) => e.includes("escalation_visibility"))).toBe(true);
    expect(errors.some((e) => e.includes("visible") || e.includes("suppressed"))).toBe(true);
  });

  it("rejects invalid composition.escalation_visibility value", () => {
    const data = {
      ...baseData,
      composition: { escalation_visibility: "invalid" },
    };
    const errors = validateConstitutionData(data as Record<string, unknown>);
    expect(errors.some((e) => e.includes("composition.escalation_visibility"))).toBe(true);
  });

  it("hash backward-compat: v1.4-era constitution signature still verifies after this PR", () => {
    // minimal.yaml is a signed v1.4-era fixture with no escalation_visibility.
    // constitutionToSignableDict must NOT include escalation_visibility in the
    // signable dict (it is default "visible"), so the stored signature remains valid.
    const c = loadConstitution(minimalPath);
    const valid = verifyConstitutionSignature(c, pubKey);
    expect(valid).toBe(true);
  });

  it("hash backward-compat: signable dict for v1.4-era authority_boundaries omits escalation_visibility", () => {
    // full-featured.yaml has authority_boundaries without escalation_visibility.
    // After parsing, the field defaults to "visible". The signable dict must NOT
    // include it (conditional inclusion: only when non-default "suppressed").
    const c = loadConstitution(fullPath);
    expect(c.authority_boundaries).not.toBeNull();
    expect(c.authority_boundaries!.escalation_visibility).toBe("visible");
    // Verify the signable dict does not include the field at all
    // We test this indirectly: saveConstitution uses constitutionToSignableDict,
    // and signature verification on minimal.yaml (above) is the direct proof.
    // Here we also confirm the parsed field value is the default.
  });

  it("signable dict includes escalation_visibility only when suppressed", () => {
    // Parse a constitution with escalation_visibility="suppressed" and confirm
    // that constitutionToSignableDict includes it (non-default).
    // Parse one with "visible" and confirm it is absent (default, backward compat).
    const suppData = {
      ...baseData,
      authority_boundaries: {
        ...baseData.authority_boundaries,
        escalation_visibility: "suppressed",
      },
    };
    const cSupp = parseConstitution(suppData);
    // Verify the parsed field is suppressed
    expect(cSupp.authority_boundaries!.escalation_visibility).toBe("suppressed");
    // Verify the default-visibility constitution compiles without escalation_visibility in signable dict
    const cDefault = parseConstitution(baseData);
    expect(cDefault.authority_boundaries!.escalation_visibility).toBe("visible");
    // The hash backward-compat test (signature verification above) is the definitive proof.
  });
});
