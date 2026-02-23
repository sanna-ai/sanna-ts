import { describe, it, expect } from "vitest";
import {
  loadInvariantChecks,
  runInvariantCheck,
  runAllInvariantChecks,
} from "../src/invariants.js";
import type { Constitution, InvariantDefinition } from "../src/types.js";

function makeConstitution(invariants: Constitution["invariants"]): Constitution {
  return {
    schema_version: "1.0.0",
    identity: {
      agent_name: "test-agent",
      domain: "testing",
      description: "Test agent",
      extensions: {},
    },
    provenance: {
      authored_by: "test@sanna.dev",
      approved_by: ["test@sanna.dev"],
      approval_date: "2026-02-22",
      approval_method: "test",
      change_history: [],
      signature: null,
    },
    boundaries: [
      { id: "B001", description: "Test boundary", category: "scope", severity: "medium" },
    ],
    trust_tiers: { autonomous: [], requires_approval: [], prohibited: [] },
    halt_conditions: [],
    invariants,
    policy_hash: null,
    authority_boundaries: null,
    trusted_sources: null,
  };
}

describe("loadInvariantChecks", () => {
  it("should detect pii_detection type from rule text", () => {
    const constitution = makeConstitution([
      { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs).toHaveLength(1);
    expect(defs[0].type).toBe("pii_detection");
  });

  it("should detect max_length type from rule text", () => {
    const constitution = makeConstitution([
      { id: "INV_LEN", rule: "Maximum 500 characters per response", enforcement: "warn", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBe("max_length");
    expect(defs[0].maxLength).toBe(500);
  });

  it("should detect regex_match type from rule text", () => {
    const constitution = makeConstitution([
      { id: "INV_REGEX", rule: "Output must match /^\\d{4}-\\d{2}$/", enforcement: "warn", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBe("regex_match");
    expect(defs[0].pattern).toBe("^\\d{4}-\\d{2}$");
  });

  it("should detect regex_deny type from rule text", () => {
    const constitution = makeConstitution([
      { id: "INV_DENY", rule: "Must not match /password:\\s*.+/", enforcement: "halt", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBe("regex_deny");
    expect(defs[0].pattern).toBe("password:\\s*.+");
  });

  it("should detect required_keywords type from rule text", () => {
    const constitution = makeConstitution([
      { id: "INV_KW", rule: "Output must contain 'disclaimer', 'terms'", enforcement: "warn", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBe("required_keywords");
    expect(defs[0].keywords).toEqual(["disclaimer", "terms"]);
  });

  it("should skip type detection for invariants with explicit check field", () => {
    const constitution = makeConstitution([
      { id: "INV_CUSTOM", rule: "No PII in output", enforcement: "halt", check: "sanna.context_contradiction" },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBeUndefined();
  });

  it("should return undefined type for undetectable rules", () => {
    const constitution = makeConstitution([
      { id: "INV_UNKNOWN", rule: "No fabrication", enforcement: "halt", check: null },
    ]);
    const defs = loadInvariantChecks(constitution);
    expect(defs[0].type).toBeUndefined();
  });
});

describe("runInvariantCheck", () => {
  describe("regex_match", () => {
    it("should pass when output matches pattern", () => {
      const inv: InvariantDefinition = {
        id: "INV_DATE", rule: "Must match date pattern", enforcement: "warn",
        type: "regex_match", pattern: "^\\d{4}-\\d{2}-\\d{2}$",
      };
      const result = runInvariantCheck(inv, "2026-02-22");
      expect(result.passed).toBe(true);
    });

    it("should fail when output doesn't match pattern", () => {
      const inv: InvariantDefinition = {
        id: "INV_DATE", rule: "Must match date pattern", enforcement: "warn",
        type: "regex_match", pattern: "^\\d{4}-\\d{2}-\\d{2}$",
      };
      const result = runInvariantCheck(inv, "not a date");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("does not match");
    });

    it("should return NOT_CHECKED when no pattern specified", () => {
      const inv: InvariantDefinition = {
        id: "INV_NO_PAT", rule: "Must match something", enforcement: "warn",
        type: "regex_match",
      };
      const result = runInvariantCheck(inv, "test");
      expect(result.status).toBe("NOT_CHECKED");
    });
  });

  describe("regex_deny", () => {
    it("should pass when output doesn't match forbidden pattern", () => {
      const inv: InvariantDefinition = {
        id: "INV_NO_SECRET", rule: "No secrets", enforcement: "halt",
        type: "regex_deny", pattern: "password:\\s*.+",
      };
      const result = runInvariantCheck(inv, "The system is working fine.");
      expect(result.passed).toBe(true);
    });

    it("should fail when output matches forbidden pattern", () => {
      const inv: InvariantDefinition = {
        id: "INV_NO_SECRET", rule: "No secrets", enforcement: "halt",
        type: "regex_deny", pattern: "password:\\s*.+",
      };
      const result = runInvariantCheck(inv, "The password: hunter2 is stored here.");
      expect(result.passed).toBe(false);
      expect(result.severity).toBe("critical");
      expect(result.evidence).toContain("forbidden pattern");
    });
  });

  describe("max_length", () => {
    it("should pass when output is within limit", () => {
      const inv: InvariantDefinition = {
        id: "INV_LEN", rule: "Max 100 characters", enforcement: "warn",
        type: "max_length", maxLength: 100,
      };
      const result = runInvariantCheck(inv, "Short text.");
      expect(result.passed).toBe(true);
    });

    it("should fail when output exceeds limit", () => {
      const inv: InvariantDefinition = {
        id: "INV_LEN", rule: "Max 10 characters", enforcement: "warn",
        type: "max_length", maxLength: 10,
      };
      const result = runInvariantCheck(inv, "This is definitely more than ten characters.");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("exceeds");
    });
  });

  describe("required_keywords", () => {
    it("should pass when all keywords present", () => {
      const inv: InvariantDefinition = {
        id: "INV_KW", rule: "Must contain keywords", enforcement: "warn",
        type: "required_keywords", keywords: ["disclaimer", "terms"],
      };
      const result = runInvariantCheck(inv, "Please read the disclaimer and terms of service.");
      expect(result.passed).toBe(true);
    });

    it("should fail when keywords are missing", () => {
      const inv: InvariantDefinition = {
        id: "INV_KW", rule: "Must contain keywords", enforcement: "warn",
        type: "required_keywords", keywords: ["disclaimer", "terms"],
      };
      const result = runInvariantCheck(inv, "Here is the information you requested.");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("disclaimer");
      expect(result.evidence).toContain("terms");
    });

    it("should be case-insensitive", () => {
      const inv: InvariantDefinition = {
        id: "INV_KW", rule: "Must contain keywords", enforcement: "warn",
        type: "required_keywords", keywords: ["Disclaimer"],
      };
      const result = runInvariantCheck(inv, "See the DISCLAIMER section.");
      expect(result.passed).toBe(true);
    });
  });

  describe("pii_detection", () => {
    it("should pass when no PII found", () => {
      const inv: InvariantDefinition = {
        id: "INV_PII", rule: "No PII", enforcement: "halt",
        type: "pii_detection",
      };
      const result = runInvariantCheck(inv, "The system is operational and running smoothly.");
      expect(result.passed).toBe(true);
    });

    it("should detect email addresses", () => {
      const inv: InvariantDefinition = {
        id: "INV_PII", rule: "No PII", enforcement: "halt",
        type: "pii_detection",
      };
      const result = runInvariantCheck(inv, "Contact john@example.com for details.");
      expect(result.passed).toBe(false);
      expect(result.severity).toBe("critical");
      expect(result.evidence).toContain("email");
    });

    it("should detect phone numbers", () => {
      const inv: InvariantDefinition = {
        id: "INV_PII", rule: "No PII", enforcement: "halt",
        type: "pii_detection",
      };
      const result = runInvariantCheck(inv, "Call (555) 123-4567 for support.");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("phone");
    });

    it("should detect SSN patterns", () => {
      const inv: InvariantDefinition = {
        id: "INV_PII", rule: "No PII", enforcement: "halt",
        type: "pii_detection",
      };
      const result = runInvariantCheck(inv, "SSN: 123-45-6789 on file.");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("SSN");
    });

    it("should detect multiple PII types", () => {
      const inv: InvariantDefinition = {
        id: "INV_PII", rule: "No PII", enforcement: "halt",
        type: "pii_detection",
      };
      const result = runInvariantCheck(inv, "Email: test@example.com, Phone: 555-123-4567");
      expect(result.passed).toBe(false);
      expect(result.evidence).toContain("email");
      expect(result.evidence).toContain("phone");
    });
  });

  describe("safe regex validation", () => {
    it("should reject a known ReDoS pattern like (a+)+", () => {
      const inv: InvariantDefinition = {
        id: "INV_REDOS", rule: "Must match pattern", enforcement: "warn",
        type: "regex_match", pattern: "(a+)+",
      };
      const result = runInvariantCheck(inv, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab");
      expect(result.passed).toBe(true); // fail-open
      expect(result.status).toBe("UNSAFE_PATTERN");
      expect(result.evidence).toContain("safe-regex2");
    });

    it("should reject a ReDoS pattern in regex_deny", () => {
      const inv: InvariantDefinition = {
        id: "INV_REDOS_DENY", rule: "Deny pattern", enforcement: "halt",
        type: "regex_deny", pattern: "(a+)+",
      };
      const result = runInvariantCheck(inv, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab");
      expect(result.passed).toBe(true); // fail-open
      expect(result.status).toBe("UNSAFE_PATTERN");
    });

    it("should allow a normal safe pattern to execute", () => {
      const inv: InvariantDefinition = {
        id: "INV_SAFE", rule: "Must match date", enforcement: "warn",
        type: "regex_match", pattern: "^\\d{4}-\\d{2}-\\d{2}$",
      };
      const result = runInvariantCheck(inv, "2026-02-22");
      expect(result.passed).toBe(true);
      expect(result.status).toBeUndefined();
    });
  });

  describe("unknown type", () => {
    it("should return NOT_CHECKED for unknown invariant type", () => {
      const inv: InvariantDefinition = {
        id: "INV_CUSTOM", rule: "Custom rule", enforcement: "warn",
        type: "custom_type",
      };
      const result = runInvariantCheck(inv, "test output");
      expect(result.status).toBe("NOT_CHECKED");
      expect(result.passed).toBe(true);
    });

    it("should return NOT_CHECKED when no type detected", () => {
      const inv: InvariantDefinition = {
        id: "INV_CUSTOM", rule: "Custom rule", enforcement: "warn",
      };
      const result = runInvariantCheck(inv, "test output");
      expect(result.status).toBe("NOT_CHECKED");
    });
  });
});

describe("runAllInvariantChecks", () => {
  it("should run all invariants from a constitution", () => {
    const constitution = makeConstitution([
      { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      { id: "INV_LEN", rule: "Maximum 500 characters per response", enforcement: "warn", check: null },
      { id: "INV_CUSTOM", rule: "Custom rule with no detection", enforcement: "log", check: null },
    ]);
    const results = runAllInvariantChecks(constitution, "Short clean output.");
    expect(results).toHaveLength(3);
    expect(results[0].check_id).toBe("INV_PII");
    expect(results[0].passed).toBe(true);
    expect(results[1].check_id).toBe("INV_LEN");
    expect(results[1].passed).toBe(true);
    expect(results[2].check_id).toBe("INV_CUSTOM");
    expect(results[2].status).toBe("NOT_CHECKED");
  });

  it("should return empty array for constitution with no invariants", () => {
    const constitution = makeConstitution([]);
    const results = runAllInvariantChecks(constitution, "test");
    expect(results).toHaveLength(0);
  });

  it("should detect failures across multiple invariants", () => {
    const constitution = makeConstitution([
      { id: "INV_PII", rule: "No PII in output", enforcement: "halt", check: null },
      { id: "INV_LEN", rule: "Max 10 characters per response", enforcement: "warn", check: null },
    ]);
    const results = runAllInvariantChecks(constitution, "Contact user@example.com for help with the long response.");
    const pii = results.find((r) => r.check_id === "INV_PII")!;
    const len = results.find((r) => r.check_id === "INV_LEN")!;
    expect(pii.passed).toBe(false);
    expect(len.passed).toBe(false);
  });
});
