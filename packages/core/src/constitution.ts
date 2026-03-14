/**
 * Sanna Protocol — Constitution module
 *
 * Load, parse, validate, and verify constitution YAML documents.
 * See Sanna specification v1.0, Section 6.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import yaml from "js-yaml";
import type { KeyObject } from "node:crypto";

import { canonicalize, hashContent, hashObj } from "./hashing.js";
import { sign, verify, getKeyId } from "./crypto.js";
import type {
  Constitution,
  Boundary,
  HaltCondition,
  TrustTiers,
  TrustedSources,
  Provenance,
  ConstitutionSignature,
  AgentIdentity,
  Invariant,
  AuthorityBoundaries,
  EscalationRule,
  EscalationTargetConfig,
  CliPermissions,
  CliCommand,
  CliInvariant,
} from "./types.js";

// ── Constants ────────────────────────────────────────────────────────

const VALID_CATEGORIES = new Set([
  "scope", "authorization", "confidentiality", "safety", "compliance", "custom",
]);
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const VALID_ENFORCEMENT = new Set(["halt", "warn", "log"]);

const BOUNDARY_ID_RE = /^B\d{3}$/;
const HALT_ID_RE = /^H\d{3}$/;
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}/;

// ── Validation ───────────────────────────────────────────────────────

export function validateConstitutionData(data: Record<string, unknown>): string[] {
  const errors: string[] = [];

  for (const key of ["identity", "provenance", "boundaries"]) {
    if (!(key in data)) errors.push(`Missing required field: ${key}`);
  }
  if (errors.length) return errors;

  // Identity
  const identity = data.identity as Record<string, unknown> | undefined;
  if (!identity || typeof identity !== "object") {
    errors.push("identity must be an object");
  } else {
    if (!identity.agent_name) errors.push("identity.agent_name is required");
    if (!identity.domain) errors.push("identity.domain is required");
  }

  // Provenance
  const prov = data.provenance as Record<string, unknown> | undefined;
  if (!prov || typeof prov !== "object") {
    errors.push("provenance must be an object");
  } else {
    if (!prov.authored_by) errors.push("provenance.authored_by is required");
    let approvedBy = prov.approved_by;
    if (typeof approvedBy === "string") approvedBy = [approvedBy];
    if (!Array.isArray(approvedBy) || approvedBy.length === 0) {
      errors.push("provenance.approved_by must have at least one entry");
    }
    const approvalDate = String(prov.approval_date ?? "");
    if (!approvalDate) {
      errors.push("provenance.approval_date is required");
    } else if (!ISO8601_RE.test(approvalDate)) {
      errors.push(`provenance.approval_date is not valid ISO 8601: ${approvalDate}`);
    }
    if (!prov.approval_method) errors.push("provenance.approval_method is required");
  }

  // Boundaries
  const boundaries = data.boundaries;
  if (!Array.isArray(boundaries) || boundaries.length === 0) {
    errors.push("boundaries must contain at least one boundary");
  } else {
    const seenIds = new Set<string>();
    for (let i = 0; i < boundaries.length; i++) {
      const b = boundaries[i] as Record<string, unknown>;
      if (!b || typeof b !== "object") {
        errors.push(`boundaries[${i}] must be an object`);
        continue;
      }
      const bid = String(b.id ?? "");
      if (!BOUNDARY_ID_RE.test(bid)) {
        errors.push(`boundaries[${i}].id '${bid}' must match B### pattern`);
      }
      if (seenIds.has(bid)) errors.push(`Duplicate boundary ID: ${bid}`);
      seenIds.add(bid);
      if (!b.description) errors.push(`boundaries[${i}].description is required`);
      if (!VALID_CATEGORIES.has(String(b.category ?? ""))) {
        errors.push(`boundaries[${i}].category '${b.category}' is invalid`);
      }
      if (!VALID_SEVERITIES.has(String(b.severity ?? ""))) {
        errors.push(`boundaries[${i}].severity '${b.severity}' is invalid`);
      }
    }
  }

  // Halt conditions (optional)
  const haltConditions = data.halt_conditions;
  if (Array.isArray(haltConditions)) {
    const seenHids = new Set<string>();
    for (let i = 0; i < haltConditions.length; i++) {
      const h = haltConditions[i] as Record<string, unknown>;
      if (!h || typeof h !== "object") {
        errors.push(`halt_conditions[${i}] must be an object`);
        continue;
      }
      const hid = String(h.id ?? "");
      if (!HALT_ID_RE.test(hid)) {
        errors.push(`halt_conditions[${i}].id '${hid}' must match H### pattern`);
      }
      if (seenHids.has(hid)) errors.push(`Duplicate halt condition ID: ${hid}`);
      seenHids.add(hid);
      if (!h.trigger) errors.push(`halt_conditions[${i}].trigger is required`);
      if (!h.escalate_to) errors.push(`halt_conditions[${i}].escalate_to is required`);
      if (!VALID_SEVERITIES.has(String(h.severity ?? ""))) {
        errors.push(`halt_conditions[${i}].severity '${h.severity}' is invalid`);
      }
      if (!VALID_ENFORCEMENT.has(String(h.enforcement ?? ""))) {
        errors.push(`halt_conditions[${i}].enforcement '${h.enforcement}' is invalid`);
      }
    }
  }

  // Invariants (optional)
  const invariants = data.invariants;
  if (Array.isArray(invariants)) {
    const seenInvIds = new Set<string>();
    for (let i = 0; i < invariants.length; i++) {
      const inv = invariants[i] as Record<string, unknown>;
      if (!inv || typeof inv !== "object") {
        errors.push(`invariants[${i}] must be an object`);
        continue;
      }
      const invId = String(inv.id ?? "");
      if (!invId) errors.push(`invariants[${i}].id is required`);
      if (seenInvIds.has(invId)) errors.push(`Duplicate invariant ID: ${invId}`);
      seenInvIds.add(invId);
      if (!inv.rule) errors.push(`invariants[${i}].rule is required`);
      if (!VALID_ENFORCEMENT.has(String(inv.enforcement ?? ""))) {
        errors.push(`invariants[${i}].enforcement '${inv.enforcement}' is invalid`);
      }
    }
  }

  // CLI permissions (optional)
  const cliPerms = data.cli_permissions;
  if (cliPerms != null) {
    if (typeof cliPerms !== "object" || Array.isArray(cliPerms)) {
      errors.push("cli_permissions must be an object");
    } else {
      const cpObj = cliPerms as Record<string, unknown>;
      const mode = cpObj.mode;
      if (mode !== undefined && mode !== "strict" && mode !== "permissive") {
        errors.push(`cli_permissions.mode '${mode}' must be 'strict' or 'permissive'`);
      }
      const cmds = cpObj.commands;
      if (cmds !== undefined && !Array.isArray(cmds)) {
        errors.push("cli_permissions.commands must be a list");
      } else if (Array.isArray(cmds)) {
        for (let i = 0; i < cmds.length; i++) {
          const cmd = cmds[i] as Record<string, unknown>;
          if (!cmd || typeof cmd !== "object") {
            errors.push(`cli_permissions.commands[${i}] must be an object`);
            continue;
          }
          if (!cmd.id) errors.push(`cli_permissions.commands[${i}].id is required`);
          if (!cmd.binary) errors.push(`cli_permissions.commands[${i}].binary is required`);
          const auth = cmd.authority;
          if (auth !== undefined && auth !== "can_execute" && auth !== "must_escalate" && auth !== "cannot_execute") {
            errors.push(`cli_permissions.commands[${i}].authority '${auth}' is invalid`);
          }
        }
      }
      const invs = cpObj.invariants;
      if (invs !== undefined && !Array.isArray(invs)) {
        errors.push("cli_permissions.invariants must be a list");
      }
    }
  }

  // Authority boundaries (optional)
  const ab = data.authority_boundaries;
  if (ab != null) {
    if (typeof ab !== "object" || Array.isArray(ab)) {
      errors.push("authority_boundaries must be an object");
    } else {
      const abObj = ab as Record<string, unknown>;
      for (const key of ["cannot_execute", "can_execute"]) {
        if (key in abObj && !Array.isArray(abObj[key])) {
          errors.push(`authority_boundaries.${key} must be a list`);
        }
      }
      const mustEsc = abObj.must_escalate;
      if (mustEsc !== undefined && !Array.isArray(mustEsc)) {
        errors.push("authority_boundaries.must_escalate must be a list");
      } else if (Array.isArray(mustEsc)) {
        for (let i = 0; i < mustEsc.length; i++) {
          const rule = mustEsc[i] as Record<string, unknown>;
          if (!rule || typeof rule !== "object") {
            errors.push(`authority_boundaries.must_escalate[${i}] must be an object`);
          } else if (!rule.condition) {
            errors.push(`authority_boundaries.must_escalate[${i}].condition is required`);
          }
        }
      }
    }
  }

  return errors;
}

// ── Parsing ──────────────────────────────────────────────────────────

export function parseConstitution(data: Record<string, unknown>): Constitution {
  const errors = validateConstitutionData(data);
  if (errors.length) {
    throw new Error(`Invalid constitution: ${errors.join("; ")}`);
  }

  const schemaVersion = String(
    data.sanna_constitution ?? data.schema_version ?? "0.1.0",
  );

  // Identity
  const identityData = data.identity as Record<string, unknown>;
  const knownIdentityKeys = new Set(["agent_name", "domain", "description", "identity_claims"]);
  const extensions: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(identityData)) {
    if (!knownIdentityKeys.has(k)) extensions[k] = v;
  }
  const identity: AgentIdentity = {
    agent_name: String(identityData.agent_name),
    domain: String(identityData.domain),
    description: String(identityData.description ?? ""),
    extensions,
  };

  // Provenance
  const provData = data.provenance as Record<string, unknown>;
  let approvedBy = provData.approved_by;
  if (typeof approvedBy === "string") approvedBy = [approvedBy];

  let provSignature: ConstitutionSignature | null = null;
  const sigData = provData.signature as Record<string, unknown> | undefined;
  if (sigData && typeof sigData === "object") {
    provSignature = {
      value: (sigData.value as string) ?? null,
      key_id: (sigData.key_id as string) ?? null,
      signed_by: (sigData.signed_by as string) ?? null,
      signed_at: (sigData.signed_at as string) ?? null,
      scheme: String(sigData.scheme ?? "constitution_sig_v1"),
    };
  }

  const provenance: Provenance = {
    authored_by: String(provData.authored_by),
    approved_by: approvedBy as string[],
    approval_date: String(provData.approval_date),
    approval_method: String(provData.approval_method),
    change_history: (provData.change_history as Record<string, string>[]) ?? [],
    signature: provSignature,
  };

  // Boundaries
  const boundaries: Boundary[] = (data.boundaries as Record<string, unknown>[]).map((b) => ({
    id: String(b.id),
    description: String(b.description),
    category: String(b.category) as Boundary["category"],
    severity: String(b.severity) as Boundary["severity"],
  }));

  // Trust tiers
  const trustData = (data.trust_tiers ?? {}) as Record<string, unknown>;
  const trustTiers: TrustTiers = {
    autonomous: (trustData.autonomous as string[]) ?? [],
    requires_approval: (trustData.requires_approval as string[]) ?? [],
    prohibited: (trustData.prohibited as string[]) ?? [],
  };

  // Halt conditions
  const haltConditions: HaltCondition[] = ((data.halt_conditions ?? []) as Record<string, unknown>[]).map((h) => ({
    id: String(h.id),
    trigger: String(h.trigger),
    escalate_to: String(h.escalate_to),
    severity: String(h.severity) as HaltCondition["severity"],
    enforcement: String(h.enforcement) as HaltCondition["enforcement"],
  }));

  // Invariants
  const invariants: Invariant[] = ((data.invariants ?? []) as Record<string, unknown>[]).map((inv) => ({
    id: String(inv.id),
    rule: String(inv.rule),
    enforcement: String(inv.enforcement) as Invariant["enforcement"],
    check: inv.check != null ? String(inv.check) : null,
  }));

  // Authority boundaries
  let authorityBoundaries: AuthorityBoundaries | null = null;
  const abData = data.authority_boundaries as Record<string, unknown> | undefined;
  if (abData && typeof abData === "object") {
    const etData = (data.escalation_targets ?? {}) as Record<string, unknown>;
    const defaultEscalation = String(etData.default ?? "log");

    const mustEscalate: EscalationRule[] = ((abData.must_escalate ?? []) as Record<string, unknown>[]).map((rule) => {
      let target: EscalationTargetConfig | null = null;
      const targetData = rule.target as Record<string, unknown> | undefined;
      if (targetData && typeof targetData === "object") {
        target = {
          type: String(targetData.type ?? "log") as EscalationTargetConfig["type"],
          url: targetData.url as string | undefined,
          handler: targetData.handler as string | undefined,
        };
      }
      return { condition: String(rule.condition ?? ""), target };
    });

    authorityBoundaries = {
      cannot_execute: (abData.cannot_execute as string[]) ?? [],
      must_escalate: mustEscalate,
      can_execute: (abData.can_execute as string[]) ?? [],
      default_escalation: defaultEscalation,
    };
  }

  // CLI permissions
  const cliPermsData = data.cli_permissions as Record<string, unknown> | undefined;
  let cliPermissions: CliPermissions | null = null;
  if (cliPermsData && typeof cliPermsData === "object") {
    const commands: CliCommand[] = [];
    const rawCommands = (cliPermsData.commands as Record<string, unknown>[]) ?? [];
    for (const cmd of rawCommands) {
      if (cmd && typeof cmd === "object") {
        commands.push({
          id: (cmd.id as string) ?? "",
          binary: (cmd.binary as string) ?? "",
          authority: (cmd.authority as "can_execute" | "must_escalate" | "cannot_execute") ?? "can_execute",
          argv_pattern: (cmd.argv_pattern as string) ?? "*",
          description: (cmd.description as string) ?? "",
          escalation_target: cmd.escalation_target as string | undefined,
        });
      }
    }

    const cliInvariants: CliInvariant[] = [];
    const rawInvariants = (cliPermsData.invariants as Record<string, unknown>[]) ?? [];
    for (const inv of rawInvariants) {
      if (inv && typeof inv === "object") {
        cliInvariants.push({
          id: (inv.id as string) ?? "",
          description: (inv.description as string) ?? "",
          verdict: (inv.verdict as "halt" | "warn") ?? "halt",
          pattern: inv.pattern as string | undefined,
          condition: inv.condition as string | undefined,
        });
      }
    }

    cliPermissions = {
      mode: (cliPermsData.mode as "strict" | "permissive") ?? "strict",
      justification_required: (cliPermsData.justification_required as boolean) ?? true,
      commands,
      invariants: cliInvariants,
    };
  }

  // Trusted sources
  let trustedSources: TrustedSources | null = null;
  const tsData = data.trusted_sources as Record<string, unknown> | undefined;
  if (tsData && typeof tsData === "object") {
    trustedSources = {
      tier_1: (tsData.tier_1 as string[]) ?? [],
      tier_2: (tsData.tier_2 as string[]) ?? [],
      tier_3: (tsData.tier_3 as string[]) ?? [],
      untrusted: (tsData.untrusted as string[]) ?? [],
    };
  }

  return {
    schema_version: schemaVersion,
    identity,
    provenance,
    boundaries,
    trust_tiers: trustTiers,
    halt_conditions: haltConditions,
    invariants,
    policy_hash: (data.policy_hash as string) ?? null,
    authority_boundaries: authorityBoundaries,
    cli_permissions: cliPermissions,
    trusted_sources: trustedSources,
  };
}

// ── Loading ──────────────────────────────────────────────────────────

/**
 * Load a constitution from a YAML file.
 * Parses, validates, and returns the structured Constitution object.
 */
export function loadConstitution(path: string): Constitution {
  const content = readFileSync(path, "utf-8");
  const data = yaml.load(content) as Record<string, unknown>;
  return parseConstitution(data);
}

// ── Content hash ─────────────────────────────────────────────────────

/**
 * Compute the content hash of a constitution YAML file.
 * This is `hash_text(file_content)` per the Python fixture generator.
 */
export function computeFileContentHash(path: string): string {
  const content = readFileSync(path, "utf-8");
  return hashContent(content, 64);
}

// ── Signature verification ───────────────────────────────────────────

/**
 * Build the signable dict for a constitution, matching Python's
 * `constitution_to_signable_dict()`.
 *
 * The signature.value is blanked to "". All other fields are included.
 */
function constitutionToSignableDict(c: Constitution): Record<string, unknown> {
  const provDict: Record<string, unknown> = {
    authored_by: c.provenance.authored_by,
    approved_by: c.provenance.approved_by,
    approval_date: c.provenance.approval_date,
    approval_method: c.provenance.approval_method,
    change_history: c.provenance.change_history,
  };

  if (c.provenance.signature) {
    provDict.signature = {
      value: "",  // excluded from signing
      key_id: c.provenance.signature.key_id,
      signed_by: c.provenance.signature.signed_by,
      signed_at: c.provenance.signature.signed_at,
      scheme: c.provenance.signature.scheme,
    };
  } else {
    provDict.signature = null;
  }

  // Identity dict — flatten extensions to top level (matches Python _identity_dict)
  const identityDict: Record<string, unknown> = {
    agent_name: c.identity.agent_name,
    domain: c.identity.domain,
    description: c.identity.description,
  };
  if (c.identity.extensions) {
    Object.assign(identityDict, c.identity.extensions);
  }

  const result: Record<string, unknown> = {
    schema_version: c.schema_version,
    identity: identityDict,
    provenance: provDict,
    boundaries: c.boundaries.map((b) => ({ ...b })),
    trust_tiers: { ...c.trust_tiers },
    halt_conditions: c.halt_conditions.map((h) => ({ ...h })),
    invariants: c.invariants.map((inv) => ({
      id: inv.id,
      rule: inv.rule,
      enforcement: inv.enforcement,
      check: inv.check,
    })),
    policy_hash: c.policy_hash,
  };

  if (c.authority_boundaries) {
    result.authority_boundaries = {
      cannot_execute: c.authority_boundaries.cannot_execute,
      must_escalate: c.authority_boundaries.must_escalate.map((r) => {
        const rule: Record<string, unknown> = { condition: r.condition };
        if (r.target) rule.target = { ...r.target };
        else rule.target = null;
        return rule;
      }),
      can_execute: c.authority_boundaries.can_execute,
      default_escalation: c.authority_boundaries.default_escalation,
    };
    result.escalation_targets = {
      default: c.authority_boundaries.default_escalation,
    };
  }

  if (c.cli_permissions) {
    result.cli_permissions = {
      mode: c.cli_permissions.mode,
      justification_required: c.cli_permissions.justification_required,
      commands: c.cli_permissions.commands.map((cmd) => {
        const plain: Record<string, unknown> = {
          id: cmd.id,
          binary: cmd.binary,
          authority: cmd.authority,
        };
        if (cmd.argv_pattern !== undefined) plain.argv_pattern = cmd.argv_pattern;
        if (cmd.description !== undefined) plain.description = cmd.description;
        if (cmd.escalation_target !== undefined) plain.escalation_target = cmd.escalation_target;
        return plain;
      }),
      invariants: c.cli_permissions.invariants.map((inv) => {
        const plain: Record<string, unknown> = {
          id: inv.id,
          description: inv.description,
          verdict: inv.verdict,
        };
        if (inv.pattern !== undefined) plain.pattern = inv.pattern;
        if (inv.condition !== undefined) plain.condition = inv.condition;
        return plain;
      }),
    };
  }

  if (c.trusted_sources) {
    result.trusted_sources = { ...c.trusted_sources };
  }

  return result;
}

/**
 * Sanitize a value tree for signing: convert exact-integer floats to int,
 * reject non-integer floats. Matches Python's `sanitize_for_signing()`.
 */
function sanitizeForSigning(obj: unknown): unknown {
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error(`Non-finite number in signed content: ${obj}`);
    }
    if (Number.isInteger(obj)) return obj;
    if (obj === Math.trunc(obj)) return Math.trunc(obj);
    throw new Error(`Non-integer float in signed content: ${obj}`);
  }
  if (Array.isArray(obj)) {
    return obj.map((v) => sanitizeForSigning(v));
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      result[k] = sanitizeForSigning(v);
    }
    return result;
  }
  return obj;
}

/**
 * Verify a constitution's Ed25519 signature.
 *
 * Reconstructs the signable dict with signature.value="", canonicalizes it,
 * and verifies against the stored signature. Also checks key_id match.
 *
 * Returns false for unsigned constitutions.
 */
export function verifyConstitutionSignature(
  constitution: Constitution,
  publicKey: KeyObject,
): boolean {
  const sig = constitution.provenance.signature;
  if (!sig || !sig.value) return false;

  // Check key_id matches
  const expectedKeyId = getKeyId(publicKey);
  if (sig.key_id !== expectedKeyId) return false;

  const signableDict = constitutionToSignableDict(constitution);
  const sanitized = sanitizeForSigning(signableDict);
  const canonical = canonicalize(sanitized);
  const data = Buffer.from(canonical, "utf-8");

  return verify(data, sig.value, publicKey);
}

// ── Constitution signing ─────────────────────────────────────────────

/**
 * Compute policy_hash and add Ed25519 signature to a constitution.
 *
 * Returns a new constitution object with provenance.signature populated.
 */
export function signConstitution(
  constitution: Constitution,
  privateKey: KeyObject,
  signedBy: string,
): Constitution {
  const keyId = getKeyId(privateKey);

  // Build signable dict with policy_hash and blank signature
  const sigBlock: ConstitutionSignature = {
    value: "",
    key_id: keyId,
    signed_by: signedBy,
    signed_at: new Date().toISOString(),
    scheme: "constitution_sig_v1",
  };

  // Clone and attach signature placeholder
  const signed: Constitution = structuredClone(constitution);
  signed.provenance = { ...signed.provenance, signature: sigBlock };

  // Pass 1: compute policy_hash (signable dict still has policy_hash=null)
  const preDict = constitutionToSignableDict(signed);
  const preSanitized = sanitizeForSigning(preDict);
  signed.policy_hash = hashObj(preSanitized);

  // Pass 2: rebuild signable dict with correct policy_hash, then sign
  const signableDict = constitutionToSignableDict(signed);
  const sanitized = sanitizeForSigning(signableDict);
  const canonical = canonicalize(sanitized);
  const data = Buffer.from(canonical, "utf-8");
  const signatureB64 = sign(data, privateKey);

  // Replace placeholder
  signed.provenance.signature!.value = signatureB64;

  return signed;
}

/**
 * Serialize a constitution to YAML and write to a file.
 */
export function saveConstitution(constitution: Constitution, path: string): void {
  const dir = dirname(path);
  if (dir) mkdirSync(dir, { recursive: true });

  const dict = constitutionToSignableDict(constitution);

  // Restore actual signature value (constitutionToSignableDict blanks it)
  if (constitution.provenance.signature?.value) {
    const prov = dict.provenance as Record<string, unknown>;
    const sig = prov.signature as Record<string, unknown>;
    sig.value = constitution.provenance.signature.value;
  }

  // Use sanna_constitution instead of schema_version at top level
  const output: Record<string, unknown> = { sanna_constitution: dict.schema_version };
  for (const [k, v] of Object.entries(dict)) {
    if (k !== "schema_version") output[k] = v;
  }

  const yamlStr = yaml.dump(output, {
    lineWidth: -1,
    noRefs: true,
    quotingType: "'",
    forceQuotes: false,
  });

  writeFileSync(path, yamlStr, "utf-8");
}
