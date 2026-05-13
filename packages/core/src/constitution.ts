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
import { sign, verify, getKeyId, sanitizeForSigning } from "./crypto.js";
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
  AnomalyTracking,
  EscalationRule,
  EscalationTargetConfig,
  CliPermissions,
  CliCommand,
  CliInvariant,
  ApiPermissions,
  ApiEndpoint,
  ApiInvariant,
  Composition,
  ReasoningConfig,
  GLCCheckConfig,
  GLCMinimumSubstanceConfig,
  GLCNoParrotingConfig,
  GLCLLMCoherenceConfig,
  JudgeConfig,
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

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function isDangerousKey(key: string): boolean {
  return DANGEROUS_KEYS.has(key) || key.startsWith("__");
}

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

  // CLI permissions (optional, v1.2+)
  const cliPerms = data.cli_permissions;
  if (cliPerms !== undefined && cliPerms !== null) {
    if (typeof cliPerms !== "object" || Array.isArray(cliPerms)) {
      errors.push("cli_permissions must be an object");
    } else {
      const cp = cliPerms as Record<string, unknown>;
      const cpMode = cp.mode ?? "strict";
      if (cpMode !== "strict" && cpMode !== "permissive") {
        errors.push(`cli_permissions.mode '${cpMode}' must be 'strict' or 'permissive'`);
      }
      const cpJr = cp.justification_required;
      if (cpJr !== undefined && cpJr !== null && typeof cpJr !== "boolean") {
        errors.push("cli_permissions.justification_required must be a boolean");
      }

      const cmds = cp.commands ?? [];
      if (!Array.isArray(cmds)) {
        errors.push("cli_permissions.commands must be an array");
      } else {
        const seenCmdIds = new Set<string>();
        for (let i = 0; i < cmds.length; i++) {
          const cmd = cmds[i] as Record<string, unknown>;
          if (!cmd || typeof cmd !== "object") {
            errors.push(`cli_permissions.commands[${i}] must be an object`);
            continue;
          }
          const cmdId = String(cmd.id ?? "");
          if (!cmdId) errors.push(`cli_permissions.commands[${i}].id is required`);
          if (seenCmdIds.has(cmdId)) errors.push(`Duplicate cli_permissions command ID: ${cmdId}`);
          seenCmdIds.add(cmdId);

          const binary = String(cmd.binary ?? "");
          if (!binary) errors.push(`cli_permissions.commands[${i}].binary is required`);
          if (/[/\\*?]/.test(binary)) {
            errors.push(`cli_permissions.commands[${i}].binary must not contain path separators or wildcards`);
          }

          const cmdAuth = cmd.authority;
          if (!["can_execute", "must_escalate", "cannot_execute"].includes(String(cmdAuth ?? ""))) {
            errors.push(`cli_permissions.commands[${i}].authority '${cmdAuth}' must be 'can_execute', 'must_escalate', or 'cannot_execute'`);
          }
        }
      }

      const cpInvs = cp.invariants ?? [];
      if (!Array.isArray(cpInvs)) {
        errors.push("cli_permissions.invariants must be an array");
      } else {
        const seenCpInvIds = new Set<string>();
        for (let i = 0; i < cpInvs.length; i++) {
          const inv = cpInvs[i] as Record<string, unknown>;
          if (!inv || typeof inv !== "object") {
            errors.push(`cli_permissions.invariants[${i}] must be an object`);
            continue;
          }
          const cpInvId = String(inv.id ?? "");
          if (!cpInvId) errors.push(`cli_permissions.invariants[${i}].id is required`);
          if (seenCpInvIds.has(cpInvId)) errors.push(`Duplicate cli_permissions invariant ID: ${cpInvId}`);
          seenCpInvIds.add(cpInvId);
          if (!inv.description) errors.push(`cli_permissions.invariants[${i}].description is required`);
          const cpVerdict = inv.verdict;
          if (cpVerdict !== "halt" && cpVerdict !== "warn") {
            errors.push(`cli_permissions.invariants[${i}].verdict '${cpVerdict}' must be 'halt' or 'warn'`);
          }
        }
      }
    }
  }

  // API permissions (optional, v1.2+)
  const VALID_HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "*"]);
  const apiPerms = data.api_permissions;
  if (apiPerms !== undefined && apiPerms !== null) {
    if (typeof apiPerms !== "object" || Array.isArray(apiPerms)) {
      errors.push("api_permissions must be an object");
    } else {
      const ap = apiPerms as Record<string, unknown>;
      const apMode = ap.mode ?? "strict";
      if (apMode !== "strict" && apMode !== "permissive") {
        errors.push(`api_permissions.mode '${apMode}' must be 'strict' or 'permissive'`);
      }
      const apJr = ap.justification_required;
      if (apJr !== undefined && apJr !== null && typeof apJr !== "boolean") {
        errors.push("api_permissions.justification_required must be a boolean");
      }

      const endpoints = ap.endpoints ?? [];
      if (!Array.isArray(endpoints)) {
        errors.push("api_permissions.endpoints must be an array");
      } else {
        const seenEpIds = new Set<string>();
        for (let i = 0; i < endpoints.length; i++) {
          const ep = endpoints[i] as Record<string, unknown>;
          if (!ep || typeof ep !== "object") {
            errors.push(`api_permissions.endpoints[${i}] must be an object`);
            continue;
          }
          const epId = String(ep.id ?? "");
          if (!epId) errors.push(`api_permissions.endpoints[${i}].id is required`);
          if (seenEpIds.has(epId)) errors.push(`Duplicate api_permissions endpoint ID: ${epId}`);
          seenEpIds.add(epId);
          if (!ep.url_pattern) errors.push(`api_permissions.endpoints[${i}].url_pattern is required`);

          const epAuth = ep.authority;
          if (!["can_execute", "must_escalate", "cannot_execute"].includes(String(epAuth ?? ""))) {
            errors.push(`api_permissions.endpoints[${i}].authority '${epAuth}' must be 'can_execute', 'must_escalate', or 'cannot_execute'`);
          }

          const methods = ep.methods;
          if (methods !== undefined && methods !== null) {
            if (!Array.isArray(methods)) {
              errors.push(`api_permissions.endpoints[${i}].methods must be an array`);
            } else {
              for (let j = 0; j < methods.length; j++) {
                if (!VALID_HTTP_METHODS.has(String(methods[j]))) {
                  errors.push(`api_permissions.endpoints[${i}].methods[${j}] '${methods[j]}' is not a valid HTTP method`);
                }
              }
            }
          }
        }
      }

      const apInvs = ap.invariants ?? [];
      if (!Array.isArray(apInvs)) {
        errors.push("api_permissions.invariants must be an array");
      } else {
        const seenApInvIds = new Set<string>();
        for (let i = 0; i < apInvs.length; i++) {
          const inv = apInvs[i] as Record<string, unknown>;
          if (!inv || typeof inv !== "object") {
            errors.push(`api_permissions.invariants[${i}] must be an object`);
            continue;
          }
          const apInvId = String(inv.id ?? "");
          if (!apInvId) errors.push(`api_permissions.invariants[${i}].id is required`);
          if (seenApInvIds.has(apInvId)) errors.push(`Duplicate api_permissions invariant ID: ${apInvId}`);
          seenApInvIds.add(apInvId);
          if (!inv.description) errors.push(`api_permissions.invariants[${i}].description is required`);
          const apVerdict = inv.verdict;
          if (apVerdict !== "halt" && apVerdict !== "warn") {
            errors.push(`api_permissions.invariants[${i}].verdict '${apVerdict}' must be 'halt' or 'warn'`);
          }
        }
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
      const ev = abObj.escalation_visibility;
      if (ev !== undefined && ev !== "visible" && ev !== "suppressed") {
        errors.push(`authority_boundaries.escalation_visibility '${ev}' must be 'visible' or 'suppressed'`);
      }
    }
  }

  // Composition (optional, v1.5+)
  const composition = data.composition;
  if (composition !== undefined && composition !== null) {
    if (typeof composition !== "object" || Array.isArray(composition)) {
      errors.push("composition must be an object");
    } else {
      const compObj = composition as Record<string, unknown>;
      const compEv = compObj.escalation_visibility;
      if (compEv !== undefined && compEv !== "visible" && compEv !== "suppressed") {
        errors.push(`composition.escalation_visibility '${compEv}' must be 'visible' or 'suppressed'`);
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
    if (!knownIdentityKeys.has(k) && !isDangerousKey(k)) extensions[k] = v;
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

    const anomalyTrackingData = abData.anomaly_tracking as Record<string, unknown> | undefined;
    const anomalyTracking: AnomalyTracking = {
      cli: Boolean(anomalyTrackingData?.cli ?? false),
      http: Boolean(anomalyTrackingData?.http ?? false),
    };

    authorityBoundaries = {
      cannot_execute: (abData.cannot_execute as string[]) ?? [],
      must_escalate: mustEscalate,
      can_execute: (abData.can_execute as string[]) ?? [],
      default_escalation: defaultEscalation,
      escalation_visibility: (abData.escalation_visibility as "visible" | "suppressed" | undefined) ?? "visible",
      anomaly_tracking: anomalyTracking,
    };
  }

  // Composition (optional, v1.5+)
  let composition: Composition | null = null;
  const compData = data.composition as Record<string, unknown> | undefined;
  if (compData && typeof compData === "object") {
    composition = {
      escalation_visibility: (compData.escalation_visibility as "visible" | "suppressed" | undefined) ?? "visible",
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
      inspect_scripts: Boolean(cliPermsData.inspect_scripts ?? false),
      commands,
      invariants: cliInvariants,
    };
  }

  // API permissions
  const apiPermsData = data.api_permissions as Record<string, unknown> | undefined;
  let apiPermissions: ApiPermissions | null = null;
  if (apiPermsData && typeof apiPermsData === "object") {
    const endpoints: ApiEndpoint[] = [];
    const rawEndpoints = (apiPermsData.endpoints as Record<string, unknown>[]) ?? [];
    for (const ep of rawEndpoints) {
      if (ep && typeof ep === "object") {
        endpoints.push({
          id: (ep.id as string) ?? "",
          url_pattern: (ep.url_pattern as string) ?? "",
          authority: (ep.authority as "can_execute" | "must_escalate" | "cannot_execute") ?? "can_execute",
          methods: (ep.methods as string[]) ?? ["*"],
          description: (ep.description as string) ?? "",
          escalation_target: ep.escalation_target as string | undefined,
        });
      }
    }

    const apiInvariants: ApiInvariant[] = [];
    const rawApiInvariants = (apiPermsData.invariants as Record<string, unknown>[]) ?? [];
    for (const inv of rawApiInvariants) {
      if (inv && typeof inv === "object") {
        apiInvariants.push({
          id: (inv.id as string) ?? "",
          description: (inv.description as string) ?? "",
          verdict: (inv.verdict as "halt" | "warn") ?? "halt",
          pattern: inv.pattern as string | undefined,
        });
      }
    }

    apiPermissions = {
      mode: (apiPermsData.mode as "strict" | "permissive") ?? "strict",
      justification_required: (apiPermsData.justification_required as boolean) ?? true,
      endpoints,
      invariants: apiInvariants,
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

  // Version (default "1.0")
  const version = data.version != null ? String(data.version) : "1.0";

  // Reasoning config (v1.1+)
  let reasoning: ReasoningConfig | null = null;
  const reasoningData = data.reasoning as Record<string, unknown> | undefined;
  if (reasoningData && typeof reasoningData === "object") {
    const checksRaw = (reasoningData.checks as Record<string, Record<string, unknown>>) ?? {};
    const checks: Record<string, GLCCheckConfig | GLCMinimumSubstanceConfig | GLCNoParrotingConfig | GLCLLMCoherenceConfig> = {};
    for (const [name, checkData] of Object.entries(checksRaw)) {
      if (checkData && typeof checkData === "object") {
        const enabled = Boolean(checkData.enabled ?? true);
        if ("score_threshold" in checkData || "enabled_for" in checkData) {
          const c: GLCLLMCoherenceConfig = {
            enabled,
            enabled_for: (checkData.enabled_for as string[]) ?? ["must_escalate"],
            timeout_ms: (checkData.timeout_ms as number) ?? 2000,
            score_threshold: (checkData.score_threshold as number) ?? 0.6,
            judge_override: (checkData.judge_override as Record<string, unknown>) ?? null,
          };
          checks[name] = c;
        } else if ("blocklist" in checkData) {
          const c: GLCNoParrotingConfig = {
            enabled,
            blocklist: (checkData.blocklist as string[]) ?? [],
          };
          checks[name] = c;
        } else if ("min_length" in checkData) {
          const c: GLCMinimumSubstanceConfig = {
            enabled,
            min_length: (checkData.min_length as number) ?? 20,
          };
          checks[name] = c;
        } else {
          checks[name] = { enabled };
        }
      }
    }

    let judge: JudgeConfig | null = null;
    const judgeData = reasoningData.judge as Record<string, unknown> | undefined;
    if (judgeData && typeof judgeData === "object") {
      judge = {
        default_provider: (judgeData.default_provider as string) ?? null,
        default_model: (judgeData.default_model as string) ?? null,
        cross_provider: Boolean(judgeData.cross_provider ?? false),
      };
    }

    reasoning = {
      require_justification_for: (reasoningData.require_justification_for as string[]) ?? ["must_escalate", "cannot_execute"],
      on_missing_justification: (reasoningData.on_missing_justification as string) ?? "block",
      on_check_error: (reasoningData.on_check_error as string) ?? "block",
      on_api_error: (reasoningData.on_api_error as string) ?? "block",
      checks,
      judge,
      evaluate_before_escalation: Boolean(reasoningData.evaluate_before_escalation ?? true),
      auto_deny_on_reasoning_failure: Boolean(reasoningData.auto_deny_on_reasoning_failure ?? false),
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
    api_permissions: apiPermissions,
    trusted_sources: trustedSources,
    composition,
    version,
    reasoning,
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

// Verbatim v1 form — DO NOT MODIFY. The v1 byte contract is frozen.
function _constitutionToSignableDictV1(c: Constitution): Record<string, unknown> {
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
    for (const [k, v] of Object.entries(c.identity.extensions)) {
      if (!isDangerousKey(k)) identityDict[k] = v;
    }
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
    const ab: Record<string, unknown> = {
      cannot_execute: c.authority_boundaries.cannot_execute,
      // SAN-490: emit null explicitly for absent optional sub-fields to match
      // Python's asdict-include-null canonicalization. See spec/fixtures/
      // constitution-signable-vectors.json for the byte-equal contract.
      must_escalate: c.authority_boundaries.must_escalate.map((r) => {
        const rule: Record<string, unknown> = { condition: r.condition };
        if (r.target) {
          rule.target = {
            type: r.target.type,
            url: r.target.url ?? null,
            handler: r.target.handler ?? null,
          };
        } else {
          rule.target = null;
        }
        return rule;
      }),
      can_execute: c.authority_boundaries.can_execute,
      default_escalation: c.authority_boundaries.default_escalation,
    };
    if (c.authority_boundaries.escalation_visibility && c.authority_boundaries.escalation_visibility !== "visible") {
      ab.escalation_visibility = c.authority_boundaries.escalation_visibility;
    }
    if (c.authority_boundaries.anomaly_tracking?.cli || c.authority_boundaries.anomaly_tracking?.http) {
      const at: Record<string, boolean> = {};
      if (c.authority_boundaries.anomaly_tracking.cli) at.cli = true;
      if (c.authority_boundaries.anomaly_tracking.http) at.http = true;
      ab.anomaly_tracking = at;
    }
    result.authority_boundaries = ab;
    result.escalation_targets = {
      default: c.authority_boundaries.default_escalation,
    };
  }
  if (c.composition && c.composition.escalation_visibility && c.composition.escalation_visibility !== "visible") {
    result.composition = { escalation_visibility: c.composition.escalation_visibility };
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

  if (c.api_permissions) {
    result.api_permissions = {
      mode: c.api_permissions.mode,
      justification_required: c.api_permissions.justification_required,
      endpoints: c.api_permissions.endpoints.map((ep) => {
        const plain: Record<string, unknown> = {
          id: ep.id,
          url_pattern: ep.url_pattern,
          authority: ep.authority,
        };
        if (ep.methods !== undefined) plain.methods = ep.methods;
        if (ep.description !== undefined) plain.description = ep.description;
        if (ep.escalation_target !== undefined) plain.escalation_target = ep.escalation_target;
        return plain;
      }),
      invariants: c.api_permissions.invariants.map((inv) => {
        const plain: Record<string, unknown> = {
          id: inv.id,
          description: inv.description,
          verdict: inv.verdict,
        };
        if (inv.pattern !== undefined) plain.pattern = inv.pattern;
        return plain;
      }),
    };
  }

  if (c.trusted_sources) {
    result.trusted_sources = { ...c.trusted_sources };
  }

  return result;
}

// Unnumbered → numbered check key mapping (mirrors Python's _UNNUMBERED_TO_NUMBERED)
const _UNNUMBERED_TO_NUMBERED: Record<string, string> = {
  glc_minimum_substance: "glc_002_minimum_substance",
  glc_no_parroting: "glc_003_no_parroting",
  glc_llm_coherence: "glc_005_llm_coherence",
};

// Serialize ReasoningConfig for signing (mirrors Python's _reasoning_config_to_dict with for_signing=True)
function _reasoningConfigToSignableDict(reasoning: ReasoningConfig): Record<string, unknown> {
  const checksDict: Record<string, Record<string, unknown>> = {};
  for (const [name, check] of Object.entries(reasoning.checks)) {
    const canonical = _UNNUMBERED_TO_NUMBERED[name] ?? name;
    const d: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(check)) {
      d[k] = v;
    }
    if (canonical === "glc_005_llm_coherence" && "score_threshold" in check) {
      // Convert float to basis points for deterministic canonical JSON (mirrors Python for_signing=True)
      d["score_threshold"] = Math.round((check as GLCLLMCoherenceConfig).score_threshold * 10000);
    }
    checksDict[name] = d;
  }

  const d: Record<string, unknown> = {
    require_justification_for: reasoning.require_justification_for,
    on_missing_justification: reasoning.on_missing_justification,
    on_check_error: reasoning.on_check_error,
    on_api_error: reasoning.on_api_error,
    checks: checksDict,
    evaluate_before_escalation: reasoning.evaluate_before_escalation,
    auto_deny_on_reasoning_failure: reasoning.auto_deny_on_reasoning_failure,
  };

  if (reasoning.judge != null) {
    d["judge"] = {
      default_provider: reasoning.judge.default_provider,
      default_model: reasoning.judge.default_model,
      cross_provider: reasoning.judge.cross_provider,
    };
  }

  return d;
}

// v2 canonical form — mirrors spec/tools/generate_signable_vectors_v2.py:build_v2_signable_dict byte-for-byte
function _constitutionToSignableDictV2(c: Constitution): Record<string, unknown> {
  const provDict: Record<string, unknown> = {
    authored_by: c.provenance.authored_by,
    approved_by: c.provenance.approved_by,
    approval_date: c.provenance.approval_date,
    approval_method: c.provenance.approval_method,
    change_history: c.provenance.change_history,
  };

  if (c.provenance.signature != null) {
    provDict.signature = {
      value: "",
      key_id: c.provenance.signature.key_id,
      signed_by: c.provenance.signature.signed_by,
      signed_at: c.provenance.signature.signed_at,
      scheme: c.provenance.signature.scheme,
    };
  } else {
    provDict.signature = null;
  }

  const identityDict: Record<string, unknown> = {
    agent_name: c.identity.agent_name,
    domain: c.identity.domain,
    description: c.identity.description,
  };
  if (c.identity.extensions) {
    for (const [k, v] of Object.entries(c.identity.extensions)) {
      if (!isDangerousKey(k)) identityDict[k] = v;
    }
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

  if (c.authority_boundaries != null) {
    const ab: Record<string, unknown> = {
      cannot_execute: c.authority_boundaries.cannot_execute,
      must_escalate: c.authority_boundaries.must_escalate.map((r) => {
        if (r.target == null) {
          return { condition: r.condition, target: null };
        }
        return {
          condition: r.condition,
          target: {
            type: r.target.type,
            url: r.target.url ?? null,
            handler: r.target.handler ?? null,
          },
        };
      }),
      can_execute: c.authority_boundaries.can_execute,
      default_escalation: c.authority_boundaries.default_escalation,
    };
    if (c.authority_boundaries.escalation_visibility !== "visible") {
      ab.escalation_visibility = c.authority_boundaries.escalation_visibility;
    }
    if (c.authority_boundaries.anomaly_tracking?.cli || c.authority_boundaries.anomaly_tracking?.http) {
      const at: Record<string, boolean> = {};
      if (c.authority_boundaries.anomaly_tracking.cli) at.cli = true;
      if (c.authority_boundaries.anomaly_tracking.http) at.http = true;
      ab.anomaly_tracking = at;
    }
    result.authority_boundaries = ab;
    result.escalation_targets = { default: c.authority_boundaries.default_escalation };
  }

  // v2: composition emitted whenever present, even at default escalation_visibility
  if (c.composition != null) {
    result.composition = { escalation_visibility: c.composition.escalation_visibility ?? "visible" };
  }

  if (c.cli_permissions != null) {
    result.cli_permissions = {
      mode: c.cli_permissions.mode,
      justification_required: c.cli_permissions.justification_required,
      inspect_scripts: c.cli_permissions.inspect_scripts ?? false,
      commands: c.cli_permissions.commands.map((cmd) => ({
        id: cmd.id,
        binary: cmd.binary,
        authority: cmd.authority,
        argv_pattern: cmd.argv_pattern ?? "*",
        description: cmd.description ?? "",
        escalation_target: cmd.escalation_target ?? null,
      })),
      invariants: c.cli_permissions.invariants.map((inv) => ({
        id: inv.id,
        description: inv.description,
        verdict: inv.verdict,
        pattern: inv.pattern ?? null,
        condition: inv.condition ?? null,
      })),
    };
  }

  if (c.api_permissions != null) {
    result.api_permissions = {
      mode: c.api_permissions.mode,
      justification_required: c.api_permissions.justification_required,
      endpoints: c.api_permissions.endpoints.map((ep) => ({
        id: ep.id,
        url_pattern: ep.url_pattern,
        authority: ep.authority,
        methods: ep.methods ?? ["*"],
        description: ep.description ?? "",
        escalation_target: ep.escalation_target ?? null,
      })),
      invariants: c.api_permissions.invariants.map((inv) => ({
        id: inv.id,
        description: inv.description,
        verdict: inv.verdict,
        pattern: inv.pattern ?? null,
      })),
    };
  }

  if (c.trusted_sources != null) {
    result.trusted_sources = { ...c.trusted_sources };
  }

  // v2: version emitted when non-default
  if (c.version != null && c.version !== "1.0") {
    result.version = c.version;
  }

  // v2: reasoning emitted when present
  if (c.reasoning != null) {
    result.reasoning = _reasoningConfigToSignableDict(c.reasoning);
  }

  return result;
}

/** Parse signing version from a scheme string. Throws on unrecognized or malformed input. */
function _parseSigningVersion(scheme: string): number {
  const PREFIX = "constitution_sig_v";
  if (!scheme.startsWith(PREFIX)) {
    throw new Error(`Unrecognized signature scheme: ${scheme}`);
  }
  const suffix = scheme.slice(PREFIX.length);
  const n = Number(suffix);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`Malformed signature scheme version: ${scheme}`);
  }
  return n;
}

/**
 * Build the signable dict for a constitution.
 *
 * signingVersion=1 dispatches to the frozen v1 form (legacy verification).
 * signingVersion=2 (default) dispatches to the v2 unified canonical form (SAN-492).
 */
export function constitutionToSignableDict(c: Constitution, signingVersion: number = 2): Record<string, unknown> {
  if (signingVersion === 1) return _constitutionToSignableDictV1(c);
  if (signingVersion === 2) return _constitutionToSignableDictV2(c);
  throw new Error(`Unsupported signing_version: ${signingVersion}`);
}

/**
 * Compute the canonical signable JSON string for a Constitution.
 *
 * signingVersion defaults to 2 (v2 unified canonical form, SAN-492).
 * Pass signingVersion=1 to reproduce the frozen v1 byte sequence.
 */
export function computeCanonicalSignableJson(constitution: Constitution, signingVersion: number = 2): string {
  const signableDict = constitutionToSignableDict(constitution, signingVersion);
  const sanitized = sanitizeForSigning(signableDict);
  return canonicalize(sanitized);
}

/**
 * Verify a constitution's Ed25519 signature.
 *
 * Reads signature.scheme and dispatches to the matching signing version.
 * Unrecognized, malformed, or unsupported schemes return false (preserving
 * the boolean return contract for callers).
 *
 * Returns false for unsigned constitutions.
 */
export function verifyConstitutionSignature(
  constitution: Constitution,
  publicKey: KeyObject,
): boolean {
  const sig = constitution.provenance.signature;
  if (!sig || !sig.value) return false;

  const expectedKeyId = getKeyId(publicKey);
  if (sig.key_id !== expectedKeyId) return false;

  let signableDict: Record<string, unknown>;
  try {
    const version = _parseSigningVersion(sig.scheme);
    signableDict = constitutionToSignableDict(constitution, version);
  } catch {
    // Unrecognized scheme, malformed scheme, or unsupported version: not verifiable
    return false;
  }

  const sanitized = sanitizeForSigning(signableDict);
  const canonical = canonicalize(sanitized);
  const data = Buffer.from(canonical, "utf-8");

  return verify(data, sig.value, publicKey);
}

// ── Constitution signing ─────────────────────────────────────────────

/**
 * Compute policy_hash and add Ed25519 signature to a constitution.
 *
 * signingVersion defaults to 2 (SAN-492). Pass signingVersion=1 only to
 * re-sign legacy constitutions under the v1 canonical form.
 *
 * Returns a new constitution object with provenance.signature populated.
 */
export function signConstitution(
  constitution: Constitution,
  privateKey: KeyObject,
  signedBy: string,
  signingVersion: number = 2,
): Constitution {
  const keyId = getKeyId(privateKey);

  const sigBlock: ConstitutionSignature = {
    value: "",
    key_id: keyId,
    signed_by: signedBy,
    signed_at: new Date().toISOString(),
    scheme: "constitution_sig_v" + signingVersion,
  };

  const signed: Constitution = structuredClone(constitution);
  signed.provenance = { ...signed.provenance, signature: sigBlock };

  // Pass 1: compute policy_hash (signable dict still has policy_hash=null)
  const preDict = constitutionToSignableDict(signed, signingVersion);
  const preSanitized = sanitizeForSigning(preDict);
  signed.policy_hash = hashObj(preSanitized);

  // Pass 2: rebuild signable dict with correct policy_hash, then sign
  const signableDict = constitutionToSignableDict(signed, signingVersion);
  const sanitized = sanitizeForSigning(signableDict);
  const canonical = canonicalize(sanitized);
  const data = Buffer.from(canonical, "utf-8");
  const signatureB64 = sign(data, privateKey);

  signed.provenance.signature!.value = signatureB64;

  return signed;
}

/**
 * Serialize a constitution to YAML and write to a file.
 */
export function saveConstitution(constitution: Constitution, path: string): void {
  const dir = dirname(path);
  if (dir) mkdirSync(dir, { recursive: true });

  // signingVersion=1: preserve existing customer-visible YAML output (SAN-492)
  const dict = constitutionToSignableDict(constitution, 1);

  // Restore actual signature value (_constitutionToSignableDictV1 blanks it)
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
