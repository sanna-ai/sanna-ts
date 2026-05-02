/**
 * Authority decision recording infrastructure.
 *
 * Helpers for constructing authority_decisions[i] records that satisfy the
 * AuthorityDecisionRecord schema in receipt.schema.json. Recording
 * infrastructure only -- authority evaluation logic lives in the interceptor-
 * specific modules (interceptors/api-authority.ts, interceptors/cli-authority.ts).
 */

/**
 * Construct an authority_decisions[i] record with decision=modify_with_constraints.
 *
 * Returns an object matching AuthorityDecisionRecord in the receipt schema,
 * populated with the three MODIFY recording fields (tool_input_original,
 * tool_input_transformed, transformations_applied) per spec Section 2.7.
 *
 * Validates at construction time:
 * - transformations is a non-empty array
 * - each transformation has exactly {type, target_field, rationale}
 * - original and transformed are string or plain object (not null, not array)
 *
 * boundary_type is "can_execute": MODIFY proceeds with the action (transformed
 * input) so it sits under the can_execute boundary. The decision field carries
 * the MODIFY granularity. Schema enum on boundary_type does not include a
 * separate MODIFY value (spec line 870).
 *
 * SAN-369 ships this recording infrastructure. Constitution-rule-driven
 * emission (evaluateAuthority returning modify_with_constraints) is a separate
 * follow-up ticket.
 *
 * Cross-SDK byte-equal parity with Python's build_modify_authority_decision
 * (sanna-repo c2c6a39): identical inputs produce identical record shape, key
 * order, and value semantics.
 */
export function buildModifyAuthorityDecision(
  action: string,
  original: string | Record<string, unknown>,
  transformed: string | Record<string, unknown>,
  transformations: Array<{ type: string; target_field: string; rationale: string }>,
  options?: { reason?: string; timestamp?: string },
): {
  action: string;
  decision: "modify_with_constraints";
  reason: string;
  boundary_type: "can_execute";
  timestamp: string;
  tool_input_original: string | Record<string, unknown>;
  tool_input_transformed: string | Record<string, unknown>;
  transformations_applied: Array<{ type: string; target_field: string; rationale: string }>;
} {
  if (!Array.isArray(transformations) || transformations.length === 0) {
    throw new Error(
      "transformations must be a non-empty array of {type, target_field, rationale} objects",
    );
  }

  const requiredKeys = ["type", "target_field", "rationale"] as const;
  transformations.forEach((t, i) => {
    if (t === null || typeof t !== "object" || Array.isArray(t)) {
      throw new Error(`transformations[${i}] must be an object, got ${typeof t}`);
    }
    const keys = Object.keys(t);
    const missing = requiredKeys.filter((k) => !keys.includes(k));
    if (missing.length > 0) {
      throw new Error(
        `transformations[${i}] missing required keys: ${JSON.stringify(missing.sort())}`,
      );
    }
    const extra = keys.filter((k) => !(requiredKeys as readonly string[]).includes(k));
    if (extra.length > 0) {
      throw new Error(
        `transformations[${i}] has unexpected keys: ${JSON.stringify(extra.sort())} (only ${JSON.stringify([...requiredKeys].sort())} permitted)`,
      );
    }
  });

  const isPlainObject = (v: unknown): v is Record<string, unknown> =>
    v !== null && typeof v === "object" && !Array.isArray(v);

  if (typeof original !== "string" && !isPlainObject(original)) {
    throw new Error(
      `original must be string or object, got ${original === null ? "null" : Array.isArray(original) ? "array" : typeof original}`,
    );
  }
  if (typeof transformed !== "string" && !isPlainObject(transformed)) {
    throw new Error(
      `transformed must be string or object, got ${transformed === null ? "null" : Array.isArray(transformed) ? "array" : typeof transformed}`,
    );
  }

  const timestamp = options?.timestamp ?? new Date().toISOString();
  const reason = options?.reason ?? `MODIFY: action '${action}' parameters transformed`;

  // Construct with explicit key order matching Python helper output (sanna-repo c2c6a39):
  // action, decision, reason, boundary_type, timestamp, tool_input_original,
  // tool_input_transformed, transformations_applied.
  return {
    action,
    decision: "modify_with_constraints",
    reason,
    boundary_type: "can_execute",
    timestamp,
    tool_input_original: original,
    tool_input_transformed: transformed,
    transformations_applied: transformations,
  };
}
