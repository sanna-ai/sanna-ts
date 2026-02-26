/**
 * Custom invariant evaluator registry.
 *
 * Allows users to register functions as evaluators for custom invariants.
 * When a constitution defines an invariant that has no built-in check,
 * the registry is consulted before falling through to UNKNOWN_TYPE.
 */

import type { Constitution, CheckResult } from "./types.js";

export type InvariantEvaluatorFn = (
  context: string,
  output: string,
  constitution: Constitution,
  checkConfig: Record<string, unknown>,
) => CheckResult;

const _EVALUATOR_REGISTRY = new Map<string, InvariantEvaluatorFn>();

/**
 * Register a function as the evaluator for an invariant ID.
 * Throws if the invariant ID is already registered.
 */
export function registerInvariantEvaluator(
  invariantId: string,
  evaluator: InvariantEvaluatorFn,
): void {
  if (_EVALUATOR_REGISTRY.has(invariantId)) {
    throw new Error(
      `Evaluator already registered for invariant '${invariantId}'`,
    );
  }
  _EVALUATOR_REGISTRY.set(invariantId, evaluator);
}

/**
 * Get the registered evaluator for an invariant ID, or undefined.
 */
export function getEvaluator(
  invariantId: string,
): InvariantEvaluatorFn | undefined {
  return _EVALUATOR_REGISTRY.get(invariantId);
}

/**
 * List all registered invariant IDs.
 */
export function listEvaluators(): string[] {
  return [..._EVALUATOR_REGISTRY.keys()];
}

/**
 * Remove all registered evaluators. For test isolation.
 */
export function clearEvaluators(): void {
  _EVALUATOR_REGISTRY.clear();
}
