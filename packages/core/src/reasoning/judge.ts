/**
 * Abstract judge interface for reasoning evaluation.
 * Provider-agnostic contract that all judge implementations must satisfy.
 */

export enum JudgeVerdict {
  PASS = "pass",
  FAIL = "fail",
  ERROR = "error",
  HEURISTIC = "heuristic",
}

export interface JudgeResult {
  score: number; // 0.0-1.0, higher = more aligned
  verdict: JudgeVerdict;
  method: string; // "heuristic", "anthropic_llm", etc.
  explanation: string;
  latencyMs: number;
  errorDetail?: string; // Present only when verdict is ERROR
}

export interface BaseJudge {
  evaluate(
    toolName: string,
    args: Record<string, unknown>,
    justification: string,
    invariantId: string,
    constitutionContext?: Record<string, unknown>,
  ): Promise<JudgeResult>;

  providerName(): string;
}
