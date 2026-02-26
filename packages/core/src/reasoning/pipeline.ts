/**
 * Reasoning evaluation pipeline.
 *
 * Orchestrates judge evaluation with threshold-based verdict mapping.
 */

import { JudgeVerdict, type BaseJudge, type JudgeResult } from "./judge.js";

export interface ReasoningPipelineOptions {
  judge: BaseJudge;
  passThreshold?: number; // default: 0.5
  failThreshold?: number; // default: 0.3
}

export interface ReasoningResult {
  score: number;
  verdict: JudgeVerdict;
  method: string;
  explanation: string;
  latencyMs: number;
  checks: Array<{
    checkId: string;
    passed: boolean;
    score: number;
    detail: string;
  }>;
}

export class ReasoningPipeline {
  private readonly judge: BaseJudge;
  private readonly passThreshold: number;
  private readonly failThreshold: number;

  constructor(options: ReasoningPipelineOptions) {
    this.judge = options.judge;
    this.passThreshold = options.passThreshold ?? 0.5;
    this.failThreshold = options.failThreshold ?? 0.3;
  }

  async evaluate(
    toolName: string,
    args: Record<string, unknown>,
    justification: string,
    constitutionContext?: Record<string, unknown>,
  ): Promise<ReasoningResult> {
    const judgeResult: JudgeResult = await this.judge.evaluate(
      toolName,
      args,
      justification,
      "reasoning_quality",
      constitutionContext,
    );

    // Apply threshold logic to determine final verdict
    let verdict: JudgeVerdict;
    if (judgeResult.verdict === JudgeVerdict.ERROR) {
      verdict = JudgeVerdict.ERROR;
    } else if (judgeResult.score >= this.passThreshold) {
      verdict = JudgeVerdict.PASS;
    } else if (judgeResult.score < this.failThreshold) {
      verdict = JudgeVerdict.FAIL;
    } else {
      verdict = JudgeVerdict.HEURISTIC;
    }

    // Build checks array from explanation
    const checks = this.parseChecks(judgeResult);

    return {
      score: judgeResult.score,
      verdict,
      method: judgeResult.method,
      explanation: judgeResult.explanation,
      latencyMs: judgeResult.latencyMs,
      checks,
    };
  }

  private parseChecks(
    result: JudgeResult,
  ): ReasoningResult["checks"] {
    // If explanation contains semicolon-separated sub-check results, parse them
    if (result.explanation === "All heuristic checks passed") {
      return [
        {
          checkId: "reasoning_quality",
          passed: true,
          score: result.score,
          detail: result.explanation,
        },
      ];
    }

    const parts = result.explanation.split("; ");
    return parts.map((part) => {
      const colonIdx = part.indexOf(": ");
      const checkId = colonIdx >= 0 ? part.slice(0, colonIdx) : "reasoning_quality";
      const detail = colonIdx >= 0 ? part.slice(colonIdx + 2) : part;
      return {
        checkId,
        passed: false,
        score: 0.0,
        detail,
      };
    });
  }
}
