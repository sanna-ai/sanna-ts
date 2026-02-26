import { describe, it, expect, afterEach, vi } from "vitest";
import {
  LLMJudge,
  enableLlmChecks,
  registerLlmEvaluators,
  LLMEvaluationError,
} from "../src/evaluators/llm.js";
import {
  getEvaluator,
  listEvaluators,
  clearEvaluators,
} from "../src/evaluator-registry.js";
import type { Constitution } from "../src/types.js";

const EMPTY_CONSTITUTION = {} as Constitution;

afterEach(() => {
  clearEvaluators();
  vi.restoreAllMocks();
});

function mockFetchSuccess(pass: boolean, confidence: number, evidence: string) {
  return vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      content: [
        {
          type: "text",
          text: JSON.stringify({ pass, confidence, evidence }),
        },
      ],
    }),
  });
}

describe("enableLlmChecks", () => {
  it("should register all 5 evaluators via enableLlmChecks", () => {
    enableLlmChecks({ apiKey: "test-key" });
    const ids = listEvaluators();
    expect(ids).toHaveLength(5);
    expect(ids).toContain("INV_LLM_CONTEXT_GROUNDING");
    expect(ids).toContain("INV_LLM_FABRICATION_DETECTION");
    expect(ids).toContain("INV_LLM_INSTRUCTION_ADHERENCE");
    expect(ids).toContain("INV_LLM_FALSE_CERTAINTY");
    expect(ids).toContain("INV_LLM_PREMATURE_COMPRESSION");
  });

  it("should register a subset of evaluators", () => {
    enableLlmChecks({ apiKey: "test-key", checks: ["LLM_C1", "LLM_C3"] });
    const ids = listEvaluators();
    expect(ids).toHaveLength(2);
    expect(ids).toContain("INV_LLM_CONTEXT_GROUNDING");
    expect(ids).toContain("INV_LLM_INSTRUCTION_ADHERENCE");
  });

  it("should be idempotent", () => {
    enableLlmChecks({ apiKey: "test-key" });
    enableLlmChecks({ apiKey: "test-key" });
    const ids = listEvaluators();
    expect(ids).toHaveLength(5);
  });

  it("should throw on unknown check alias", () => {
    expect(() =>
      enableLlmChecks({ apiKey: "test-key", checks: ["LLM_C99"] }),
    ).toThrow("Unknown LLM check alias: LLM_C99");
  });
});

describe("LLMJudge", () => {
  it("should parse successful API response", async () => {
    vi.stubGlobal("fetch", mockFetchSuccess(true, 0.95, "grounded"));

    const judge = new LLMJudge({ apiKey: "test-key" });
    registerLlmEvaluators(judge, ["LLM_C1"]);

    const evaluator = getEvaluator("INV_LLM_CONTEXT_GROUNDING")!;
    const result = await (evaluator as Function)(
      "some context",
      "some output",
      EMPTY_CONSTITUTION,
      {},
    );

    expect(result.passed).toBe(true);
    expect(result.check_impl).toBe("llm_judge");
    expect(result.check_id).toBe("INV_LLM_CONTEXT_GROUNDING");
  });

  it("should throw LLMEvaluationError on API failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network error")),
    );

    const judge = new LLMJudge({ apiKey: "test-key" });
    registerLlmEvaluators(judge, ["LLM_C1"]);

    const evaluator = getEvaluator("INV_LLM_CONTEXT_GROUNDING")!;
    await expect(
      (evaluator as Function)("ctx", "out", EMPTY_CONSTITUTION, {}),
    ).rejects.toThrow(LLMEvaluationError);
  });

  it("should throw LLMEvaluationError on malformed response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [{ type: "text", text: "not json at all" }],
        }),
      }),
    );

    const judge = new LLMJudge({ apiKey: "test-key" });
    registerLlmEvaluators(judge, ["LLM_C1"]);

    const evaluator = getEvaluator("INV_LLM_CONTEXT_GROUNDING")!;
    await expect(
      (evaluator as Function)("ctx", "out", EMPTY_CONSTITUTION, {}),
    ).rejects.toThrow(LLMEvaluationError);
  });

  it("should throw LLMEvaluationError when 'pass' field is missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          content: [
            {
              type: "text",
              text: JSON.stringify({ confidence: 0.8, evidence: "something" }),
            },
          ],
        }),
      }),
    );

    const judge = new LLMJudge({ apiKey: "test-key" });
    registerLlmEvaluators(judge, ["LLM_C1"]);

    const evaluator = getEvaluator("INV_LLM_CONTEXT_GROUNDING")!;
    await expect(
      (evaluator as Function)("ctx", "out", EMPTY_CONSTITUTION, {}),
    ).rejects.toThrow(LLMEvaluationError);
  });

  it("should use ANTHROPIC_API_KEY env var as fallback", () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    try {
      process.env.ANTHROPIC_API_KEY = "test-env-key";
      const judge = new LLMJudge();
      expect(judge).toBeDefined();
    } finally {
      if (saved) {
        process.env.ANTHROPIC_API_KEY = saved;
      } else {
        delete process.env.ANTHROPIC_API_KEY;
      }
    }
  });

  it("should throw if no API key available", () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    try {
      delete process.env.ANTHROPIC_API_KEY;
      expect(() => new LLMJudge()).toThrow("No API key");
    } finally {
      if (saved) {
        process.env.ANTHROPIC_API_KEY = saved;
      }
    }
  });
});
