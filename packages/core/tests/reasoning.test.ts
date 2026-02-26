import { describe, it, expect } from "vitest";
import {
  JudgeVerdict,
  HeuristicJudge,
  ReasoningPipeline,
} from "../src/reasoning/index.js";

// ── HeuristicJudge ──────────────────────────────────────────────────

describe("HeuristicJudge", () => {
  const judge = new HeuristicJudge();

  it("should pass a well-formed justification", async () => {
    const result = await judge.evaluate(
      "delete_file",
      { path: "/tmp/test.txt" },
      "Calling delete_file to remove the temporary artifact left over from the build step.",
      "reasoning_quality",
    );

    expect(result.score).toBe(1.0);
    expect(result.verdict).toBe(JudgeVerdict.HEURISTIC);
    expect(result.method).toBe("heuristic");
    expect(result.explanation).toBe("All heuristic checks passed");
  });

  it("should fail an empty justification", async () => {
    const result = await judge.evaluate(
      "delete_file",
      {},
      "",
      "reasoning_quality",
    );

    expect(result.score).toBe(0.0);
    expect(result.verdict).toBe(JudgeVerdict.FAIL);
  });

  it("should fail a too-short justification", async () => {
    const result = await judge.evaluate(
      "delete_file",
      {},
      "ok",
      "reasoning_quality",
    );

    expect(result.score).toBe(0.0);
    expect(result.verdict).toBe(JudgeVerdict.FAIL);
    expect(result.explanation).toContain("minimum_substance");
  });

  it("should detect parroting", async () => {
    const result = await judge.evaluate(
      "delete_file",
      {},
      "I did this because you asked me to do it and that is the reason.",
      "reasoning_quality",
    );

    expect(result.score).toBe(0.0);
    expect(result.verdict).toBe(JudgeVerdict.FAIL);
    expect(result.explanation).toContain("no_parroting");
  });

  it("should give partial credit for missing action reference", async () => {
    const result = await judge.evaluate(
      "delete_file",
      {},
      "Removing the temporary artifact left over from the build step to clean up workspace.",
      "reasoning_quality",
    );

    expect(result.score).toBe(0.5);
    expect(result.verdict).toBe(JudgeVerdict.HEURISTIC);
    expect(result.explanation).toContain("action_reference");
  });

  it("should use custom blocklist", async () => {
    const custom = new HeuristicJudge({
      blocklist: ["just doing my job"],
    });

    const result = await custom.evaluate(
      "send_email",
      {},
      "Running send_email because I am just doing my job here.",
      "reasoning_quality",
    );

    expect(result.score).toBe(0.0);
    expect(result.explanation).toContain("just doing my job");
  });

  it("should use custom minimum length", async () => {
    const custom = new HeuristicJudge({ minLength: 5 });

    const result = await custom.evaluate(
      "run_query",
      {},
      "run_query needed",
      "reasoning_quality",
    );

    // Length is 16 >= 5, tool name present, no blocklist → all pass
    expect(result.score).toBe(1.0);
    expect(result.verdict).toBe(JudgeVerdict.HEURISTIC);
  });

  it("should measure latency", async () => {
    const result = await judge.evaluate(
      "test_tool",
      {},
      "Calling test_tool to verify the integration is working correctly.",
      "reasoning_quality",
    );

    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(typeof result.latencyMs).toBe("number");
  });
});

// ── ReasoningPipeline ───────────────────────────────────────────────

describe("ReasoningPipeline", () => {
  it("should evaluate with heuristic judge", async () => {
    const pipeline = new ReasoningPipeline({
      judge: new HeuristicJudge(),
    });

    const result = await pipeline.evaluate(
      "delete_file",
      { path: "/tmp/test.txt" },
      "Calling delete_file to remove the temporary artifact left over from the build step.",
    );

    expect(result.score).toBe(1.0);
    expect(result.verdict).toBe(JudgeVerdict.PASS);
    expect(result.method).toBe("heuristic");
    expect(result.explanation).toBeTruthy();
    expect(result.latencyMs).toBeGreaterThanOrEqual(0);
    expect(result.checks).toBeDefined();
  });

  it("should apply pass threshold", async () => {
    const pipeline = new ReasoningPipeline({
      judge: new HeuristicJudge(),
      passThreshold: 0.5,
    });

    // Justification with tool name missing → score 0.5 → meets passThreshold
    const result = await pipeline.evaluate(
      "delete_file",
      {},
      "Removing the temporary artifact left over from the build step to clean up workspace.",
    );

    expect(result.score).toBe(0.5);
    expect(result.verdict).not.toBe(JudgeVerdict.FAIL);
  });

  it("should apply fail threshold", async () => {
    const pipeline = new ReasoningPipeline({
      judge: new HeuristicJudge(),
      failThreshold: 0.3,
    });

    // Empty justification → score 0.0 → below failThreshold
    const result = await pipeline.evaluate(
      "delete_file",
      {},
      "",
    );

    expect(result.score).toBe(0.0);
    expect(result.verdict).toBe(JudgeVerdict.FAIL);
  });

  it("should include checks array in result", async () => {
    const pipeline = new ReasoningPipeline({
      judge: new HeuristicJudge(),
    });

    const result = await pipeline.evaluate(
      "test_tool",
      {},
      "Calling test_tool to verify the integration is working correctly.",
    );

    expect(Array.isArray(result.checks)).toBe(true);
    expect(result.checks.length).toBeGreaterThan(0);
    for (const check of result.checks) {
      expect(check).toHaveProperty("checkId");
      expect(check).toHaveProperty("passed");
      expect(check).toHaveProperty("score");
      expect(check).toHaveProperty("detail");
    }
  });
});
