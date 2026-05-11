/**
 * SAN-493: regression guard that state.md header does not embed git SHA.
 *
 * Pre-fix, tools/generate-state-doc.ts embedded `git-sha: <12-char>` in
 * the state.md header. The SHA was always one-commit-stale because regen
 * runs pre-commit (per the sealed-gate pattern, HEAD at regen time is
 * the parent commit's SHA, never the SHA of the commit landing the
 * state.md update). Post-fix, the SHA is dropped entirely; commit SHAs
 * live only in git log.
 *
 * This test reads the committed state.md without invoking the regen
 * command, so it has no side effects on the file. The test PASSES on
 * the PR branch (state.md regenerated to drop SHA) and would FAIL on
 * origin/main pre-fix (state.md line 2 contains `git-sha:`).
 */
import { describe, it, expect } from "vitest";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

describe("SAN-493: state.md header", () => {
  it("does not contain git-sha substring (header dropped per SAN-493)", () => {
    const root = execSync("git rev-parse --show-toplevel", { encoding: "utf8" }).trim();
    const content = readFileSync(join(root, "docs", "state.md"), "utf8");
    const header = content.split("\n").slice(0, 5).join("\n");
    expect(header).not.toContain("git-sha");
  });
});
