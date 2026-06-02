import { execFileSync } from "node:child_process";
import { strict as assert } from "node:assert";
import { describe, test } from "vitest";

function git(args: string[], cwd?: string): { code: number; stderr: string } {
  try {
    execFileSync("git", args, { cwd, encoding: "utf8" });
    return { code: 0, stderr: "" };
  } catch (e: any) {
    return { code: e.status ?? 1, stderr: String(e.stderr ?? "") };
  }
}

describe("spec submodule integrity (SAN-667 cross-SDK parity)", () => {
  test("spec pin is reachable on sanna-protocol origin/main", (ctx) => {
    const root = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();
    // committed gitlink SHA (source of truth, independent of checkout state)
    const pin = execFileSync("git", ["-C", root, "ls-tree", "HEAD", "spec"], { encoding: "utf8" }).trim().split(/\s+/)[2];
    const spec = `${root}/spec`;
    const fetched = git(["-C", spec, "fetch", "origin", "main"]);
    if (fetched.code !== 0) {
      // Never silently skip in the enforcement environment; a CI network blip must fail loudly.
      if (process.env.CI || process.env.GITHUB_ACTIONS) {
        throw new Error(`could not fetch sanna-protocol origin/main to verify pin: ${fetched.stderr}`);
      }
      ctx.skip();
      return;
    }
    // Assumption: this repo tracks sanna-protocol `main`. If protocol ever adopts
    // release/maintenance branches this repo should track instead, broaden this
    // origin/main assertion to the relevant branch.
    const reachable = git(["-C", spec, "merge-base", "--is-ancestor", pin, "origin/main"]).code === 0;
    assert.ok(reachable, `spec submodule pin ${pin} is NOT reachable on sanna-protocol origin/main (dangling/unmerged PR-branch commit). Re-pin to a commit merged to protocol main.`);
  });
});
