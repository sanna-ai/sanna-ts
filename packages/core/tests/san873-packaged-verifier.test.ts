/**
 * SAN-873: verifyReceipt must work from a PUBLISHED install (ESM and CJS),
 * with no runtime filesystem read, and must still ENFORCE the receipt
 * schema (not silently accept schema-invalid receipts).
 *
 * Pre-fix, getAjvValidator() in src/verifier.ts loaded receipt.schema.json
 * at runtime via readFileSync(resolve(dirname(fileURLToPath(import.meta.url)),
 * "../../../spec/schemas/receipt.schema.json")). That path only resolves
 * inside this repo tree -- the spec/ git submodule is not shipped in the
 * npm tarball (packages/core/package.json `files` only lists dist,
 * README.md, LICENSE) -- so every published install returned
 * verifyReceipt(...).valid === false for EVERY receipt, valid or not. The
 * CJS build additionally threw before reaching readFileSync: tsup shims
 * import.meta as {} for CJS output, so import.meta.url is undefined and
 * fileURLToPath(undefined) throws ERR_INVALID_ARG_TYPE.
 *
 * This defect is invisible to an in-repo `import { verifyReceipt } from
 * "../src/verifier.js"` test (see verifier.test.ts) because the repo tree
 * always has spec/ present at the relative path the old code resolved.
 * It is only observable by installing the ACTUAL packed npm tarball
 * somewhere that does not have a spec/ submodule alongside it -- which is
 * exactly what every real downstream consumer does. This test packs the
 * already-built dist (`npm pack`), installs the tarball OFFLINE into a
 * fresh temp directory outside the repo tree, and drives verifyReceipt
 * from spawned ESM and CJS consumer scripts that only ever `import`/
 * `require("@sanna-ai/core")` -- exactly like a real consumer would.
 *
 * Manually captured evidence that this reproduces the PRE-FIX defect
 * (both module systems returned valid:false with a
 * "Schema validation internal error" ENOENT / ERR_INVALID_ARG_TYPE
 * message) is recorded in the SAN-873 PR description; git-stashing the
 * fix to re-run this exact suite against the pre-fix build is
 * intentionally not done here per the no-git-stash hard constraint.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const coreDir = resolve(__dirname, ".."); // packages/core

// ── Spawned consumer scripts ─────────────────────────────────────────
//
// Each script imports/requires ONLY "@sanna-ai/core" (package-name
// resolution through node_modules, not a relative src/dist path) so it
// exercises exactly what a downstream consumer's module resolution does.
//
// Case "valid_receipt": a freshly generated + signed valid receipt must
// verify true with no schema-load error (assertion 1).
//
// Case "positive_control" (ESM only): proves the bundled schema is a REAL,
// ENFORCING schema and not an empty/permissive stand-in (assertion 2).
// It uses allOf rule index 16 ("CFC-A: enforcement.halt_reason present
// requires enforcement.action=halted", spec Section 4.6) -- a CONDITIONAL
// if/then rule, not an unconditional required-field rule already covered
// by the hand-rolled checks in verifier.ts (grep confirms "halt_reason"
// and "constitution_status_evidence" appear nowhere in verifier.ts /
// verifier-manifest.ts). The receipt satisfies the `if` (enforcement.
// halt_reason is present as a string) but violates the `then`
// (enforcement.action must be the const "halted"; this receipt uses
// "warned", which receipt generation's own PASS-status override makes
// internally self-consistent with status=WARN, so the hand-rolled
// status-consistency check in checkStatusConsistency does NOT also fire).
// The result is a receipt that is valid per every hand-rolled check and
// correctly signed, isolating the ajv/schema-only enforcement path.

const ESM_SCRIPT = `
import { generateKeypair, generateReceipt, signReceipt, verifyReceipt } from "@sanna-ai/core";

const { privateKey, publicKey } = generateKeypair();

const validReceipt = generateReceipt({
  correlation_id: "san873-valid-esm",
  inputs: { query: "What is 2+2?", context: "Math" },
  outputs: { response: "4" },
  checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
});
signReceipt(validReceipt, privateKey, "san873-test@sanna.dev");
const validResult = verifyReceipt(validReceipt, publicKey);
console.log(JSON.stringify({ case: "valid_receipt", valid: validResult.valid, errors: validResult.errors }));

const controlReceipt = generateReceipt({
  correlation_id: "san873-positive-control-esm",
  inputs: { query: "What is 2+2?", context: "Math" },
  outputs: { response: "4" },
  checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
  enforcement: { action: "warned", halt_reason: "test_halt_reason_san873" },
});
signReceipt(controlReceipt, privateKey, "san873-test@sanna.dev");
const controlResult = verifyReceipt(controlReceipt, publicKey);
console.log(JSON.stringify({ case: "positive_control", valid: controlResult.valid, errors: controlResult.errors }));
`;

const CJS_SCRIPT = `
const { generateKeypair, generateReceipt, signReceipt, verifyReceipt } = require("@sanna-ai/core");

const { privateKey, publicKey } = generateKeypair();

const validReceipt = generateReceipt({
  correlation_id: "san873-valid-cjs",
  inputs: { query: "What is 2+2?", context: "Math" },
  outputs: { response: "4" },
  checks: [{ check_id: "C1", passed: true, severity: "info", evidence: null }],
});
signReceipt(validReceipt, privateKey, "san873-test@sanna.dev");
const validResult = verifyReceipt(validReceipt, publicKey);
console.log(JSON.stringify({ case: "valid_receipt", valid: validResult.valid, errors: validResult.errors }));
`;

interface CaseResult {
  case: string;
  valid: boolean;
  errors: string[];
}

function parseCaseLines(stdout: string): CaseResult[] {
  return stdout
    .trim()
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as CaseResult);
}

describe("SAN-873: packaged verifier is self-contained (schema bundled into dist)", () => {
  let workDir: string;

  beforeAll(() => {
    // Pack the already-built dist. CI and the Phase 4 local gate both run
    // `npm run build --workspace @sanna-ai/core` (or `npm run build`)
    // before the test suite, so dist/ reflects the current source.
    workDir = mkdtempSync(join(tmpdir(), "san873-pkg-test-"));

    const packResult = spawnSync(
      "npm",
      ["pack", "--json", "--pack-destination", workDir],
      { cwd: coreDir, encoding: "utf-8" },
    );
    if (packResult.status !== 0) {
      throw new Error(`npm pack failed (exit ${packResult.status}): ${packResult.stderr}`);
    }
    const packInfo = JSON.parse(packResult.stdout) as Array<{ filename: string }>;
    const tgzPath = join(workDir, packInfo[0].filename);

    // Minimal package.json for the install target -- avoids depending on
    // `npm init` behavior/prompts.
    writeFileSync(
      join(workDir, "package.json"),
      JSON.stringify({ name: "san873-pkg-test", version: "0.0.0", private: true }, null, 2),
    );

    // Cache-first install of the packed tarball's runtime deps (adm-zip,
    // ajv, ajv-formats, better-sqlite3, canonicalize, js-yaml,
    // safe-regex2). `--prefer-offline` uses the npm cache when a dep is
    // present and falls back to the registry only for what is missing:
    // locally a prior `npm ci` has already cached everything (no network),
    // while in CI the download cache is not guaranteed to hold these
    // tarballs (node_modules is often restored from actions/cache without
    // repopulating the download cache), so a strict `--offline`
    // (cache-only) install would ENOTCACHED-fail there. If beforeAll
    // throws, vitest marks this file's assertions as SKIPPED (not failed)
    // -- a skipped security assertion reads as enforced but is not -- so
    // the throw below is deliberately loud and this must never be softened
    // into a skip-to-green. `--ignore-scripts` skips better-sqlite3's
    // native postinstall build: the verify path never touches sqlite and
    // core lazy-loads it, so the build is unnecessary for reaching
    // verifyReceipt and only adds a flaky native-toolchain dependency to
    // the temp install.
    const installResult = spawnSync(
      "npm",
      ["install", tgzPath, "--prefer-offline", "--no-save", "--ignore-scripts"],
      { cwd: workDir, encoding: "utf-8" },
    );
    if (installResult.status !== 0) {
      throw new Error(
        `npm install --prefer-offline failed (exit ${installResult.status}). This setup ` +
          `MUST fail loud, never skip-to-green: the assertions guarding the packaged ` +
          `verifier are security assertions. stderr:\n${installResult.stderr}`,
      );
    }

    writeFileSync(join(workDir, "t.mjs"), ESM_SCRIPT);
    writeFileSync(join(workDir, "t.cjs"), CJS_SCRIPT);
  }, 60000);

  afterAll(() => {
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  });

  it(
    "ESM: valid receipt verifies true with no schema-load error, and a schema-violating receipt (CFC-A: allOf[16]) is rejected by the bundled, enforcing schema",
    () => {
      const result = spawnSync("node", ["t.mjs"], { cwd: workDir, encoding: "utf-8" });
      expect(result.status, `node t.mjs failed. stderr:\n${result.stderr}`).toBe(0);
      const cases = parseCaseLines(result.stdout);

      // Assertion 1: valid receipt verifies true, no internal schema-load error.
      const validCase = cases.find((c) => c.case === "valid_receipt");
      expect(validCase).toBeDefined();
      expect(validCase!.valid).toBe(true);
      expect(validCase!.errors).toEqual([]);
      expect(
        validCase!.errors.some((e) => e.includes("Schema validation internal error")),
      ).toBe(false);

      // Assertion 2 (positive control): the bundled schema actively rejects
      // a receipt that violates a real conditional allOf rule, with a
      // genuine ajv/schema-validation error -- not the pre-fix internal
      // ENOENT/ERR_INVALID_ARG_TYPE error, and not an empty/permissive
      // schema silently accepting it.
      const controlCase = cases.find((c) => c.case === "positive_control");
      expect(controlCase).toBeDefined();
      expect(controlCase!.valid).toBe(false);
      expect(
        controlCase!.errors.some(
          (e) => e.startsWith("Schema validation failed:") && e.includes("action"),
        ),
      ).toBe(true);
      expect(
        controlCase!.errors.some((e) => e.includes("Schema validation internal error")),
      ).toBe(false);
    },
    30000,
  );

  it(
    "CJS: valid receipt verifies true with no schema-load error (proves the import.meta.url-undefined crash is fixed)",
    () => {
      const result = spawnSync("node", ["t.cjs"], { cwd: workDir, encoding: "utf-8" });
      expect(result.status, `node t.cjs failed. stderr:\n${result.stderr}`).toBe(0);
      const cases = parseCaseLines(result.stdout);

      const validCase = cases.find((c) => c.case === "valid_receipt");
      expect(validCase).toBeDefined();
      expect(validCase!.valid).toBe(true);
      expect(validCase!.errors).toEqual([]);
      expect(
        validCase!.errors.some((e) => e.includes("Schema validation internal error")),
      ).toBe(false);
    },
    30000,
  );
});
