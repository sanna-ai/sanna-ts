import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/authority.ts"],
  format: ["esm", "cjs"],
  // tsup's rollup.ts unconditionally injects `baseUrl: process.cwd()` into the
  // DTS pipeline (https://github.com/egoist/tsup/issues/1388). TS 6 promotes
  // the baseUrl deprecation to a hard error (TS5101). Scope the suppression
  // to this dts pipeline only — root tsconfig stays strict on deprecations.
  // Remove this once tsup ships PR #1390 (https://github.com/egoist/tsup/pull/1390).
  // Tracked: SAN-257.
  dts: {
    compilerOptions: {
      ignoreDeprecations: "6.0",
    },
  },
  clean: true,
  sourcemap: true,
  external: ["better-sqlite3"],
  noExternal: ["canonicalize", "safe-regex2"],
});
