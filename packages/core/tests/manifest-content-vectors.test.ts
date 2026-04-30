import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseConstitution, generateManifest } from "../src/index.js";

const VECTORS_PATH = resolve(import.meta.dirname, "../../../spec/fixtures/manifest-content-vectors.json");
const VECTORS = JSON.parse(readFileSync(VECTORS_PATH, "utf-8")).vectors;

describe("SAN-209 manifest content vectors (cross-SDK fixtures)", () => {
  for (const vec of VECTORS) {
    it(`${vec.id}: ${vec.description}`, () => {
      const inp = vec.input;
      const expected = vec.expected;
      const consDict = inp.constitution;
      const cons = consDict !== null ? parseConstitution(consDict) : null;

      const actual = generateManifest(
        cons,
        inp.mcp_tools ?? undefined,
        inp.surfaces_filter ?? undefined,
      );

      expect(actual).toEqual(expected);
    });
  }
});
