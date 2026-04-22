import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import { matchesAction } from "../src/evaluator.js";

const FIXTURES = resolve(__dirname, "../../../spec/fixtures");

interface AuthorityVector {
  id: string;
  pattern: string;
  action: string;
  expected: boolean;
  rationale: string;
}

interface AuthorityMatchingFixture {
  version: string;
  description: string;
  vectors: AuthorityVector[];
}

const fixture: AuthorityMatchingFixture = JSON.parse(
  readFileSync(resolve(FIXTURES, "authority-matching-vectors.json"), "utf-8"),
);

const vectors = fixture.vectors;

describe("authority-matching fixture vectors (cross-SDK contract)", () => {
  it.each(vectors)(
    "$id: $rationale",
    ({ pattern, action, expected }) => {
      expect(matchesAction(pattern, action)).toBe(expected);
    },
  );
});
