import { describe, expect, it } from "vitest";
import { legalVersionsMatch } from "./legal";

const expected = { terms: "terms-v1", privacy: "privacy-v1", assetBoundary: "asset-v1" };

describe("legalVersionsMatch", () => {
  it("accepts only an exact three-document match", () => {
    expect(legalVersionsMatch(expected, expected)).toBe(true);
    expect(legalVersionsMatch(expected, { ...expected, privacy: "privacy-v2" })).toBe(false);
    expect(legalVersionsMatch(expected, undefined)).toBe(false);
  });
});
