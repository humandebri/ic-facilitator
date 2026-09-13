import { describe, expect, it } from "vitest";
import { formatJpyc } from "./format";

describe("seller web formatting", () => {
  it("formats JPYC atomic units without floating point conversion", () => {
    expect(formatJpyc("1000000000000000001")).toBe("1.000000000000000001 JPYC");
  });
});
