import { describe, expect, it } from "vitest";
import { formatJpyc, shortAddress } from "./format";

describe("seller web formatting", () => {
  it("formats JPYC atomic units without floating point conversion", () => {
    expect(formatJpyc("1000000000000000001")).toBe("1.000000000000000001 JPYC");
  });

  it("shortens addresses only for display", () => {
    expect(shortAddress("0x1234567890abcdef1234567890abcdef12345678")).toBe("0x1234…5678");
  });
});
