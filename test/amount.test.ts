// test/amount.test.ts: JPYC decimal amount の atomic unit 変換を固定する。
import { describe, expect, it } from "vitest";

import { decimalToAtomicUnits, positiveDecimalToAtomicUnits } from "../src/amount";

describe("amount conversion", () => {
  it("converts JPYC decimal strings to atomic units", () => {
    expect(decimalToAtomicUnits("1", 18)).toBe("1000000000000000000");
    expect(decimalToAtomicUnits("1.25", 18)).toBe("1250000000000000000");
    expect(decimalToAtomicUnits("0.000000000000000001", 18)).toBe("1");
  });

  it("rejects invalid or non-positive JPYC prices", () => {
    expect(() => decimalToAtomicUnits("1.0000000000000000001", 18)).toThrow("more than 18");
    expect(() => positiveDecimalToAtomicUnits("0", 18, "JPYC_PRICE")).toThrow("positive decimal");
    expect(() => positiveDecimalToAtomicUnits("abc", 18, "JPYC_PRICE")).toThrow("positive decimal");
  });
});
