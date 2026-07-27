import { describe, expect, it } from "vitest";

import { requiredPayerMintAmount } from "../scripts/amoy_fee_benchmark";

describe("Amoy fee benchmark setup", () => {
  it("derives the payer mint requirement from every setup deposit", () => {
    expect(requiredPayerMintAmount(161)).toBe(487n);
  });

  it("rejects invalid channel counts", () => {
    expect(() => requiredPayerMintAmount(-1)).toThrow("non-negative safe integer");
  });
});
