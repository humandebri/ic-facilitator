// test/jpycWallet.test.ts: buyer wallet の required amount 判定を確認する。
import { describe, expect, it } from "vitest";

import { fundingNextActions, hasRequiredAmount, walletRequirementFailure, walletRequirementSummary } from "../scripts/jpyc_wallet";

describe("jpyc wallet", () => {
  it("requires balance to cover the exact required amount", () => {
    expect(hasRequiredAmount(100n, 100n)).toBe(true);
    expect(hasRequiredAmount(101n, 100n)).toBe(true);
    expect(hasRequiredAmount(99n, 100n)).toBe(false);
  });

  it("reports missing JPYC balance", () => {
    expect(walletRequirementFailure(true)).toBeNull();
    expect(walletRequirementFailure(false)).toBe("buyer wallet is missing required JPYC balance");
  });

  it("builds wallet requirement summary for CLI output", () => {
    expect(walletRequirementSummary(100n, 0n, 100n)).toEqual({
      hasNativeGasBalance: false,
      hasRequiredBalance: true,
      nativeGasRequired: false,
      requirementFailure: null
    });
  });

  it("prints concrete funding next actions", () => {
    expect(fundingNextActions("0x1000000000000000000000000000000000000402", false, "1")).toEqual([
      "send at least 1 JPYC on Polygon to 0x1000000000000000000000000000000000000402"
    ]);
    expect(fundingNextActions("0x1000000000000000000000000000000000000402", true, "1")).toEqual([]);
  });
});
