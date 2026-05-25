// test/jpycWallet.test.ts: buyer wallet の required amount 判定を確認する。
import { describe, expect, it } from "vitest";

import { approveRequirementFailure, approveRequirementWarning, fundingNextActions, hasRequiredAmount, shouldSendPermit2Approve, walletRequirementFailure, walletRequirementSummary } from "../scripts/jpyc_wallet";

describe("jpyc wallet", () => {
  it("requires balances and allowances to cover the exact required amount", () => {
    expect(hasRequiredAmount(100n, 100n)).toBe(true);
    expect(hasRequiredAmount(101n, 100n)).toBe(true);
    expect(hasRequiredAmount(99n, 100n)).toBe(false);
  });

  it("reports which wallet requirement is missing", () => {
    expect(walletRequirementFailure(true, true)).toBeNull();
    expect(walletRequirementFailure(false, true)).toBe("buyer wallet is missing required JPYC balance");
    expect(walletRequirementFailure(true, false)).toBe("buyer wallet is missing required Permit2 allowance");
    expect(walletRequirementFailure(false, false)).toBe("buyer wallet is missing required JPYC balance and Permit2 allowance");
  });

  it("builds wallet requirement summary for CLI output", () => {
    expect(walletRequirementSummary(100n, 99n, 0n, 100n)).toEqual({
      approveFailure: "buyer wallet needs native Polygon gas to approve Permit2 allowance",
      approveWarning: null,
      hasPermit2Allowance: false,
      hasNativeGasBalance: false,
      hasRequiredBalance: true,
      requirementFailure: "buyer wallet is missing required Permit2 allowance"
    });
  });

  it("reports gas needs for Permit2 approve", () => {
    expect(approveRequirementFailure(true, false)).toBeNull();
    expect(approveRequirementFailure(false, true)).toBeNull();
    expect(approveRequirementFailure(false, false)).toBe("buyer wallet needs native Polygon gas to approve Permit2 allowance");
  });

  it("warns that approve does not fund missing JPYC balance", () => {
    expect(approveRequirementWarning(false, false)).toBe("Permit2 approve does not add JPYC balance");
    expect(approveRequirementWarning(false, true)).toBeNull();
    expect(approveRequirementWarning(true, false)).toBeNull();
  });

  it("skips approve when Permit2 allowance already covers the payment", () => {
    expect(shouldSendPermit2Approve(true)).toBe(false);
    expect(shouldSendPermit2Approve(false)).toBe(true);
  });

  it("prints concrete funding next actions", () => {
    expect(fundingNextActions("0x1000000000000000000000000000000000000402", false, false, false, "1")).toEqual([
      "send at least 1 JPYC on Polygon to 0x1000000000000000000000000000000000000402",
      "send Polygon native gas to 0x1000000000000000000000000000000000000402",
      "run JPYC_APPROVE=1 npm run wallet:jpyc after gas is funded"
    ]);
  });
});
