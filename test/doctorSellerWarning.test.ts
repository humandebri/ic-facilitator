// test/doctorSellerWarning.test.ts: doctor が sample seller address を拒否することを確認する。
import { describe, expect, it } from "vitest";

import { collectChecks } from "../scripts/doctor";

const sampleSeller = "0x0000000000000000000000000000000000000402";

describe("doctor seller guard", () => {
  it("fails when the sample seller address is configured", () => {
    const checks = collectChecks(".", {
      BUYER_EVM_PRIVATE_KEY: `0x${"1".repeat(64)}`,
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: sampleSeller,
      X402_TARGET_URL: "https://example.test/jpyc/report"
    }, "all");

    expect(checks.some((check) => check.name === "env:SELLER_EVM_ADDRESS_SAMPLE" && check.status === "fail")).toBe(true);
  }, 10_000);
});
