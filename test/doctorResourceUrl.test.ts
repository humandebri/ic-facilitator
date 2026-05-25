// test/doctorResourceUrl.test.ts: local HTTP target で必要な x402 HTTPS resource env を検証する。
import { describe, expect, it } from "vitest";

import { collectChecks } from "../scripts/doctor";

const buyerEnv = {
  BUYER_EVM_PRIVATE_KEY: `0x${"1".repeat(64)}`,
  POLYGON_RPC_URL: "https://polygon.example",
  SELLER_EVM_ADDRESS: "0x1000000000000000000000000000000000000402"
};

describe("doctor resource URL checks", () => {
  it("requires explicit resource URL for local HTTP payment targets", () => {
    const checks = collectChecks(".", {
      ...buyerEnv,
      X402_TARGET_URL: "http://edge.local.localhost:8000/jpyc/report"
    }, "buyer");

    expect(checks.some((check) => check.name === "env:X402_RESOURCE_URL" && check.status === "fail")).toBe(true);
  });

  it("accepts HTTPS targets without a separate resource URL", () => {
    const checks = collectChecks(".", {
      ...buyerEnv,
      X402_TARGET_URL: "https://example.test/jpyc/report"
    }, "buyer");

    expect(checks.some((check) => check.name === "env:X402_RESOURCE_URL")).toBe(false);
  });

  it("accepts HTTPS resource URL for local HTTP payment targets", () => {
    const checks = collectChecks(".", {
      ...buyerEnv,
      X402_RESOURCE_URL: "https://ic-edge.local/jpyc/report",
      X402_TARGET_URL: "http://edge.local.localhost:8000/jpyc/report"
    }, "buyer");

    expect(checks.some((check) => check.name === "env:X402_RESOURCE_URL")).toBe(false);
  });
});
