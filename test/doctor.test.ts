// test/doctor.test.ts: doctor script と env 注入 script の副作用が小さい箇所を検証する。

import { describe, expect, it } from "vitest";

import {
  collectChecks,
  envChecks,
  envPresenceCheck,
  hasInstalledRustTarget,
  isEvmAddress,
  isHttpUrl,
  isHttpsOrigin,
  isPositiveIntegerString,
  isPrivateKey,
  parseMode
} from "../scripts/doctor";

const privateKey = `0x${"1".repeat(64)}`;

function canisterEnv(publicOrigin: string): NodeJS.ProcessEnv {
  return {
    FACILITATOR_EVM_PRIVATE_KEY: privateKey,
    FACILITATOR_PUBLIC_ORIGIN: publicOrigin,
    JPYC_EIP712_VERSION: "1",
    POLYGON_RPC_URL: "https://polygon.example",
    SELLER_CREDIT_PAY_TO: "0x2000000000000000000000000000000000000402",
    SELLER_SETTLEMENT_FEE_AMOUNT: "1000000000000000000"
  };
}

describe("doctor helpers", () => {
  it("parses supported modes", () => {
    expect(parseMode(["--mode=buyer"])).toBe("buyer");
    expect(parseMode(["--mode", "buyer"])).toBe("buyer");
    expect(parseMode(["--mode=canister"])).toBe("canister");
    expect(parseMode(["--mode=all"])).toBe("all");
    expect(parseMode(["--mode=unknown"])).toBe("all");
  });

  it("detects installed rust targets by exact line", () => {
    expect(hasInstalledRustTarget("wasm32-unknown-unknown\nx86_64-apple-darwin", "wasm32-unknown-unknown")).toBe(true);
    expect(hasInstalledRustTarget("wasm32-unknown-unknown-threads", "wasm32-unknown-unknown")).toBe(false);
  });

  it("reports missing env values", () => {
    expect(envPresenceCheck("TOKEN", { TOKEN: "abc" }).status).toBe("ok");
    expect(envPresenceCheck("TOKEN", { TOKEN: " " }).status).toBe("fail");
    expect(envPresenceCheck("TOKEN", {}).status).toBe("fail");
  });

  it("validates runtime env formats", () => {
    expect(isEvmAddress("0x0000000000000000000000000000000000000402")).toBe(true);
    expect(isEvmAddress("0x402")).toBe(false);
    expect(isPrivateKey(privateKey)).toBe(true);
    expect(isPrivateKey("0x1")).toBe(false);
    expect(isHttpUrl("https://polygon.example")).toBe(true);
    expect(isHttpUrl("file:///tmp/x")).toBe(false);
    expect(isPositiveIntegerString("60")).toBe(true);
    expect(isPositiveIntegerString("30000000000000000")).toBe(true);
    expect(isPositiveIntegerString("0")).toBe(false);
  });

  it("validates canister env formats and warns about ignored JPYC override", () => {
    const checks = envChecks("canister", {
      FACILITATOR_EVM_PRIVATE_KEY: "0x1",
      FACILITATOR_MAX_GAS: "0",
      FACILITATOR_MAX_SETTLEMENT_FEE_WEI: "0",
      FACILITATOR_PUBLIC_ORIGIN: "http://canister.example.test",
      JPYC_POLYGON_ADDRESS: "0x402",
      POLYGON_RPC_URL: "http://polygon.example",
      SELLER_CREDIT_PAY_TO: "0x402",
      SELLER_CREDIT_TOPUP_AMOUNT: "0",
      SELLER_SETTLEMENT_FEE_AMOUNT: "1.5",
      SETTLE_CONFIRMATION_TIMEOUT_SECONDS: "0",
      SETTLE_MIN_CONFIRMATIONS: "0",
      SETTLEMENT_CACHE_TTL_SECONDS: "1.5"
    });

    expect(checks.some((check) => check.name === "env-format:FACILITATOR_EVM_PRIVATE_KEY")).toBe(true);
    expect(checks.some((check) => check.name === "env:JPYC_POLYGON_ADDRESS" && check.status === "warn")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_URL")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_MAX_GAS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_MAX_SETTLEMENT_FEE_WEI")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_PUBLIC_ORIGIN")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_CREDIT_PAY_TO")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_CREDIT_TOPUP_AMOUNT")).toBe(false);
    expect(checks.some((check) => check.name === "env-format:SELLER_SETTLEMENT_FEE_AMOUNT")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLE_CONFIRMATION_TIMEOUT_SECONDS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLE_MIN_CONFIRMATIONS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLEMENT_CACHE_TTL_SECONDS")).toBe(true);
  }, 20_000);

  it("accepts path/query but rejects unsafe Polygon RPC URLs for canister env", () => {
    for (const value of [
      "https://trusted.example@evil.example",
      "https://polygon.example#x"
    ]) {
      const checks = envChecks("canister", {
        POLYGON_RPC_URL: value
      });

      expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_URL")).toBe(true);
    }

    for (const value of ["https://polygon.example:443", "https://polygon.example/path", "https://polygon.example?x=1"]) {
      const checks = envChecks("canister", { POLYGON_RPC_URL: value });
      expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_URL")).toBe(false);
    }
  }, 20_000);

  it("validates facilitator public origin as a strict HTTPS origin", () => {
    expect(isHttpsOrigin("https://canister.example.test")).toBe(true);
    expect(isHttpsOrigin("https://canister.example.test:443")).toBe(true);

    for (const origin of [
      "https://trusted.example@evil.example",
      "https://canister.example.test/path",
      "https://canister.example.test?x=1",
      "https://canister.example.test#x"
    ]) {
      expect(isHttpsOrigin(origin)).toBe(false);
    }

    const checks = envChecks("canister", canisterEnv("https://trusted.example@evil.example"));
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_PUBLIC_ORIGIN")).toBe(true);
  }, 10_000);

  it("validates optional buyer env formats", () => {
    const checks = envChecks("buyer", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      JPYC_POLYGON_ADDRESS: "0x402",
      JPYC_PRICE: "0",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: "0x402",
      X402_RESOURCE_URL: "http://resource.example.test/jpyc/report",
      X402_TARGET_URL: "https://example.test/jpyc/report"
    });

    expect(checks.some((check) => check.name === "env-format:JPYC_POLYGON_ADDRESS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:JPYC_PRICE")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:X402_RESOURCE_URL")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_EVM_ADDRESS")).toBe(true);
  });

  it("rejects non-HTTPS Polygon RPC URLs for buyer env", () => {
    for (const value of [
      "http://polygon.example",
      "https://trusted.example@evil.example",
      "https://polygon.example/#x",
      "https://polygon.example/v2/key#x"
    ]) {
      const checks = envChecks("buyer", {
        BUYER_EVM_PRIVATE_KEY: privateKey,
        POLYGON_RPC_URL: value,
        X402_TARGET_URL: "https://example.test/jpyc/report"
      });

      expect(checks).toContainEqual(expect.objectContaining({
        detail: "userinfo/fragment なしの HTTPS URL ではない",
        name: "env-format:POLYGON_RPC_URL",
        status: "fail"
      }));
    }
  });

  it("keeps buyer checks independent from canister toolchain", () => {
    const checks = collectChecks(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      POLYGON_RPC_URL: "https://polygon.example",
      X402_TARGET_URL: "https://example.test/jpyc/report"
    }, "buyer");

    expect(checks.some((check) => check.name === "command:icp")).toBe(false);
    expect(checks.some((check) => check.name === "rust-target")).toBe(false);
    expect(checks.some((check) => check.name === "env:FACILITATOR_EVM_PRIVATE_KEY")).toBe(false);
  });
});
