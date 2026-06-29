// test/doctor.test.ts: doctor script と env 注入 script の副作用が小さい箇所を検証する。
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

import {
  collectChecks,
  envPresenceCheck,
  hasInstalledRustTarget,
  isEvmAddress,
  isHttpUrl,
  isHttpsOrigin,
  isPositiveIntegerString,
  isPrivateKey,
  isSingleHttpsRpcServices,
  parseMode
} from "../scripts/doctor";

const privateKey = `0x${"1".repeat(64)}`;

function canisterEnv(publicOrigin: string): NodeJS.ProcessEnv {
  return {
    FACILITATOR_EVM_PRIVATE_KEY: privateKey,
    FACILITATOR_PUBLIC_ORIGIN: publicOrigin,
    JPYC_EIP712_VERSION: "1",
    POLYGON_RPC_SERVICES: "https://polygon.example",
    SELLER_CREDIT_PAY_TO: "0x2000000000000000000000000000000000000402",
    SELLER_CREDIT_TOPUP_AMOUNT: "1000",
    SELLER_SETTLEMENT_FEE_AMOUNT: "100"
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
    expect(isSingleHttpsRpcServices("https://polygon.example")).toBe(true);
    expect(isSingleHttpsRpcServices("http://polygon.example")).toBe(false);
    expect(isSingleHttpsRpcServices("https://a.example,https://b.example")).toBe(false);
    expect(isPositiveIntegerString("60")).toBe(true);
    expect(isPositiveIntegerString("30000000000000000")).toBe(true);
    expect(isPositiveIntegerString("0")).toBe(false);
  });

  it("validates canister env formats and warns about ignored JPYC override", () => {
    const checks = collectChecks(".", {
      FACILITATOR_EVM_PRIVATE_KEY: "0x1",
      FACILITATOR_MAX_GAS: "0",
      FACILITATOR_MAX_SETTLEMENT_FEE_WEI: "0",
      FACILITATOR_PUBLIC_ORIGIN: "http://canister.example.test",
      JPYC_POLYGON_ADDRESS: "0x402",
      POLYGON_RPC_SERVICES: "http://polygon.example",
      SELLER_CREDIT_PAY_TO: "0x402",
      SELLER_CREDIT_TOPUP_AMOUNT: "0",
      SELLER_SETTLEMENT_FEE_AMOUNT: "1.5",
      SETTLE_CONFIRMATION_TIMEOUT_SECONDS: "0",
      SETTLE_MIN_CONFIRMATIONS: "0",
      SETTLEMENT_CACHE_TTL_SECONDS: "1.5"
    }, "canister");

    expect(checks.some((check) => check.name === "env-format:FACILITATOR_EVM_PRIVATE_KEY")).toBe(true);
    expect(checks.some((check) => check.name === "env:JPYC_POLYGON_ADDRESS" && check.status === "warn")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_SERVICES")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_MAX_GAS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_MAX_SETTLEMENT_FEE_WEI")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_PUBLIC_ORIGIN")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_CREDIT_PAY_TO")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_CREDIT_TOPUP_AMOUNT")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SELLER_SETTLEMENT_FEE_AMOUNT")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLE_CONFIRMATION_TIMEOUT_SECONDS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLE_MIN_CONFIRMATIONS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLEMENT_CACHE_TTL_SECONDS")).toBe(true);
  }, 20_000);

  it("rejects non-origin Polygon RPC service values for canister env", () => {
    for (const value of [
      "https://trusted.example@evil.example",
      "https://polygon.example/path",
      "https://polygon.example?x=1",
      "https://polygon.example#x"
    ]) {
      const checks = collectChecks(".", {
        POLYGON_RPC_SERVICES: value
      }, "canister");

      expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_SERVICES")).toBe(true);
    }

    const checks = collectChecks(".", {
      POLYGON_RPC_SERVICES: "https://polygon.example:443"
    }, "canister");
    expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_SERVICES")).toBe(false);
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

    const checks = collectChecks(".", canisterEnv("https://trusted.example@evil.example"), "canister");
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_PUBLIC_ORIGIN")).toBe(true);
  }, 10_000);

  it("validates optional buyer env formats", () => {
    const checks = collectChecks(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      JPYC_POLYGON_ADDRESS: "0x402",
      JPYC_PRICE: "0",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: "0x402",
      X402_RESOURCE_URL: "http://resource.example.test/jpyc/report",
      X402_TARGET_URL: "https://example.test/jpyc/report"
    }, "buyer");

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
      const checks = collectChecks(".", {
        BUYER_EVM_PRIVATE_KEY: privateKey,
        POLYGON_RPC_URL: value,
        X402_TARGET_URL: "https://example.test/jpyc/report"
      }, "buyer");

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

  it("passes facilitator env to the canister env script", () => {
    const dir = mkdtempSync(join(tmpdir(), "ic-facilitator-env-"));
    const logPath = join(dir, "icp.log");
    const fakeIcp = join(dir, "icp");

    writeFileSync(fakeIcp, "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$ICP_FAKE_LOG\"\n");
    chmodSync(fakeIcp, 0o755);

    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: "0x2000000000000000000000000000000000000402",
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(0);
      const output = readFileSync(logPath, "utf8");
      expect(output).toContain('"FACILITATOR_EVM_PRIVATE_KEY",');
      expect(output).toContain('"JPYC_EIP712_VERSION", "1"');
      expect(output).toContain('"POLYGON_RPC_SERVICES", "https://polygon.example"');
      expect(output).toContain('"SELLER_CREDIT_PAY_TO", "0x2000000000000000000000000000000000000402"');
      expect(output).toContain('"SELLER_CREDIT_TOPUP_AMOUNT", "1000"');
      expect(output).toContain('"SELLER_SETTLEMENT_FEE_AMOUNT", "100"');
      expect(output).toContain('"FACILITATOR_MAX_GAS", "500000"');
      expect(output).toContain('"FACILITATOR_MAX_SETTLEMENT_FEE_WEI", "30000000000000000"');
      expect(output).toContain('"FACILITATOR_PUBLIC_ORIGIN", "https://canister.example.test"');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  }, 10_000);
});
