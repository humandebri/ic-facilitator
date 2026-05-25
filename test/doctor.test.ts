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
  isPositiveIntegerString,
  isPrivateKey,
  isRpcServices,
  parseMode
} from "../scripts/doctor";

const privateKey = `0x${"1".repeat(64)}`;

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
    expect(isRpcServices("https://one.example")).toBe(true);
    expect(isRpcServices("https://one.example,https://two.example")).toBe(false);
    expect(isRpcServices("http://one.example")).toBe(false);
    expect(isRpcServices("file:///tmp/x")).toBe(false);
    expect(isPositiveIntegerString("60")).toBe(true);
    expect(isPositiveIntegerString("0")).toBe(false);
  });

  it("validates optional canister env formats", () => {
    const checks = collectChecks(".", {
      FACILITATOR_EVM_PRIVATE_KEY: "0x1",
      FACILITATOR_MAX_GAS: "0",
      JPYC_POLYGON_ADDRESS: "0x402",
      POLYGON_RPC_SERVICES: "file:///tmp/rpc",
      SETTLE_CONFIRMATION_TIMEOUT_SECONDS: "0",
      SETTLEMENT_CACHE_TTL_SECONDS: "1.5"
    }, "canister");

    expect(checks.some((check) => check.name === "env-format:FACILITATOR_EVM_PRIVATE_KEY")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:JPYC_POLYGON_ADDRESS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:POLYGON_RPC_SERVICES")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:FACILITATOR_MAX_GAS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLE_CONFIRMATION_TIMEOUT_SECONDS")).toBe(true);
    expect(checks.some((check) => check.name === "env-format:SETTLEMENT_CACHE_TTL_SECONDS")).toBe(true);
  });

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
          ICP_FAKE_LOG: logPath,
          PATH: `${dir}:${process.env.PATH ?? ""}`,
          POLYGON_RPC_SERVICES: "https://one.example"
        }
      });

      expect(result.status).toBe(0);
      const output = readFileSync(logPath, "utf8");
      expect(output).toContain('"FACILITATOR_EVM_PRIVATE_KEY",');
      expect(output).toContain('"POLYGON_RPC_SERVICES", "https://one.example"');
      expect(output).toContain('"FACILITATOR_MAX_GAS", "500000"');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  }, 10_000);
});
