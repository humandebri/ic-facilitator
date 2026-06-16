// test/setCanisterEnv.test.ts: facilitator env 注入前の secret/config 検証を確認する。
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

const privateKey = `0x${"1".repeat(64)}`;
const sellerCreditPayTo = "0x2000000000000000000000000000000000000402";

function fakeIcpDir(): { readonly dir: string; readonly logPath: string } {
  const dir = mkdtempSync(join(tmpdir(), "ic-facilitator-env-"));
  const logPath = join(dir, "icp.log");
  const fakeIcp = join(dir, "icp");
  writeFileSync(fakeIcp, "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$ICP_FAKE_LOG\"\n");
  chmodSync(fakeIcp, 0o755);
  return { dir, logPath };
}

describe("set_canister_env facilitator validation", () => {
  it("rejects invalid facilitator private keys before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          FACILITATOR_EVM_PRIVATE_KEY: "0x1",
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

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("FACILITATOR_EVM_PRIVATE_KEY must be a 0x-prefixed 32-byte private key");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects missing Polygon RPC services before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
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
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("missing required env: POLYGON_RPC_SERVICES");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects non-HTTPS Polygon RPC services before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
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
          POLYGON_RPC_SERVICES: "http://polygon.example",
          SELLER_CREDIT_PAY_TO: "0x2000000000000000000000000000000000000402",
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("POLYGON_RPC_SERVICES must be an HTTPS RPC URL");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("sets facilitator env defaults", () => {
    const { dir, logPath } = fakeIcpDir();
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
      const log = readFileSync(logPath, "utf8");
      expect(log).toContain(`set_env ("FACILITATOR_EVM_PRIVATE_KEY", "${privateKey}")`);
      expect(log).toContain('set_env ("JPYC_EIP712_VERSION", "1")');
      expect(log).toContain('set_env ("POLYGON_RPC_SERVICES", "https://polygon.example")');
      expect(log).toContain('set_env ("FACILITATOR_PUBLIC_ORIGIN", "https://canister.example.test")');
      expect(log).toContain('set_env ("SELLER_CREDIT_PAY_TO", "0x2000000000000000000000000000000000000402")');
      expect(log).toContain('set_env ("SELLER_CREDIT_TOPUP_AMOUNT", "1000")');
      expect(log).toContain('set_env ("SELLER_SETTLEMENT_FEE_AMOUNT", "100")');
      expect(log).not.toContain("JPYC_POLYGON_ADDRESS");
      expect(log).toContain('set_env ("FACILITATOR_MAX_GAS", "500000")');
      expect(log).toContain('set_env ("FACILITATOR_MAX_SETTLEMENT_FEE_WEI", "30000000000000000")');
      expect(log).toContain('set_env ("SETTLE_CONFIRMATION_TIMEOUT_SECONDS", "60")');
      expect(log).toContain('set_env ("SETTLE_MIN_CONFIRMATIONS", "3")');
      expect(log).toContain('set_env ("SETTLEMENT_CACHE_TTL_SECONDS", "86400")');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("loads missing values from a dotenv file", () => {
    const { dir, logPath } = fakeIcpDir();
    const dotenvPath = join(dir, ".env");
    try {
      writeFileSync(dotenvPath, [
        `FACILITATOR_EVM_PRIVATE_KEY=${privateKey}`,
        "JPYC_EIP712_VERSION=1",
        "POLYGON_RPC_SERVICES=https://polygon.example",
        "FACILITATOR_PUBLIC_ORIGIN=https://canister.example.test",
        "SELLER_CREDIT_PAY_TO=0x2000000000000000000000000000000000000402",
        "SELLER_CREDIT_TOPUP_AMOUNT=1000",
        "SELLER_SETTLEMENT_FEE_AMOUNT=100",
        "FACILITATOR_MAX_GAS=700000",
        "FACILITATOR_MAX_SETTLEMENT_FEE_WEI=40000000000000000"
      ].join("\n"));
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          DOTENV_PATH: dotenvPath,
          ICP_FAKE_LOG: logPath,
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(0);
      const log = readFileSync(logPath, "utf8");
      expect(log).toContain(`set_env ("FACILITATOR_EVM_PRIVATE_KEY", "${privateKey}")`);
      expect(log).toContain('set_env ("JPYC_EIP712_VERSION", "1")');
      expect(log).toContain('set_env ("POLYGON_RPC_SERVICES", "https://polygon.example")');
      expect(log).toContain('set_env ("FACILITATOR_PUBLIC_ORIGIN", "https://canister.example.test")');
      expect(log).toContain('set_env ("SELLER_CREDIT_PAY_TO", "0x2000000000000000000000000000000000000402")');
      expect(log).toContain('set_env ("SELLER_CREDIT_TOPUP_AMOUNT", "1000")');
      expect(log).toContain('set_env ("SELLER_SETTLEMENT_FEE_AMOUNT", "100")');
      expect(log).toContain('set_env ("FACILITATOR_MAX_GAS", "700000")');
      expect(log).toContain('set_env ("FACILITATOR_MAX_SETTLEMENT_FEE_WEI", "40000000000000000")');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("keeps explicit shell env values over dotenv values", () => {
    const { dir, logPath } = fakeIcpDir();
    const dotenvPath = join(dir, ".env");
    try {
      writeFileSync(dotenvPath, [
        "FACILITATOR_EVM_PRIVATE_KEY=0x2222222222222222222222222222222222222222222222222222222222222222",
        "JPYC_EIP712_VERSION=2",
        "POLYGON_RPC_SERVICES=https://dotenv.example",
        "FACILITATOR_PUBLIC_ORIGIN=https://dotenv.example",
        "SELLER_CREDIT_PAY_TO=0x3000000000000000000000000000000000000402",
        "SELLER_CREDIT_TOPUP_AMOUNT=3000",
        "SELLER_SETTLEMENT_FEE_AMOUNT=300",
        "FACILITATOR_MAX_GAS=700000",
        "FACILITATOR_MAX_SETTLEMENT_FEE_WEI=40000000000000000"
      ].join("\n"));
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          DOTENV_PATH: dotenvPath,
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          FACILITATOR_MAX_SETTLEMENT_FEE_WEI: "50000000000000000",
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
      const log = readFileSync(logPath, "utf8");
      expect(log).toContain(`set_env ("FACILITATOR_EVM_PRIVATE_KEY", "${privateKey}")`);
      expect(log).toContain('set_env ("FACILITATOR_MAX_SETTLEMENT_FEE_WEI", "50000000000000000")');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });
});
