// test/setCanisterEnv.test.ts: facilitator env 注入前の secret/config 検証を確認する。
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

const privateKey = `0x${"1".repeat(64)}`;
const sellerCreditPayTo = "0x2000000000000000000000000000000000000402";
const batchSettlementContract = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";

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
  }, 15_000);

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
      expect(result.stderr).toContain("POLYGON_RPC_SERVICES must be a single https://host[:port] RPC origin");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects non-origin Polygon RPC services before calling icp", () => {
    for (const value of [
      "https://trusted.example@evil.example",
      "https://polygon.example/path",
      "https://polygon.example?x=1",
      "https://polygon.example#x"
    ]) {
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
            POLYGON_RPC_SERVICES: value,
            SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
            SELLER_CREDIT_TOPUP_AMOUNT: "1000",
            SELLER_SETTLEMENT_FEE_AMOUNT: "100",
            PATH: `${dir}:${process.env.PATH ?? ""}`
          }
        });

        expect(result.status).toBe(1);
        expect(result.stderr).toContain("POLYGON_RPC_SERVICES must be a single https://host[:port] RPC origin");
        expect(() => readFileSync(logPath, "utf8")).toThrow();
      } finally {
        rmSync(dir, { force: true, recursive: true });
      }
    }
  });

  it("rejects userinfo in facilitator public origin before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://trusted.example@evil.example",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("FACILITATOR_PUBLIC_ORIGIN must be an HTTPS origin");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects batch withdraw delay outside official range before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          BATCH_WITHDRAW_DELAY_SECONDS: "899",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_WITHDRAW_DELAY_SECONDS must be between 900 and 2592000");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects missing batch channel storage writer principal when batch is enabled", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("missing required env: BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects missing batch settlement contract when batch is enabled", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("missing required env: BATCH_SETTLEMENT_CONTRACT");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects a non-canonical batch settlement contract before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: "0x0000000000000000000000000000000000000001",
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain(`BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${batchSettlementContract}`);
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects invalid batch channel storage writer principal before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "not a principal",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects batch settlement fee amount above uint128 before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "340282366920938463463374607431768211456",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_SETTLEMENT_FEE_AMOUNT must fit uint128");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects batch channel storage writer principal with invalid checksum before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-caj",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects anonymous batch channel storage writer principal before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "2vxsx-fae",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: `0x${"2".repeat(64)}`,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be a non-system IC principal");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects matching facilitator and batch receiver authorizer keys before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: privateKey,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address");
      expect(() => readFileSync(logPath, "utf8")).toThrow();
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  }, 15_000);

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
      expect(log).toContain('set_env ("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "")');
      expect(log).toContain('set_env ("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "")');
      expect(log).toContain('set_env ("BATCH_SETTLEMENT_CONTRACT", "")');
      expect(log).toContain('set_env ("BATCH_WITHDRAW_DELAY_SECONDS", "")');
      expect(log).toContain('set_env ("BATCH_SETTLEMENT_FEE_AMOUNT", "")');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("sets batch channel storage writer principal when batch is enabled", () => {
    const { dir, logPath } = fakeIcpDir();
    const batchReceiverAuthorizerKey = `0x${"2".repeat(64)}`;
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
          BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: batchReceiverAuthorizerKey,
          BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
          BATCH_SETTLEMENT_FEE_AMOUNT: "100",
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
          ICP_FAKE_LOG: logPath,
          JPYC_EIP712_VERSION: "1",
          POLYGON_RPC_SERVICES: "https://polygon.example",
          SELLER_CREDIT_PAY_TO: sellerCreditPayTo,
          SELLER_CREDIT_TOPUP_AMOUNT: "1000",
          SELLER_SETTLEMENT_FEE_AMOUNT: "100",
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(0);
      const log = readFileSync(logPath, "utf8");
      expect(log).toContain('set_env ("BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "ryjl3-tyaaa-aaaaa-aaaba-cai")');
      expect(log).toContain(`set_env ("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "${batchReceiverAuthorizerKey}")`);
      expect(log).toContain(`set_env ("BATCH_SETTLEMENT_CONTRACT", "${batchSettlementContract}")`);
      expect(log).toContain('set_env ("BATCH_WITHDRAW_DELAY_SECONDS", "900")');
      expect(log).toContain('set_env ("BATCH_SETTLEMENT_FEE_AMOUNT", "100")');
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  }, 15_000);

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
