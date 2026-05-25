// test/setCanisterEnv.test.ts: facilitator env 注入前の secret/config 検証を確認する。
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

const privateKey = `0x${"1".repeat(64)}`;

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
          ICP_FAKE_LOG: logPath,
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

  it("rejects malformed Polygon RPC services before calling icp", () => {
    const { dir, logPath } = fakeIcpDir();
    try {
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          ICP_FAKE_LOG: logPath,
          PATH: `${dir}:${process.env.PATH ?? ""}`,
          POLYGON_RPC_SERVICES: "file:///tmp/rpc"
        }
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain("POLYGON_RPC_SERVICES must be a single https URL");
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
          ICP_FAKE_LOG: logPath,
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(0);
      const log = readFileSync(logPath, "utf8");
      expect(log).toContain(`set_env ("FACILITATOR_EVM_PRIVATE_KEY", "${privateKey}")`);
      expect(log).toContain('set_env ("JPYC_POLYGON_ADDRESS", "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB")');
      expect(log).toContain('set_env ("POLYGON_RPC_SERVICES", "https://polygon-bor-rpc.publicnode.com")');
      expect(log).toContain('set_env ("FACILITATOR_MAX_GAS", "500000")');
      expect(log).toContain('set_env ("SETTLE_CONFIRMATION_TIMEOUT_SECONDS", "60")');
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
        "POLYGON_RPC_SERVICES=https://one.example",
        "FACILITATOR_MAX_GAS=700000"
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
      expect(log).toContain('set_env ("POLYGON_RPC_SERVICES", "https://one.example")');
      expect(log).toContain('set_env ("FACILITATOR_MAX_GAS", "700000")');
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
        "FACILITATOR_MAX_GAS=700000"
      ].join("\n"));
      const result = spawnSync("bash", ["scripts/set_canister_env.sh", "local"], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          DOTENV_PATH: dotenvPath,
          FACILITATOR_EVM_PRIVATE_KEY: privateKey,
          ICP_FAKE_LOG: logPath,
          PATH: `${dir}:${process.env.PATH ?? ""}`
        }
      });

      expect(result.status).toBe(0);
      expect(readFileSync(logPath, "utf8")).toContain(`set_env ("FACILITATOR_EVM_PRIVATE_KEY", "${privateKey}")`);
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });
});
