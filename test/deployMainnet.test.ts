import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

const privateKey = `0x${"1".repeat(64)}`;

function runDeploy(statusExists: boolean, approvedLegalVersions = true) {
  const dir = mkdtempSync(join(tmpdir(), "ic-facilitator-deploy-"));
  const logPath = join(dir, "icp.log");
  const fakeIcp = join(dir, "icp");
  writeFileSync(fakeIcp, `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$ICP_FAKE_LOG"
if [[ "$1 $2 $3" == "canister status edge" ]]; then exit ${statusExists ? 0 : 1}; fi
exit 0
`);
  chmodSync(fakeIcp, 0o755);
  const result = spawnSync("bash", ["scripts/deploy_mainnet.sh"], {
    cwd: process.cwd(),
    encoding: "utf8",
    env: {
      ...process.env,
      DOTENV_PATH: join(dir, "missing.env"),
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: "https://canister.example.test",
      ICP_FAKE_LOG: logPath,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_CREDIT_PAY_TO: "0x2000000000000000000000000000000000000402",
      SELLER_SETTLEMENT_FEE_AMOUNT: "1000000000000000000",
      SELLER_TERMS_VERSION: approvedLegalVersions ? "2026-07-13" : "2026-07-13-draft",
      PRIVACY_VERSION: approvedLegalVersions ? "2026-07-13" : "",
      ASSET_BOUNDARY_VERSION: approvedLegalVersions ? "2026-07-13" : "",
      PATH: `${dir}:${process.env.PATH ?? ""}`
    }
  });
  const log = existsSync(logPath) ? readFileSync(logPath, "utf8") : "";
  return { dir, log, result };
}

describe("mainnet deploy", () => {
  it("rejects draft or missing legal document versions", () => {
    const { dir, result } = runDeploy(false, false);
    try {
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("must be an approved, non-draft version for production");
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("keeps fresh mainnet deployment disabled for the MVP", () => {
    const { dir, log, result } = runDeploy(false);
    try {
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("mainnet deployment is intentionally disabled");
      expect(log).not.toContain("deploy ");
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("rejects direct upgrade of an existing canister until a transition audit is complete", () => {
    const { dir, log, result } = runDeploy(true);
    try {
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("mainnet deployment is intentionally disabled");
      expect(log).not.toContain("deploy ");
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

});
