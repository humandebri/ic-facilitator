// scripts/smoke_canister_env.ts: canister に必要 env 名が注入済みかを secret 値なしで確認する。
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { loadDotenv } from "./env_file";

function envName(parts: readonly string[]): string {
  return parts.join("_");
}

const REQUIRED_ENV_NAMES = [
  envName(["FACILITATOR", "EVM", "PRIVATE", "KEY"]),
  "FACILITATOR_MAX_GAS",
  "FACILITATOR_MAX_SETTLEMENT_FEE_WEI",
  "JPYC_EIP712_VERSION",
  "POLYGON_RPC_SERVICES",
  "SELLER_CREDIT_PAY_TO",
  "SELLER_CREDIT_TOPUP_AMOUNT",
  "SELLER_SETTLEMENT_FEE_AMOUNT",
  "SETTLE_CONFIRMATION_TIMEOUT_SECONDS",
  "SETTLEMENT_CACHE_TTL_SECONDS"
];

export type CanisterEnvSmokeResult = {
  readonly canister: string;
  readonly environment: string;
  readonly names: readonly string[];
};

export function parseEnvNames(output: string): string[] {
  return Array.from(output.matchAll(/"([A-Z0-9_]+)"/g), (match) => {
    const value = match[1];
    if (!value) {
      throw new Error("failed to parse env name");
    }
    return value;
  });
}

function readEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name];
}

function callEnvNames(environment: string, canister: string): string {
  const result = spawnSync("icp", ["canister", "call", canister, "env_names", "()", "--environment", environment], {
    encoding: "utf8"
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    throw new Error(output.trim());
  }
  return output;
}

export function checkCanisterEnvNames(output: string, environment = "local", canister = "edge"): CanisterEnvSmokeResult {
  const names = parseEnvNames(output);
  const missing = REQUIRED_ENV_NAMES.filter((name) => !names.includes(name));
  if (missing.length > 0) {
    throw new Error(`missing canister env names: ${missing.join(", ")}`);
  }
  return { canister, environment, names };
}

export function checkCanisterEnvSmoke(env: NodeJS.ProcessEnv = process.env, output?: string): CanisterEnvSmokeResult {
  const environment = readEnv(env, "ICP_ENVIRONMENT") ?? "local";
  const canister = readEnv(env, "ICP_CANISTER") ?? "edge";
  return checkCanisterEnvNames(output ?? callEnvNames(environment, canister), environment, canister);
}

async function main(): Promise<void> {
  console.log(JSON.stringify(checkCanisterEnvSmoke(process.env), null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadDotenv();
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
