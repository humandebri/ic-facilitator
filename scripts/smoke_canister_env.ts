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
  "FACILITATOR_PUBLIC_ORIGIN",
  "JPYC_EIP712_VERSION",
  "POLYGON_RPC_URL",
  "SELLER_CREDIT_PAY_TO",
  "SELLER_SETTLEMENT_FEE_AMOUNT",
  "SETTLE_CONFIRMATION_TIMEOUT_SECONDS",
  "SETTLE_MIN_CONFIRMATIONS",
  "SETTLEMENT_CACHE_TTL_SECONDS"
];

export const REQUIRED_BATCH_ENV_NAMES = [
  "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY",
  "BATCH_SETTLEMENT_CONTRACT",
  "BATCH_SETTLEMENT_FEE_AMOUNT",
  "BATCH_WITHDRAW_DELAY_SECONDS"
];

export const BATCH_ACTION_FEE_ENV_NAMES = [
  "BATCH_DEPOSIT_FEE_AMOUNT",
  "BATCH_CLAIM_FEE_AMOUNT",
  "BATCH_SETTLE_FEE_AMOUNT",
  "BATCH_REFUND_FEE_AMOUNT"
] as const;

export const BATCH_CLAIM_SCHEDULE_ENV_NAMES = [
  "BATCH_CLAIM_1_FEE_AMOUNT",
  "BATCH_CLAIM_10_FEE_AMOUNT",
  "BATCH_CLAIM_50_FEE_AMOUNT",
  "BATCH_CLAIM_100_FEE_AMOUNT",
  "BATCH_REFUND_WITH_CLAIM_1_FEE_AMOUNT",
  "BATCH_REFUND_WITH_CLAIM_10_FEE_AMOUNT",
  "BATCH_REFUND_WITH_CLAIM_50_FEE_AMOUNT",
  "BATCH_REFUND_WITH_CLAIM_100_FEE_AMOUNT"
] as const;

export type CanisterEnvSmokeResult = {
  readonly canister: string;
  readonly environment: string;
  readonly names: readonly string[];
};

export type CanisterEnvSmokeOptions = {
  readonly requireBatch?: boolean;
};

export function canisterEnvSmokeOptionsFromArgs(args: readonly string[]): CanisterEnvSmokeOptions {
  return {
    requireBatch: args.includes("--with-batch")
  };
}

export function parseEnvNames(output: string): string[] {
  const vec = /^\s*\(\s*vec\s*\{([\s\S]*)\}\s*,?\s*\)\s*$/.exec(output);
  if (!vec) {
    throw new Error("unexpected env_names output");
  }
  const body = vec[1];
  if (body === undefined) {
    throw new Error("unexpected env_names output");
  }
  return Array.from(body.matchAll(/"([A-Z0-9_]+)"/g), (match) => {
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

export function checkCanisterEnvNames(
  output: string,
  environment = "local",
  canister = "edge",
  options: CanisterEnvSmokeOptions = {}
): CanisterEnvSmokeResult {
  const names = parseEnvNames(output);
  const required = options.requireBatch ? [...REQUIRED_ENV_NAMES, ...REQUIRED_BATCH_ENV_NAMES] : REQUIRED_ENV_NAMES;
  const missing = required.filter((name) => !names.includes(name));
  if (missing.length > 0) {
    throw new Error(`missing canister env names: ${missing.join(", ")}`);
  }
  if (options.requireBatch) {
    const configuredActionNames = BATCH_ACTION_FEE_ENV_NAMES.filter((name) => names.includes(name));
    if (configuredActionNames.length > 0 && configuredActionNames.length < BATCH_ACTION_FEE_ENV_NAMES.length) {
      const missingActionNames = BATCH_ACTION_FEE_ENV_NAMES.filter((name) => !names.includes(name));
      throw new Error(`partial batch action fee env names: ${missingActionNames.join(", ")}`);
    }
    const configuredScheduleNames = BATCH_CLAIM_SCHEDULE_ENV_NAMES.filter((name) => names.includes(name));
    if (configuredScheduleNames.length > 0 && configuredScheduleNames.length < BATCH_CLAIM_SCHEDULE_ENV_NAMES.length) {
      const missingScheduleNames = BATCH_CLAIM_SCHEDULE_ENV_NAMES.filter((name) => !names.includes(name));
      throw new Error(`partial batch claim fee schedule env names: ${missingScheduleNames.join(", ")}`);
    }
  }
  return { canister, environment, names };
}

export function checkCanisterEnvSmoke(
  env: NodeJS.ProcessEnv = process.env,
  output?: string,
  options: CanisterEnvSmokeOptions = {}
): CanisterEnvSmokeResult {
  const environment = readEnv(env, "ICP_ENVIRONMENT") ?? "local";
  const canister = readEnv(env, "ICP_CANISTER") ?? "edge";
  return checkCanisterEnvNames(output ?? callEnvNames(environment, canister), environment, canister, options);
}

async function main(): Promise<void> {
  console.log(JSON.stringify(checkCanisterEnvSmoke(process.env, undefined, canisterEnvSmokeOptionsFromArgs(process.argv)), null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadDotenv();
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
