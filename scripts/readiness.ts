// scripts/readiness.ts: canister facilitator 実決済までの未充足条件を秘密値なしで集約する。
import { pathToFileURL } from "node:url";

import { BATCH_SETTLEMENT_ADDRESS } from "@x402/evm";

import { collectChecks } from "./doctor";
import type { DoctorCheck, DoctorStatus } from "./doctor";
import { checkWallet, requirePrivateKey } from "./jpyc_wallet";
import { checkCanisterEnvSmoke } from "./smoke_canister_env";
import { checkCanisterSmoke } from "./smoke_canister";
import { checkPaidNegativeSmoke } from "./smoke_canister_paid_negative";
import { loadDotenv } from "./env_file";
import { expectedSettlementSenderFromEnv, expectedTransferFromEnv, parseTxHash, settlementMinConfirmationsFromEnv, verifySettlementReceipt } from "./settlement_receipt";
import type { ReceiptReader } from "./settlement_receipt";
import { checkBatchMainnetPreflight } from "./batch_mainnet_preflight";
import type { BatchMainnetPreflightReader } from "./batch_mainnet_preflight";
import { batchSettlementReceiptOptionsFromEnv, verifyBatchSettlementReceipt } from "./batch_settlement_receipt";
import type { BatchSettlementReceiptReader } from "./batch_settlement_receipt";

type StageName = "batch-mainnet-preflight" | "batch-settlement-receipt" | "buyer" | "canister" | "canister-env" | "canister-http" | "paid-negative-http" | "settlement-receipt" | "wallet";
const DEPLOY_ONLY_FAILURES = ["disk-space", "node_modules", "rust-target"];
const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const BATCH_RECEIPT_ENV_NEXT_COMMANDS: Readonly<Record<string, string>> = {
  BATCH_CHANNEL_ID: "set BATCH_CHANNEL_ID to the batch channel id",
  BATCH_DEPOSIT_AMOUNT: "set BATCH_DEPOSIT_AMOUNT to the deposited amount",
  BATCH_EXPECTED_MIN_BALANCE: "set BATCH_EXPECTED_MIN_BALANCE to the expected post-deposit channel balance",
  BATCH_EXPECTED_MIN_REFUND_NONCE: "set BATCH_EXPECTED_MIN_REFUND_NONCE to the expected post-refund nonce floor",
  BATCH_EXPECTED_TOTAL_CLAIMED: "set BATCH_EXPECTED_TOTAL_CLAIMED to the expected post-claim totalClaimed",
  BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key",
  BATCH_SETTLE_AMOUNT: "set BATCH_SETTLE_AMOUNT to the positive settled amount from the settle event",
  BATCH_SETTLE_RECEIVER: "set BATCH_SETTLE_RECEIVER to the expected batch receiver address",
  BATCH_SETTLEMENT_ACTION: "set BATCH_SETTLEMENT_ACTION to deposit, claim, settle, or refund",
  BATCH_SETTLEMENT_CONTRACT: `set BATCH_SETTLEMENT_CONTRACT=${BATCH_SETTLEMENT_ADDRESS}`,
  BATCH_SETTLEMENT_TX: "set BATCH_SETTLEMENT_TX to the batch settlement transaction hash",
  BATCH_WITHDRAW_DELAY_SECONDS: "set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds",
  FACILITATOR_EVM_PRIVATE_KEY: "set FACILITATOR_EVM_PRIVATE_KEY to the facilitator settlement private key"
};

export type ReadinessStage = {
  readonly failures: readonly string[];
  readonly name: StageName;
  readonly status: DoctorStatus;
  readonly warnings: readonly string[];
};

export type ReadinessReport = {
  readonly nextCommands: readonly string[];
  readonly readyForPreflight: boolean;
  readonly realSettlementVerified: boolean;
  readonly stages: readonly ReadinessStage[];
};

export type ReadinessOptions = {
  readonly batchPreflightReader?: BatchMainnetPreflightReader;
  readonly batchSettlementReceiptReader?: BatchSettlementReceiptReader;
  readonly canisterEnvNamesOutput?: string;
  readonly fetchFn?: typeof fetch;
  readonly includeBatchMainnetPreflight?: boolean;
  readonly includeBatchSettlementReceipt?: boolean;
  readonly includeCanisterEnvSmoke?: boolean;
  readonly includeCanisterSmoke?: boolean;
  readonly includePaidNegativeSmoke?: boolean;
  readonly includeSettlementReceipt?: boolean;
  readonly includeWallet?: boolean;
  readonly receiptReader?: ReceiptReader;
  readonly walletCheck?: () => Promise<void>;
};

function worstStatus(checks: readonly DoctorCheck[]): DoctorStatus {
  if (checks.some((check) => check.status === "fail")) { return "fail"; }
  if (checks.some((check) => check.status === "warn")) { return "warn"; }
  return "ok";
}

function namesWithStatus(checks: readonly DoctorCheck[], status: DoctorStatus): readonly string[] {
  return checks.filter((check) => check.status === status).map((check) => check.name);
}

function stage(name: StageName, checks: readonly DoctorCheck[]): ReadinessStage {
  return { failures: namesWithStatus(checks, "fail"), name, status: worstStatus(checks), warnings: namesWithStatus(checks, "warn") };
}

function failureStage(name: StageName, message: string): ReadinessStage {
  return { failures: [`${name}:${message}`], name, status: "fail", warnings: [] };
}

function isDeployOnlyFailure(name: string): boolean {
  return DEPLOY_ONLY_FAILURES.includes(name) || name.startsWith("command:");
}

function runtimeCanisterOk(stages: readonly ReadinessStage[]): boolean {
  return stages.some((item) => item.name === "canister-env" && item.status === "ok") &&
    stages.some((item) => item.name === "canister-http" && item.status === "ok");
}

function softenDeployOnlyCanisterFailures(stages: readonly ReadinessStage[]): readonly ReadinessStage[] {
  if (!runtimeCanisterOk(stages)) { return stages; }
  return stages.map((item) => {
    if (item.name !== "canister" || item.failures.length === 0) { return item; }
    const failures = item.failures.filter((failure) => !isDeployOnlyFailure(failure));
    const warnings = item.failures
      .filter(isDeployOnlyFailure)
      .map((failure) => `deploy-warning:${failure}`);
    return {
      ...item,
      failures,
      status: failures.length > 0 ? "fail" : item.warnings.length + warnings.length > 0 ? "warn" : "ok",
      warnings: [...item.warnings, ...warnings]
    };
  });
}

function nextCommands(stages: readonly ReadinessStage[], env: NodeJS.ProcessEnv): readonly string[] {
  const commands: string[] = [];
  const settlementFailures = stages.filter((item) => item.name === "settlement-receipt" && item.status === "fail").flatMap((item) => item.failures);
  const canPay = stages.filter((item) => item.name !== "settlement-receipt").every((item) => item.status === "ok");
  const batchMode = wantsBatchReadiness(stages, env);

  if (stages.some((item) => item.name === "canister" && item.status === "fail")) {
    commands.push("npm run doctor -- --mode=canister");
  }
  if (stages.some((item) => item.failures.includes("env:FACILITATOR_EVM_PRIVATE_KEY"))) {
    const remote = env.X402_BASE_URL && !env.X402_BASE_URL.includes("localhost") && !env.X402_BASE_URL.includes("127.0.0.1");
    commands.push(remote ? "set FACILITATOR_EVM_PRIVATE_KEY, then run npm run ic:env:mainnet" : "set FACILITATOR_EVM_PRIVATE_KEY, then run npm run ic:env:local");
  }
  if (!canPay && stages.some((item) => item.warnings.includes("deploy-warning:disk-space"))) {
    commands.push("npm run clean:build");
  }
  if (stages.some((item) => item.name === "buyer" && item.status === "fail")) {
    commands.push("npm run doctor -- --mode=buyer");
  }
  if (stages.some((item) => item.name === "canister-env" && item.status === "fail")) {
    commands.push(batchMode ? "npm run smoke:canister:env -- --with-batch" : "npm run smoke:canister:env");
  }
  if (stages.some((item) => item.name === "canister-http" && item.status === "fail")) {
    commands.push(batchMode ? "npm run smoke:canister -- --with-batch" : "npm run smoke:canister");
  }
  if (stages.some((item) => item.name === "paid-negative-http" && item.status === "fail")) {
    commands.push("npm run smoke:canister:paid-negative");
  }
  for (const item of stages) {
    if (item.name !== "batch-mainnet-preflight" || item.status !== "fail") {
      continue;
    }
    for (const failure of item.failures) {
      for (const command of batchPreflightNextCommands(failure)) {
        commands.push(command);
      }
    }
  }
  if (stages.some((item) => item.name === "batch-settlement-receipt" && item.status === "fail")) {
    commands.push(...batchReceiptEnvNextCommands(stages));
    commands.push("npm run receipt:batch");
  }
  if (stages.some((item) => item.name === "wallet" && item.status === "fail")) {
    commands.push("complete buyer JPYC balance, then run npm run wallet:jpyc");
  }
  if (settlementFailures.length > 0) {
    if (settlementFailures.some((failure) => failure.includes("missing required env: SETTLEMENT_TX"))) {
      if (canPay) {
        commands.push("npm run pay:jpyc", "export SETTLEMENT_TX=0x...");
      }
    }
    if (canPay || !settlementFailures.some((failure) => failure.includes("missing required env: SETTLEMENT_TX"))) {
      commands.push("npm run receipt:settlement");
    }
  }
  if (commands.length === 0) {
    if (!stages.some((item) => item.name === "canister-env")) {
      commands.push("npm run readiness:jpyc -- --with-canister-env-smoke");
    }
    if (!stages.some((item) => item.name === "canister-http")) {
      commands.push("npm run readiness:jpyc -- --with-canister-smoke");
    }
    if (!stages.some((item) => item.name === "paid-negative-http")) {
      commands.push("npm run readiness:jpyc -- --with-paid-negative-smoke");
    }
    if (env.BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY && !stages.some((item) => item.name === "batch-mainnet-preflight")) {
      commands.push("npm run readiness:jpyc -- --with-batch-mainnet-preflight");
    }
    commands.push("npm run wallet:jpyc", "npm run pay:jpyc");
    if (!stages.some((item) => item.name === "settlement-receipt")) {
      commands.push("npm run readiness:jpyc -- --with-settlement-receipt");
    }
  }
  return commands;
}

function batchReceiptEnvNextCommands(stages: readonly ReadinessStage[]): readonly string[] {
  const commands: string[] = [];
  for (const item of stages) {
    if (item.name !== "batch-settlement-receipt" || item.status !== "fail") {
      continue;
    }
    for (const failure of item.failures) {
      const match = /^batch-settlement-receipt:missing required env: ([A-Z0-9_]+)$/.exec(failure);
      const envName = match?.[1];
      const command = envName === undefined ? undefined : BATCH_RECEIPT_ENV_NEXT_COMMANDS[envName];
      if (command !== undefined) {
        commands.push(command);
      }
    }
  }
  return Array.from(new Set(commands));
}

function batchPreflightNextCommands(failure: string): readonly string[] {
  const name = failure.split(":", 2).join(":");
  switch (name) {
    case "env:POLYGON_RPC_URL":
      return ["set POLYGON_RPC_URL to a Polygon HTTPS RPC URL"];
    case "env:JPYC_POLYGON_ADDRESS":
      return ["unset JPYC_POLYGON_ADDRESS or set it to the fixed JPYC Polygon address"];
    case "env:JPYC_EIP712_VERSION":
      return ["set JPYC_EIP712_VERSION=1"];
    case "env:BATCH_SETTLEMENT_CONTRACT":
      return [`set BATCH_SETTLEMENT_CONTRACT=${BATCH_SETTLEMENT_ADDRESS}`];
    case "env:BATCH_WITHDRAW_DELAY_SECONDS":
      return ["set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds"];
    case "env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY":
      return ["set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key"];
    case "env:BATCH_SETTLEMENT_FEE_AMOUNT":
      return ["set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer"];
    case "env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL":
      return ["set BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL to the resource server actor principal"];
    default:
      return ["npm run preflight:batch"];
  }
}

function readyForPreflight(stages: readonly ReadinessStage[]): boolean {
  return stages.filter((item) => item.name !== "settlement-receipt").every((item) => item.status === "ok");
}

function realSettlementVerified(stages: readonly ReadinessStage[]): boolean {
  return stages.some((item) => item.name === "settlement-receipt" && item.status === "ok");
}

function hasBatchStage(stages: readonly ReadinessStage[]): boolean {
  return stages.some((item) => item.name === "batch-mainnet-preflight" || item.name === "batch-settlement-receipt");
}

function wantsBatchReadiness(stages: readonly ReadinessStage[], env: NodeJS.ProcessEnv): boolean {
  return hasBatchStage(stages) || Boolean(env.BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY || env.BATCH_SETTLEMENT_CONTRACT);
}

export function buildReadinessReport(cwd: string, env: NodeJS.ProcessEnv): ReadinessReport {
  const stages = [
    stage("canister", collectChecks(cwd, env, "canister")),
    stage("buyer", collectChecks(cwd, env, "buyer"))
  ];
  return {
    nextCommands: nextCommands(stages, env),
    readyForPreflight: readyForPreflight(stages),
    realSettlementVerified: false,
    stages
  };
}

export function shouldFailReadiness(report: ReadinessReport, requireSettlementReceipt: boolean): boolean {
  return !report.readyForPreflight || (requireSettlementReceipt && !report.realSettlementVerified);
}

async function settlementReceiptStage(env: NodeJS.ProcessEnv, reader?: ReceiptReader): Promise<ReadinessStage> {
  const tx = env.SETTLEMENT_TX;
  if (!tx || tx.trim() === "") {
    return failureStage("settlement-receipt", "missing required env: SETTLEMENT_TX");
  }
  if (!env.BUYER_EVM_PRIVATE_KEY || env.BUYER_EVM_PRIVATE_KEY.trim() === "") {
    return failureStage("settlement-receipt", "missing required env: BUYER_EVM_PRIVATE_KEY");
  }
  try {
    await verifySettlementReceipt({
      hash: parseTxHash(tx),
      ...(env.POLYGON_RPC_URL ? { rpcUrl: env.POLYGON_RPC_URL } : {}),
      ...(reader ? { reader } : {}),
      expectedFrom: expectedSettlementSenderFromEnv(env),
      expectedTo: env.JPYC_POLYGON_ADDRESS ?? DEFAULT_JPYC_POLYGON_ADDRESS,
      expectedTransfer: expectedTransferFromEnv(env),
      minConfirmations: settlementMinConfirmationsFromEnv(env)
    });
    return { failures: [], name: "settlement-receipt", status: "ok", warnings: [] };
  } catch (error: unknown) {
    return failureStage("settlement-receipt", error instanceof Error ? error.message : String(error));
  }
}

async function walletStage(walletCheck?: () => Promise<void>): Promise<ReadinessStage> {
  try {
    await (walletCheck ? walletCheck() : checkWallet(requirePrivateKey()));
    return { failures: [], name: "wallet", status: "ok", warnings: [] };
  } catch (error: unknown) {
    return failureStage("wallet", error instanceof Error ? error.message : String(error));
  }
}

async function batchMainnetPreflightStage(env: NodeJS.ProcessEnv, reader?: BatchMainnetPreflightReader): Promise<ReadinessStage> {
  try {
    const report = await checkBatchMainnetPreflight({ env, ...(reader ? { reader } : {}) });
    const failures = report.checks
      .filter((check) => check.status === "fail")
      .map((check) => `${check.name}:${check.detail}`);
    return { failures, name: "batch-mainnet-preflight", status: failures.length > 0 ? "fail" : "ok", warnings: [] };
  } catch (error: unknown) {
    return failureStage("batch-mainnet-preflight", error instanceof Error ? error.message : String(error));
  }
}

async function batchSettlementReceiptStage(env: NodeJS.ProcessEnv, reader?: BatchSettlementReceiptReader): Promise<ReadinessStage> {
  try {
    await verifyBatchSettlementReceipt({
      ...batchSettlementReceiptOptionsFromEnv(env),
      ...(reader ? { reader } : {})
    });
    return { failures: [], name: "batch-settlement-receipt", status: "ok", warnings: [] };
  } catch (error: unknown) {
    return failureStage("batch-settlement-receipt", error instanceof Error ? error.message : String(error));
  }
}

export async function buildReadinessReportWithSmoke(
  cwd: string,
  env: NodeJS.ProcessEnv,
  options: ReadinessOptions = {}
): Promise<ReadinessReport> {
  const base = buildReadinessReport(cwd, env);
  let stages = [...base.stages];
  const requireBatchSmoke = Boolean(options.includeBatchMainnetPreflight || options.includeBatchSettlementReceipt);
  if (options.includeCanisterEnvSmoke) {
    try {
      checkCanisterEnvSmoke(env, options.canisterEnvNamesOutput, { requireBatch: requireBatchSmoke });
      stages = [...stages, { failures: [], name: "canister-env", status: "ok", warnings: [] }];
    } catch (error: unknown) {
      stages = [...stages, failureStage("canister-env", error instanceof Error ? error.message : String(error))];
    }
  }
  if (options.includeCanisterSmoke) {
    try {
      await checkCanisterSmoke(
        options.fetchFn
          ? { allowMissingSeller: true, env, fetchFn: options.fetchFn, requireBatch: requireBatchSmoke }
          : { allowMissingSeller: true, env, requireBatch: requireBatchSmoke }
      );
      stages = [...stages, { failures: [], name: "canister-http", status: "ok", warnings: [] }];
    } catch (error: unknown) {
      stages = [...stages, failureStage("canister-http", error instanceof Error ? error.message : String(error))];
    }
  }
  if (options.includePaidNegativeSmoke) {
    try {
      await checkPaidNegativeSmoke(env, options.fetchFn ?? fetch);
      stages = [...stages, { failures: [], name: "paid-negative-http", status: "ok", warnings: [] }];
    } catch (error: unknown) {
      stages = [...stages, failureStage("paid-negative-http", error instanceof Error ? error.message : String(error))];
    }
  }
  if (options.includeWallet) {
    stages = [...stages, await walletStage(options.walletCheck)];
  }
  if (options.includeSettlementReceipt) {
    stages = [...stages, await settlementReceiptStage(env, options.receiptReader)];
  }
  if (options.includeBatchMainnetPreflight) {
    stages = [...stages, await batchMainnetPreflightStage(env, options.batchPreflightReader)];
  }
  if (options.includeBatchSettlementReceipt) {
    stages = [...stages, await batchSettlementReceiptStage(env, options.batchSettlementReceiptReader)];
  }
  stages = [...softenDeployOnlyCanisterFailures(stages)];
  return {
    nextCommands: nextCommands(stages, env),
    readyForPreflight: readyForPreflight(stages),
    realSettlementVerified: realSettlementVerified(stages),
    stages
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  const requireSettlementReceipt = process.argv.includes("--with-settlement-receipt");
  buildReadinessReportWithSmoke(process.cwd(), process.env, {
    includeBatchMainnetPreflight: process.argv.includes("--with-batch-mainnet-preflight"),
    includeBatchSettlementReceipt: process.argv.includes("--with-batch-settlement-receipt"),
    includeCanisterEnvSmoke: process.argv.includes("--with-canister-env-smoke"),
    includeCanisterSmoke: process.argv.includes("--with-canister-smoke"),
    includePaidNegativeSmoke: process.argv.includes("--with-paid-negative-smoke"),
    includeSettlementReceipt: requireSettlementReceipt,
    includeWallet: process.argv.includes("--with-wallet")
  }).then((report) => {
    console.log(JSON.stringify(report, null, 2));
    if (shouldFailReadiness(report, requireSettlementReceipt)) {
      process.exitCode = 1;
    }
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
