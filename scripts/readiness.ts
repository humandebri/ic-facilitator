// scripts/readiness.ts: canister facilitator 実決済までの未充足条件を秘密値なしで集約する。
import { pathToFileURL } from "node:url";

import { collectChecks } from "./doctor";
import type { DoctorCheck, DoctorStatus } from "./doctor";
import { checkWallet, requirePrivateKey } from "./jpyc_wallet";
import { checkCanisterEnvSmoke } from "./smoke_canister_env";
import { checkCanisterSmoke } from "./smoke_canister";
import { checkPaidNegativeSmoke } from "./smoke_canister_paid_negative";
import { loadDotenv } from "./env_file";
import { expectedTransferFromEnv, parseTxHash, verifySettlementReceipt } from "./settlement_receipt";
import type { ReceiptReader } from "./settlement_receipt";

type StageName = "buyer" | "canister" | "canister-env" | "canister-http" | "paid-negative-http" | "settlement-receipt" | "wallet";
const DEPLOY_ONLY_FAILURES = ["disk-space", "node_modules", "rust-target"];
const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";

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
  readonly canisterEnvNamesOutput?: string;
  readonly fetchFn?: typeof fetch;
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
    commands.push("npm run smoke:canister:env");
  }
  if (stages.some((item) => item.name === "canister-http" && item.status === "fail")) {
    commands.push("npm run smoke:canister");
  }
  if (stages.some((item) => item.name === "paid-negative-http" && item.status === "fail")) {
    commands.push("npm run smoke:canister:paid-negative");
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
    commands.push("npm run wallet:jpyc", "npm run pay:jpyc");
    if (!stages.some((item) => item.name === "settlement-receipt")) {
      commands.push("npm run readiness:jpyc -- --with-settlement-receipt");
    }
  }
  return commands;
}

function readyForPreflight(stages: readonly ReadinessStage[]): boolean {
  return stages.filter((item) => item.name !== "settlement-receipt").every((item) => item.status === "ok");
}

function realSettlementVerified(stages: readonly ReadinessStage[]): boolean {
  return stages.some((item) => item.name === "settlement-receipt" && item.status === "ok");
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
      expectedTo: env.JPYC_POLYGON_ADDRESS ?? DEFAULT_JPYC_POLYGON_ADDRESS,
      expectedTransfer: expectedTransferFromEnv(env)
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

export async function buildReadinessReportWithSmoke(
  cwd: string,
  env: NodeJS.ProcessEnv,
  options: ReadinessOptions = {}
): Promise<ReadinessReport> {
  const base = buildReadinessReport(cwd, env);
  let stages = [...base.stages];
  if (options.includeCanisterEnvSmoke) {
    try {
      checkCanisterEnvSmoke(env, options.canisterEnvNamesOutput);
      stages = [...stages, { failures: [], name: "canister-env", status: "ok", warnings: [] }];
    } catch (error: unknown) {
      stages = [...stages, failureStage("canister-env", error instanceof Error ? error.message : String(error))];
    }
  }
  if (options.includeCanisterSmoke) {
    try {
      await checkCanisterSmoke(options.fetchFn ? { allowMissingSeller: true, env, fetchFn: options.fetchFn } : { allowMissingSeller: true, env });
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
