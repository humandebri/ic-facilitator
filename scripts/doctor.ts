// scripts/doctor.ts: JPYC x402 facilitator の実行前提を副作用なしで検査する。
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

import { positiveDecimalToAtomicUnits } from "../src/amount";
import { loadDotenv } from "./env_file";

export type DoctorMode = "all" | "buyer" | "canister";
export type DoctorStatus = "fail" | "ok" | "warn";

export type DoctorCheck = {
  readonly detail: string;
  readonly fix?: string;
  readonly name: string;
  readonly status: DoctorStatus;
};

const RUST_TARGET = "wasm32-unknown-unknown";
const JPYC_DECIMALS = 18;
const MIN_CANISTER_DISK_KIB = 2 * 1024 * 1024;
const FIXED_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";

function envName(parts: readonly string[]): string {
  return parts.join("_");
}

const FACILITATOR_SIGNER_ENV = envName(["FACILITATOR", "EVM", "PRIVATE", "KEY"]);
const BUYER_SIGNER_ENV = envName(["BUYER", "EVM", "PRIVATE", "KEY"]);

const REQUIRED_COMMANDS = ["icp", "ic-wasm", "candid-extractor", "cargo", "rustup"];
const CANISTER_ENVS = [
  FACILITATOR_SIGNER_ENV,
  "FACILITATOR_PUBLIC_ORIGIN",
  "JPYC_EIP712_VERSION",
  "POLYGON_RPC_SERVICES",
  "SELLER_CREDIT_PAY_TO",
  "SELLER_CREDIT_TOPUP_AMOUNT",
  "SELLER_SETTLEMENT_FEE_AMOUNT"
];
const BUYER_ENVS = [BUYER_SIGNER_ENV, "JPYC_EIP712_VERSION", "POLYGON_RPC_URL", "SELLER_EVM_ADDRESS", "X402_TARGET_URL"];
const SAMPLE_SELLER_ADDRESS = "0x0000000000000000000000000000000000000402";

function ok(name: string, detail: string): DoctorCheck { return { detail, name, status: "ok" }; }
function warn(name: string, detail: string, fix?: string): DoctorCheck { return fix ? { detail, fix, name, status: "warn" } : { detail, name, status: "warn" }; }
function fail(name: string, detail: string, fix?: string): DoctorCheck { return fix ? { detail, fix, name, status: "fail" } : { detail, name, status: "fail" }; }

function run(command: string, args: string[]): { readonly output: string; readonly status: number | null } {
  const result = spawnSync(command, args, { encoding: "utf8" });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  return { output, status: result.status };
}

function commandExists(command: string): boolean {
  return run("which", [command]).status === 0;
}

function commandCheck(command: string): DoctorCheck {
  if (!commandExists(command)) {
    return fail(`command:${command}`, "PATH に存在しない", `${command} を install する`);
  }
  const version = run(command, ["--version"]).output.split(/\r?\n/)[0] ?? "";
  return ok(`command:${command}`, version || "検出済み");
}

export function hasInstalledRustTarget(output: string, target: string): boolean {
  return output.split(/\r?\n/).includes(target);
}

function rustTargetCheck(): DoctorCheck {
  const result = run("rustup", ["target", "list", "--installed"]);
  if (result.status !== 0) {
    return fail("rust-target", "installed target を取得できない", "rustup を確認する");
  }
  if (!hasInstalledRustTarget(result.output, RUST_TARGET)) {
    return fail("rust-target", `${RUST_TARGET} が未追加`, `rustup target add ${RUST_TARGET}`);
  }
  return ok("rust-target", RUST_TARGET);
}

export function parseAvailableDiskKiB(output: string): number | null {
  const line = output.split(/\r?\n/).find((item) => item.trim() !== "" && !item.startsWith("Filesystem"));
  const available = Number(line?.trim().split(/\s+/)[3]);
  return Number.isInteger(available) && available >= 0 ? available : null;
}

function diskSpaceCheck(cwd: string): DoctorCheck {
  const result = run("df", ["-Pk", cwd]);
  if (result.status !== 0) { return warn("disk-space", "空き容量を確認できない", "df -h . を確認する"); }
  const available = parseAvailableDiskKiB(result.output);
  if (available === null) { return warn("disk-space", "df 出力を解釈できない", "df -h . を確認する"); }
  const availableMiB = Math.floor(available / 1024);
  if (available < MIN_CANISTER_DISK_KIB) {
    return fail("disk-space", `${availableMiB} MiB available`, "local IC build/upload 前に 2 GiB 以上空ける");
  }
  return ok("disk-space", `${availableMiB} MiB available`);
}

export function envPresenceCheck(name: string, env: NodeJS.ProcessEnv): DoctorCheck {
  const value = env[name];
  if (!value || value.trim() === "") { return fail(`env:${name}`, "未設定", `.env または shell に ${name} を設定する`); }
  return ok(`env:${name}`, "設定済み");
}

export function isEvmAddress(value: string): boolean { return /^0x[0-9a-fA-F]{40}$/.test(value); }
function isZeroAddress(value: string): boolean { return /^0x0{40}$/i.test(value); }
export function isPrivateKey(value: string): boolean { return /^0x[0-9a-fA-F]{64}$/.test(value); }

export function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}
function isHttpsUrl(value: string): boolean { return isHttpUrl(value) && new URL(value).protocol === "https:"; }
export function isHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    const host = value.slice("https://".length);
    return url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === "" &&
      value.startsWith("https://") &&
      value !== `${url.origin}/` &&
      host !== "" &&
      /^[^/:@?#\s]+(?::[0-9]+)?$/.test(host);
  } catch {
    return false;
  }
}
export function isSingleHttpsRpcServices(value: string): boolean {
  const services = value.split(",").map((item) => item.trim()).filter((item) => item !== "");
  return services.length === 1 && isHttpsOrigin(services[0] ?? "");
}
export function isPositiveIntegerString(value: string): boolean {
  return /^[1-9][0-9]*$/.test(value);
}

function isJpycPrice(value: string): boolean { try { positiveDecimalToAtomicUnits(value, JPYC_DECIMALS, "JPYC_PRICE"); return true; } catch { return false; } }

function canisterEnvChecks(env: NodeJS.ProcessEnv): DoctorCheck[] {
  const checks = CANISTER_ENVS.map((name) => envPresenceCheck(name, env));
  const jpycAddress = env.JPYC_POLYGON_ADDRESS;
  const privateKey = env[FACILITATOR_SIGNER_ENV];
  const maxGas = env.FACILITATOR_MAX_GAS;
  const maxSettlementFeeWei = env.FACILITATOR_MAX_SETTLEMENT_FEE_WEI;
  const publicOrigin = env.FACILITATOR_PUBLIC_ORIGIN;
  const rpcServices = env.POLYGON_RPC_SERVICES;
  const sellerCreditPayTo = env.SELLER_CREDIT_PAY_TO;
  const sellerCreditTopupAmount = env.SELLER_CREDIT_TOPUP_AMOUNT;
  const sellerSettlementFeeAmount = env.SELLER_SETTLEMENT_FEE_AMOUNT;
  const settleTimeout = env.SETTLE_CONFIRMATION_TIMEOUT_SECONDS;
  const settleMinConfirmations = env.SETTLE_MIN_CONFIRMATIONS;
  const settlementCacheTtl = env.SETTLEMENT_CACHE_TTL_SECONDS;

  if (privateKey && !isPrivateKey(privateKey)) {
    checks.push(fail(`env-format:${FACILITATOR_SIGNER_ENV}`, "0x-prefixed 32-byte private key ではない"));
  }
  if (jpycAddress) {
    checks.push(warn("env:JPYC_POLYGON_ADDRESS", `canister は固定値 ${FIXED_JPYC_POLYGON_ADDRESS} を使う`, ".env から JPYC_POLYGON_ADDRESS を削除する"));
  }
  if (maxGas && !isPositiveIntegerString(maxGas)) {
    checks.push(fail("env-format:FACILITATOR_MAX_GAS", "正の integer string ではない"));
  }
  if (maxSettlementFeeWei && !isPositiveIntegerString(maxSettlementFeeWei)) {
    checks.push(fail("env-format:FACILITATOR_MAX_SETTLEMENT_FEE_WEI", "正の integer string ではない"));
  }
  if (publicOrigin && !isHttpsOrigin(publicOrigin)) {
    checks.push(fail("env-format:FACILITATOR_PUBLIC_ORIGIN", "HTTPS origin ではない"));
  }
  if (rpcServices && !isSingleHttpsRpcServices(rpcServices)) {
    checks.push(fail("env-format:POLYGON_RPC_SERVICES", "単一 HTTPS RPC URL ではない"));
  }
  if (sellerCreditPayTo && (!isEvmAddress(sellerCreditPayTo) || isZeroAddress(sellerCreditPayTo))) {
    checks.push(fail("env-format:SELLER_CREDIT_PAY_TO", "non-zero 0x-prefixed 20-byte EVM address ではない"));
  }
  if (sellerCreditTopupAmount && !isPositiveIntegerString(sellerCreditTopupAmount)) {
    checks.push(fail("env-format:SELLER_CREDIT_TOPUP_AMOUNT", "正の integer string ではない"));
  }
  if (sellerSettlementFeeAmount && !isPositiveIntegerString(sellerSettlementFeeAmount)) {
    checks.push(fail("env-format:SELLER_SETTLEMENT_FEE_AMOUNT", "正の integer string ではない"));
  }
  if (settleTimeout && !isPositiveIntegerString(settleTimeout)) {
    checks.push(fail("env-format:SETTLE_CONFIRMATION_TIMEOUT_SECONDS", "正の integer string ではない"));
  }
  if (settleMinConfirmations && !isPositiveIntegerString(settleMinConfirmations)) {
    checks.push(fail("env-format:SETTLE_MIN_CONFIRMATIONS", "正の integer string ではない"));
  }
  if (settlementCacheTtl && !isPositiveIntegerString(settlementCacheTtl)) {
    checks.push(fail("env-format:SETTLEMENT_CACHE_TTL_SECONDS", "正の integer string ではない"));
  }
  return checks;
}

function buyerEnvChecks(env: NodeJS.ProcessEnv): DoctorCheck[] {
  const checks = BUYER_ENVS.map((name) => envPresenceCheck(name, env));
  const jpycAddress = env.JPYC_POLYGON_ADDRESS;
  const jpycPrice = env.JPYC_PRICE;
  const privateKey = env[BUYER_SIGNER_ENV];
  const resourceUrl = env.X402_RESOURCE_URL;
  const rpcUrl = env.POLYGON_RPC_URL;
  const seller = env.SELLER_EVM_ADDRESS;
  const targetUrl = env.X402_TARGET_URL;

  if (jpycAddress && (!isEvmAddress(jpycAddress) || isZeroAddress(jpycAddress))) {
    checks.push(fail("env-format:JPYC_POLYGON_ADDRESS", "non-zero 0x-prefixed 20-byte EVM address ではない"));
  }
  if (jpycPrice && !isJpycPrice(jpycPrice)) {
    checks.push(fail("env-format:JPYC_PRICE", "正の decimal string ではない"));
  }
  if (privateKey && !isPrivateKey(privateKey)) {
    checks.push(fail(`env-format:${BUYER_SIGNER_ENV}`, "0x-prefixed 32-byte private key ではない"));
  }
  if (rpcUrl && !isHttpUrl(rpcUrl)) {
    checks.push(fail("env-format:POLYGON_RPC_URL", "http(s) URL ではない"));
  }
  if (targetUrl && !isHttpUrl(targetUrl)) {
    checks.push(fail("env-format:X402_TARGET_URL", "http(s) URL ではない"));
  }
  if (targetUrl && !isHttpsUrl(targetUrl) && !resourceUrl) {
    checks.push(fail("env:X402_RESOURCE_URL", "HTTP target では必須", "payment-required resource URL を HTTPS で設定する"));
  }
  if (resourceUrl && !isHttpsUrl(resourceUrl)) {
    checks.push(fail("env-format:X402_RESOURCE_URL", "HTTPS URL ではない"));
  }
  if (seller && (!isEvmAddress(seller) || isZeroAddress(seller))) {
    checks.push(fail("env-format:SELLER_EVM_ADDRESS", "non-zero 0x-prefixed 20-byte EVM address ではない"));
  }
  if (seller?.toLowerCase() === SAMPLE_SELLER_ADDRESS.toLowerCase()) { checks.push(fail("env:SELLER_EVM_ADDRESS_SAMPLE", "sample seller address のまま", "実 seller address を設定する")); }
  return checks;
}

function envChecks(mode: DoctorMode, env: NodeJS.ProcessEnv): DoctorCheck[] {
  if (mode === "buyer") {
    return buyerEnvChecks(env);
  }
  if (mode === "canister") {
    return canisterEnvChecks(env);
  }
  return canisterEnvChecks(env).concat(buyerEnvChecks(env));
}

function nodeVersionCheck(): DoctorCheck {
  const major = Number(process.versions.node.split(".")[0] ?? "0");
  if (!Number.isInteger(major) || major < 20) { return fail("node", `Node.js ${process.versions.node}`, "Node.js 20 以上を使う"); }
  return ok("node", `Node.js ${process.versions.node}`);
}

function nodeModulesCheck(cwd: string): DoctorCheck {
  if (!existsSync(`${cwd}/node_modules`)) { return fail("node_modules", "未作成", "npm install を実行する"); }
  return ok("node_modules", "検出済み");
}

function rustCanisterCheck(cwd: string): DoctorCheck {
  if (!existsSync(`${cwd}/rust/facilitator/Cargo.toml`)) {
    return fail("rust-facilitator", "crate が存在しない");
  }
  return ok("rust-facilitator", "検出済み");
}

export function parseMode(args: readonly string[]): DoctorMode {
  const modeIndex = args.findIndex((arg) => arg === "--mode");
  const modeArg = args.find((arg) => arg.startsWith("--mode="));
  const mode = modeArg?.slice("--mode=".length) ?? (modeIndex >= 0 ? args[modeIndex + 1] : undefined);
  if (mode === "buyer" || mode === "canister" || mode === "all") { return mode; }
  return "all";
}

export function collectChecks(cwd: string, env: NodeJS.ProcessEnv, mode: DoctorMode): DoctorCheck[] {
  const checks = [nodeVersionCheck(), nodeModulesCheck(cwd)];
  if (mode === "all" || mode === "canister") {
    checks.push(diskSpaceCheck(cwd), ...REQUIRED_COMMANDS.map(commandCheck), rustTargetCheck(), rustCanisterCheck(cwd));
  }
  return checks.concat(envChecks(mode, env));
}

function printCheck(check: DoctorCheck): void {
  const label = check.status.toUpperCase().padEnd(4, " ");
  console.log(`[${label}] ${check.name}: ${check.detail}`);
  if (check.fix) { console.log(`       fix: ${check.fix}`); }
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

function main(): void {
  loadDotenv();
  const mode = parseMode(process.argv.slice(2));
  const checks = collectChecks(process.cwd(), process.env, mode);
  checks.forEach(printCheck);
  if (checks.some((check) => check.status === "fail")) {
    process.exitCode = 1;
  }
}

if (isDirectRun()) {
  main();
}
