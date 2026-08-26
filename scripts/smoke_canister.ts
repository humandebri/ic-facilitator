// scripts/smoke_canister.ts: facilitator canister が x402 v2 exact Polygon EIP-3009 support を返すことを確認する。
import { pathToFileURL } from "node:url";

import { BATCH_SETTLEMENT_ADDRESS } from "@x402/evm";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { loadDotenv } from "./env_file";

const DEFAULT_BASE_URL = "http://edge.local.localhost:8000";
const EXPECTED_NETWORK = "eip155:137";
const EXPECTED_METHOD = "eip3009";
const EXPECTED_EIP712_NAME = "JPY Coin";
const UINT128_MAX = (1n << 128n) - 1n;
const MIN_BATCH_WITHDRAW_DELAY_SECONDS = 900;
const MAX_BATCH_WITHDRAW_DELAY_SECONDS = 2_592_000;

export type CanisterSmokeOptions = {
  readonly allowMissingSeller?: boolean;
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchFn?: typeof fetch;
  readonly requireBatch?: boolean;
};

export type CanisterSmokeResult = {
  readonly baseUrl: string;
  readonly facilitatorAddress: string;
  readonly healthStatus: number;
  readonly supportedStatus: number;
  readonly support: unknown;
  readonly unpaidStatus?: number;
  readonly verifyStatus?: number;
};

function readEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name];
}

function isHttpsOrigin(value: string): boolean {
  if (!/^https:\/\/[^/:@?#\s]+(:[0-9]+)?$/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === "" &&
      value === url.origin
    );
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function requireEnvString(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value || value.trim() === "") {
    throw new Error(`missing env: ${name}`);
  }
  return value.trim();
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function isPrivateKey(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function deriveReceiverAuthorizer(privateKey: string): string {
  if (!isPrivateKey(privateKey)) {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a 0x-prefixed 32-byte private key");
  }
  try {
    return privateKeyToAccount(privateKey).address;
  } catch {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a valid secp256k1 private key");
  }
}

function expectedWithdrawDelay(env: NodeJS.ProcessEnv): number {
  const value = requireEnvString(env, "BATCH_WITHDRAW_DELAY_SECONDS");
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error("BATCH_WITHDRAW_DELAY_SECONDS must be a positive integer");
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) {
    throw new Error("BATCH_WITHDRAW_DELAY_SECONDS must be a safe integer");
  }
  if (seconds < MIN_BATCH_WITHDRAW_DELAY_SECONDS || seconds > MAX_BATCH_WITHDRAW_DELAY_SECONDS) {
    throw new Error(`BATCH_WITHDRAW_DELAY_SECONDS must be between ${MIN_BATCH_WITHDRAW_DELAY_SECONDS} and ${MAX_BATCH_WITHDRAW_DELAY_SECONDS}`);
  }
  return seconds;
}

function requirePositiveIntegerEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = requireEnvString(env, name);
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function requireUint128Env(env: NodeJS.ProcessEnv, name: string): string {
  const value = requirePositiveIntegerEnv(env, name);
  if (BigInt(value) > UINT128_MAX) {
    throw new Error(`${name} must fit uint128`);
  }
  return value;
}

function requireOfficialBatchSettlementContract(env: NodeJS.ProcessEnv): string {
  const value = requireEnvString(env, "BATCH_SETTLEMENT_CONTRACT");
  if (!/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    throw new Error("BATCH_SETTLEMENT_CONTRACT must be a non-zero 0x-prefixed EVM address");
  }
  if (value.toLowerCase() !== BATCH_SETTLEMENT_ADDRESS.toLowerCase()) {
    throw new Error(`BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${BATCH_SETTLEMENT_ADDRESS}`);
  }
  return value;
}

const BATCH_ACTION_FEE_ENV_NAMES = [
  "BATCH_DEPOSIT_FEE_AMOUNT",
  "BATCH_CLAIM_FEE_AMOUNT",
  "BATCH_SETTLE_FEE_AMOUNT",
  "BATCH_REFUND_FEE_AMOUNT"
] as const;
const BATCH_CLAIM_SCHEDULE_ENV_NAMES = [
  "BATCH_CLAIM_1_FEE_AMOUNT", "BATCH_CLAIM_10_FEE_AMOUNT", "BATCH_CLAIM_50_FEE_AMOUNT", "BATCH_CLAIM_100_FEE_AMOUNT",
  "BATCH_REFUND_WITH_CLAIM_1_FEE_AMOUNT", "BATCH_REFUND_WITH_CLAIM_10_FEE_AMOUNT", "BATCH_REFUND_WITH_CLAIM_50_FEE_AMOUNT", "BATCH_REFUND_WITH_CLAIM_100_FEE_AMOUNT"
] as const;
const MIN_BATCH_ACTION_FEE_ATOMS = 500000000000000000n;

function checkBatchActionFeeEnv(env: NodeJS.ProcessEnv): void {
  const configured = BATCH_ACTION_FEE_ENV_NAMES.some((name) => (env[name] ?? "").trim() !== "");
  if (!configured) return;
  for (const name of BATCH_ACTION_FEE_ENV_NAMES) {
    const value = requireUint128Env(env, name);
    if (BigInt(value) < MIN_BATCH_ACTION_FEE_ATOMS) {
      throw new Error(`${name} must be at least 500000000000000000 (0.5 JPYC)`);
    }
  }
}

function checkBatchClaimFeeScheduleEnv(env: NodeJS.ProcessEnv): void {
  const configured = BATCH_CLAIM_SCHEDULE_ENV_NAMES.some((name) => (env[name] ?? "").trim() !== "");
  if (!configured) return;
  const values = BATCH_CLAIM_SCHEDULE_ENV_NAMES.map((name) => [name, requireUint128Env(env, name)] as const);
  for (let index = 1; index < values.length; index += 1) {
    if (index === 4) continue;
    const previous = BigInt(values[index - 1]![1]);
    const current = BigInt(values[index]![1]);
    if (current < previous) throw new Error(`${values[index]![0]} must not be lower than the previous tier`);
  }
}

async function json(response: Response, expectedStatus: number): Promise<unknown> {
  const text = await response.text();
  if (response.status !== expectedStatus) {
    throw new Error(`expected ${expectedStatus}, got ${response.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`response is not JSON: ${text}`);
  }
}

function hasExactSupport(kinds: readonly unknown[]): boolean {
  return kinds.some((item) => {
    const kind = requireRecord(item, "supported.kind");
    const extra = requireRecord(kind.extra, "supported.kind.extra");
    return kind.x402Version === 2 &&
      kind.scheme === "exact" &&
      kind.network === EXPECTED_NETWORK &&
      extra.assetTransferMethod === EXPECTED_METHOD &&
      extra.name === EXPECTED_EIP712_NAME &&
      typeof extra.version === "string" &&
      extra.version.length > 0;
  });
}

function checkBatchSupport(kinds: readonly unknown[], env: NodeJS.ProcessEnv): void {
  const expectedReceiverAuthorizer = deriveReceiverAuthorizer(requireEnvString(env, "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
  const expectedDelay = expectedWithdrawDelay(env);
  const expectedVersion = requireEnvString(env, "JPYC_EIP712_VERSION");
  requireUint128Env(env, "BATCH_SETTLEMENT_FEE_AMOUNT");
  checkBatchActionFeeEnv(env);
  checkBatchClaimFeeScheduleEnv(env);
  requireOfficialBatchSettlementContract(env);
  const batch = kinds.find((item) => {
    const kind = requireRecord(item, "supported.kind");
    return kind.x402Version === 2 &&
      kind.scheme === "batch-settlement" &&
      kind.network === EXPECTED_NETWORK;
  });
  if (!batch) {
    throw new Error("supported lacks x402 v2 batch-settlement/eip155:137");
  }
  const kind = requireRecord(batch, "supported.batch");
  const extra = requireRecord(kind.extra, "supported.batch.extra");
  const receiverAuthorizer = requireString(extra.receiverAuthorizer, "supported.batch.extra.receiverAuthorizer");
  if (!/^0x[0-9a-fA-F]{40}$/.test(receiverAuthorizer) || /^0x0{40}$/i.test(receiverAuthorizer)) {
    throw new Error("supported.batch.extra.receiverAuthorizer must be a non-zero EVM address");
  }
  if (receiverAuthorizer.toLowerCase() !== expectedReceiverAuthorizer.toLowerCase()) {
    throw new Error("supported.batch.extra.receiverAuthorizer does not match BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  }
  const withdrawDelay = requirePositiveInteger(extra.withdrawDelay, "supported.batch.extra.withdrawDelay");
  if (withdrawDelay !== expectedDelay) {
    throw new Error("supported.batch.extra.withdrawDelay does not match BATCH_WITHDRAW_DELAY_SECONDS");
  }
  if (extra.assetTransferMethod !== EXPECTED_METHOD) {
    throw new Error("supported.batch.extra.assetTransferMethod must be eip3009");
  }
  if (extra.name !== EXPECTED_EIP712_NAME || typeof extra.version !== "string" || extra.version.length === 0) {
    throw new Error("supported.batch.extra token metadata mismatch");
  }
  if (extra.version !== expectedVersion) {
    throw new Error("supported.batch.extra.version does not match JPYC_EIP712_VERSION");
  }
}

async function checkVerifyEndpoint(
  baseUrl: string,
  fetchFn: typeof fetch,
  env: NodeJS.ProcessEnv
): Promise<number> {
  const response = await fetchFn(`${baseUrl}/verify`, {
    body: JSON.stringify({
      paymentPayload: {},
      paymentRequirements: {
        scheme: "exact"
      }
    }),
    headers: { "content-type": "application/json" },
    method: "POST"
  });
  const value = requireRecord(await json(response, 400), "verify");
  if (value.invalidReason !== "unsupported_verify_scheme") {
    throw new Error("verify must reject exact scheme with unsupported_verify_scheme");
  }
  const fixture = readEnv(env, "X402_BATCH_VERIFY_FIXTURE");
  if (!fixture || fixture.trim() === "") {
    return response.status;
  }
  const positiveResponse = await fetchFn(`${baseUrl}/verify`, {
    body: fixture,
    headers: { "content-type": "application/json" },
    method: "POST"
  });
  const positive = requireRecord(await json(positiveResponse, 200), "batch verify");
  if (positive.isValid !== true) {
    throw new Error("batch verify fixture must return isValid=true");
  }
  const extra = requireRecord(positive.extra, "batch verify.extra");
  const channelState = requireRecord(extra.channelState, "batch verify.extra.channelState");
  for (const field of ["channelId", "balance", "totalClaimed", "withdrawRequestedAt", "refundNonce"]) {
    if (extra[field] !== channelState[field]) {
      throw new Error(`batch verify extra.${field} must match extra.channelState.${field}`);
    }
  }
  return response.status;
}

export async function checkCanisterSmoke(options: CanisterSmokeOptions = {}): Promise<CanisterSmokeResult> {
  const env = options.env ?? process.env;
  const fetchFn = options.fetchFn ?? fetch;
  const rawBaseUrl = readEnv(env, "X402_BASE_URL") ?? DEFAULT_BASE_URL;
  if (options.requireBatch && (readEnv(env, "ICP_ENVIRONMENT") ?? "local") === "ic") {
    if (!readEnv(env, "X402_BASE_URL") || readEnv(env, "X402_BASE_URL")?.trim() === "") {
      throw new Error("X402_BASE_URL is required for mainnet batch smoke");
    }
    if (!isHttpsOrigin(rawBaseUrl)) {
      throw new Error("X402_BASE_URL must be a https://host[:port] origin for mainnet batch smoke");
    }
  }
  const baseUrl = rawBaseUrl.trim().replace(/\/+$/, "");
  const healthResponse = await fetchFn(`${baseUrl}/health`);
  const health = requireRecord(await json(healthResponse, 200), "health");
  const healthNetwork = requireString(health.network, "health.network");
  if (healthNetwork !== EXPECTED_NETWORK) {
    throw new Error(`health.network must be ${EXPECTED_NETWORK}`);
  }
  const facilitatorAddress = requireString(health.facilitatorAddress, "health.facilitatorAddress");
  if (!/^0x[0-9a-fA-F]{40}$/.test(facilitatorAddress)) {
    throw new Error("health.facilitatorAddress must be an EVM address");
  }
  const expectedSellerFee = readEnv(env, "SELLER_SETTLEMENT_FEE_AMOUNT")?.trim();
  if (expectedSellerFee) {
    if (!/^[1-9][0-9]*$/.test(expectedSellerFee) || BigInt(expectedSellerFee) < 5n * 10n ** 17n) {
      throw new Error("SELLER_SETTLEMENT_FEE_AMOUNT must be at least 500000000000000000");
    }
    if (health.sellerSettlementFeeAmount !== expectedSellerFee) {
      throw new Error(`health.sellerSettlementFeeAmount mismatch: expected ${expectedSellerFee}, got ${String(health.sellerSettlementFeeAmount)}`);
    }
    if (health.polygonRpcConfigured !== true) {
      throw new Error("health.polygonRpcConfigured must be true");
    }
  }

  const supportedResponse = await fetchFn(`${baseUrl}/supported`);
  const supported = requireRecord(await json(supportedResponse, 200), "supported");
  const kinds = Array.isArray(supported.kinds) ? supported.kinds : [];
  if (!hasExactSupport(kinds)) {
    throw new Error("supported lacks x402 v2 exact/eip155:137 eip3009");
  }
  if (options.requireBatch) {
    checkBatchSupport(kinds, env);
  }
  const signers = requireRecord(supported.signers, "supported.signers");
  const signerList = Array.isArray(signers[EXPECTED_NETWORK]) ? signers[EXPECTED_NETWORK] : [];
  const wildcardSignerList = Array.isArray(signers["eip155:*"]) ? signers["eip155:*"] : [];
  if (!options.requireBatch && Object.prototype.hasOwnProperty.call(signers, "eip155:*")) {
    throw new Error("supported.signers must not use eip155:*");
  }
  if (!signerList.includes(facilitatorAddress)) {
    throw new Error("supported.signers lacks eip155:137 facilitator address");
  }
  if (options.requireBatch && !wildcardSignerList.includes(facilitatorAddress)) {
    throw new Error("supported.signers lacks eip155:* batch facilitator address");
  }
  const verifyStatus = options.requireBatch ? await checkVerifyEndpoint(baseUrl, fetchFn, env) : undefined;

  return {
    baseUrl,
    facilitatorAddress,
    healthStatus: healthResponse.status,
    supportedStatus: supportedResponse.status,
    support: supported,
    ...(verifyStatus === undefined ? {} : { verifyStatus })
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  checkCanisterSmoke({ requireBatch: process.argv.includes("--with-batch") })
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
