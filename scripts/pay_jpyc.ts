// scripts/pay_jpyc.ts: buyer key で x402 payment-signature を生成し、JPYC endpoint の実決済を確認する。
import { pathToFileURL } from "node:url";

import { x402Client, x402HTTPClient } from "@x402/core/client";
import type { Network, PaymentRequired, PaymentRequirements, SettleResponse } from "@x402/core/types";
import { toClientEvmSigner } from "@x402/evm";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { positiveDecimalToAtomicUnits } from "../src/amount";
import { loadDotenv } from "./env_file";
import { JPYC_EIP712_NAME, validateExactEip3009PaymentPayload } from "./eip3009_payload";

const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const DEFAULT_JPYC_PRICE = "1";
const JPYC_DECIMALS = 18;
const POLYGON_NETWORK: Network = "eip155:137";
const REQUIRED_SCHEME = "exact";
const REQUIRED_TRANSFER_METHOD = "eip3009";
const SAMPLE_SELLER_ADDRESS = "0x0000000000000000000000000000000000000402";

export type PayJpycOptions = {
  readonly expectedAmount?: string;
  readonly expectedAsset?: string;
  readonly expectedEip712Version?: string;
  readonly expectedMaxTimeoutSeconds?: number;
  readonly expectedPayTo?: string;
  readonly expectedResourceUrl?: string;
  readonly fetchFn?: typeof fetch;
  readonly privateKey: Hex;
  readonly targetUrl: string;
  readonly withPaidRetry?: boolean;
};

export type PayJpycResult = {
  readonly body: unknown;
  readonly buyer: `0x${string}`;
  readonly paidStatus: number;
  readonly paidRetryStatus?: number;
  readonly retrySettlement?: SettleResponse;
  readonly settlement: SettleResponse | null;
  readonly settlementTxExport: string;
  readonly targetUrl: string;
  readonly unpaidStatus: number;
  readonly verifyCommand: string;
};

type ValidatedPaidResponse = {
  readonly body: unknown;
  readonly settlement: SettleResponse;
  readonly status: number;
};

export function validatePaidRetrySettlements(
  first: SettleResponse,
  retry: SettleResponse,
): void {
  const firstKey = (first as SettleResponse & { extra?: { settlementKey?: string } }).extra?.settlementKey;
  const retryKey = (retry as SettleResponse & { extra?: { settlementKey?: string } }).extra?.settlementKey;
  if (!firstKey || !retryKey || firstKey !== retryKey) {
    throw new Error("paid retry settlement key mismatch");
  }
  if (first.transaction.toLowerCase() !== retry.transaction.toLowerCase()) {
    throw new Error("paid retry transaction hash mismatch");
  }
}

const PAID_REPORT = "paid JPYC access granted";

function readEnv(name: string): string | undefined {
  return process.env[name];
}

function requireEnv(name: string): string {
  const value = readEnv(name);
  if (!value || value.trim() === "") {
    throw new Error(`missing required env: ${name}`);
  }
  return value;
}

function isHex(value: string): value is Hex {
  return /^0x[0-9a-fA-F]+$/.test(value);
}

function isEvmAddress(value: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isHttpsUrl(value: string): boolean { try { return new URL(value).protocol === "https:"; } catch { return false; } }

function requireNonZeroEvmAddress(name: string, value: string): string {
  if (!isEvmAddress(value) || /^0x0{40}$/i.test(value)) {
    throw new Error(`${name} must be a non-zero 0x-prefixed 20-byte EVM address`);
  }
  return value;
}

function readExpectedAmount(options: PayJpycOptions): string {
  if (options.expectedAmount) {
    return options.expectedAmount;
  }
  return positiveDecimalToAtomicUnits(readEnv("JPYC_PRICE") ?? DEFAULT_JPYC_PRICE, JPYC_DECIMALS, "JPYC_PRICE");
}

function readExpectedAsset(options: PayJpycOptions): string {
  return requireNonZeroEvmAddress(
    "JPYC_POLYGON_ADDRESS",
    options.expectedAsset ?? readEnv("JPYC_POLYGON_ADDRESS") ?? DEFAULT_JPYC_POLYGON_ADDRESS
  );
}

function readExpectedEip712Version(options: PayJpycOptions): string {
  const value = options.expectedEip712Version ?? readEnv("JPYC_EIP712_VERSION");
  if (!value || value.trim() === "") {
    throw new Error("missing required env: JPYC_EIP712_VERSION");
  }
  return value;
}

function readExpectedPayTo(options: PayJpycOptions): string {
  const payTo = options.expectedPayTo
    ? requireNonZeroEvmAddress("expectedPayTo", options.expectedPayTo)
    : requireNonZeroEvmAddress("SELLER_EVM_ADDRESS", requireEnv("SELLER_EVM_ADDRESS"));
  if (payTo.toLowerCase() === SAMPLE_SELLER_ADDRESS.toLowerCase()) {
    throw new Error("SELLER_EVM_ADDRESS must be a real seller address, not the sample address");
  }
  return payTo;
}

function readExpectedMaxTimeoutSeconds(options: PayJpycOptions): number {
  if (options.expectedMaxTimeoutSeconds !== undefined) {
    return options.expectedMaxTimeoutSeconds;
  }
  const raw = readEnv("X402_MAX_TIMEOUT_SECONDS") ?? "60";
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error("X402_MAX_TIMEOUT_SECONDS must be a positive integer");
  }
  return value;
}

function readExpectedResourceUrl(options: PayJpycOptions): string {
  const configured = options.expectedResourceUrl ?? readEnv("X402_RESOURCE_URL");
  if (!configured && !isHttpsUrl(options.targetUrl)) { throw new Error("missing required env: X402_RESOURCE_URL"); }
  const value = configured ?? options.targetUrl;
  if (!isHttpsUrl(value)) { throw new Error("X402_RESOURCE_URL must be an https URL"); }
  return value;
}

function shouldRetryPaidRequest(options: PayJpycOptions): boolean {
  return options.withPaidRetry === true || readEnv("X402_PAID_RETRY") === "1";
}

function requirePrivateKey(): Hex {
  const value = requireEnv("BUYER_EVM_PRIVATE_KEY");
  if (!isHex(value) || value.length !== 66) {
    throw new Error("BUYER_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return value;
}

function getHeader(response: Response): (name: string) => string | null {
  return (name) => response.headers.get(name);
}

function parseBody(text: string): unknown {
  if (text === "") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed;
  } catch {
    return text;
  }
}

function equalsAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function isTxHash(value: string): boolean {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function validateSettlement(settlement: SettleResponse | null, expectedPayer: string, expectedAmount: string): SettleResponse {
  if (!settlement?.success) {
    throw new Error("payment did not settle successfully");
  }
  if (settlement.errorReason || settlement.errorMessage) {
    throw new Error("successful settlement must not include error fields");
  }
  if (settlement.network !== POLYGON_NETWORK) {
    throw new Error(`unexpected settlement network: ${settlement.network}`);
  }
  if (!settlement.payer || !equalsAddress(settlement.payer, expectedPayer)) {
    throw new Error(`unexpected settlement payer: ${settlement.payer}`);
  }
  if (!isTxHash(settlement.transaction)) {
    throw new Error("settlement transaction must be a 32-byte 0x-prefixed transaction hash");
  }
  if (settlement.amount !== undefined && settlement.amount !== expectedAmount) {
    throw new Error(`unexpected settlement amount: ${settlement.amount}`);
  }
  return settlement;
}

async function validatePaidResponse(
  response: Response,
  client: x402HTTPClient,
  expectedPayer: string,
  options: PayJpycOptions,
  label: string
): Promise<ValidatedPaidResponse> {
  const body = parseBody(await response.text());
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`expected ${label} response 2xx, got ${response.status}`);
  }
  if (!hasExpectedPaidJpycReportBody(body, readExpectedAsset(options))) {
    throw new Error(`unexpected ${label} response body`);
  }
  const paymentResponse = response.headers.get("payment-response");
  const settlement = validateSettlement(
    paymentResponse ? client.getPaymentSettleResponse(getHeader(response)) : null,
    expectedPayer,
    readExpectedAmount(options)
  );
  return { body, settlement, status: response.status };
}

export function hasPaidJpycReportBody(value: unknown): boolean {
  return hasExpectedPaidJpycReportBody(value, DEFAULT_JPYC_POLYGON_ADDRESS);
}

export function hasExpectedPaidJpycReportBody(value: unknown, expectedAsset: string): boolean {
  const asset = typeof value === "object" && value !== null
    ? Object.getOwnPropertyDescriptor(value, "asset")?.value
    : undefined;
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getOwnPropertyDescriptor(value, "network")?.value === POLYGON_NETWORK &&
    Object.getOwnPropertyDescriptor(value, "report")?.value === PAID_REPORT &&
    typeof asset === "string" &&
    equalsAddress(asset, expectedAsset)
  );
}

function validateRequirement(requirement: PaymentRequirements, options: PayJpycOptions): void {
  const expectedAsset = readExpectedAsset(options);
  const expectedPayTo = readExpectedPayTo(options);
  if (requirement.scheme !== REQUIRED_SCHEME) {
    throw new Error(`unexpected payment scheme: ${requirement.scheme}`);
  }
  if (requirement.network !== POLYGON_NETWORK) {
    throw new Error(`unexpected payment network: ${requirement.network}`);
  }
  if (!equalsAddress(requirement.asset, expectedAsset)) {
    throw new Error(`unexpected payment asset: ${requirement.asset}`);
  }
  if (requirement.amount !== readExpectedAmount(options)) {
    throw new Error(`unexpected payment amount: ${requirement.amount}`);
  }
  if (requirement.maxTimeoutSeconds !== readExpectedMaxTimeoutSeconds(options)) {
    throw new Error(`unexpected payment timeout: ${requirement.maxTimeoutSeconds}`);
  }
  if (!equalsAddress(requirement.payTo, expectedPayTo)) {
    throw new Error(`unexpected payment receiver: ${requirement.payTo}`);
  }
  if (requirement.extra?.assetTransferMethod !== REQUIRED_TRANSFER_METHOD) {
    throw new Error("unexpected payment transfer method");
  }
  if (requirement.extra?.name !== JPYC_EIP712_NAME || requirement.extra?.version !== readExpectedEip712Version(options)) {
    throw new Error("unexpected payment EIP-712 domain");
  }
}

export function validateJpycPaymentRequired(paymentRequired: PaymentRequired, options: PayJpycOptions): void {
  if (paymentRequired.x402Version !== 2) {
    throw new Error(`unexpected x402 version: ${paymentRequired.x402Version}`);
  }
  if (paymentRequired.resource.url !== readExpectedResourceUrl(options)) {
    throw new Error(`unexpected payment resource: ${paymentRequired.resource.url}`);
  }
  if (paymentRequired.accepts.length !== 1) {
    throw new Error(`unexpected payment option count: ${paymentRequired.accepts.length}`);
  }
  const requirement = paymentRequired.accepts[0];
  if (!requirement) {
    throw new Error("payment requirements are empty");
  }
  validateRequirement(requirement, options);
}

export async function payJpyc(options: PayJpycOptions): Promise<PayJpycResult> {
  const account = privateKeyToAccount(options.privateKey);
  const coreClient = new x402Client();
  const fetchFn = options.fetchFn ?? fetch;

  registerExactEvmScheme(coreClient, {
    signer: toClientEvmSigner(account),
    networks: [POLYGON_NETWORK]
  });

  const client = new x402HTTPClient(coreClient);
  const unpaidResponse = await fetchFn(options.targetUrl, { headers: { Accept: "application/json" } });

  if (unpaidResponse.status !== 402) {
    throw new Error(`expected 402 payment required, got ${unpaidResponse.status}`);
  }

  const paymentRequired = client.getPaymentRequiredResponse(getHeader(unpaidResponse));
  validateJpycPaymentRequired(paymentRequired, options);
  const paymentPayload = await client.createPaymentPayload(paymentRequired);
  validateExactEip3009PaymentPayload(paymentPayload, { amount: readExpectedAmount(options), asset: readExpectedAsset(options), buyer: account.address, eip712Version: readExpectedEip712Version(options), maxTimeoutSeconds: readExpectedMaxTimeoutSeconds(options), payTo: readExpectedPayTo(options), resourceUrl: readExpectedResourceUrl(options) });
  const paymentSignatureHeaders = client.encodePaymentSignatureHeader(paymentPayload);
  const paidResponse = await fetchFn(options.targetUrl, {
    headers: {
      Accept: "application/json",
      ...paymentSignatureHeaders
    }
  });
  const paid = await validatePaidResponse(paidResponse, client, account.address, options, "paid");
  const baseResult: PayJpycResult = { buyer: account.address, targetUrl: options.targetUrl, unpaidStatus: unpaidResponse.status, paidStatus: paid.status, body: paid.body, settlement: paid.settlement, settlementTxExport: `export SETTLEMENT_TX=${paid.settlement.transaction}`, verifyCommand: `SETTLEMENT_TX=${paid.settlement.transaction} npm run verify:jpyc` };
  if (!shouldRetryPaidRequest(options)) {
    return baseResult;
  }

  const paidRetryResponse = await fetchFn(options.targetUrl, {
    headers: {
      Accept: "application/json",
      ...paymentSignatureHeaders
    }
  });
  const paidRetry = await validatePaidResponse(paidRetryResponse, client, account.address, options, "paid retry");
  validatePaidRetrySettlements(paid.settlement, paidRetry.settlement);
  return {
    ...baseResult,
    paidRetryStatus: paidRetry.status,
    retrySettlement: paidRetry.settlement
  };
}

async function main(): Promise<void> {
  const result = await payJpyc({
    privateKey: requirePrivateKey(),
    targetUrl: requireEnv("X402_TARGET_URL")
  });

  console.log(JSON.stringify(result, null, 2));

  if (!result.settlement?.success) { process.exitCode = 1; }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadDotenv();
  main().catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
