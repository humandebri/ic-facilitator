// scripts/settlement_receipt.ts: x402 settlement tx の Polygon receipt を確認する。
import { pathToFileURL } from "node:url";

import { createPublicClient, http } from "viem";
import type { Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";

import { positiveDecimalToAtomicUnits } from "../src/amount";
import { loadDotenv } from "./env_file";
import { normalizePolygonRpcUrl } from "./rpc_url";

export type ReceiptReader = {
  getBlockNumber(): Promise<bigint>;
  getTransactionReceipt(args: { hash: Hex }): Promise<TransactionReceipt>;
};

export type SettlementReceiptResult = {
  readonly blockNumber: string;
  readonly confirmations: string;
  readonly from: Hex;
  readonly gasUsed: string;
  readonly hash: Hex;
  readonly status: "success" | "reverted";
  readonly to: Hex | null;
  readonly transfer?: {
    readonly amount: string;
    readonly asset: Hex;
    readonly from: Hex;
    readonly to: Hex;
  };
};

export type ExpectedTransfer = {
  readonly amount: string;
  readonly asset: string;
  readonly from?: string;
  readonly to: string;
};

export type SettlementReceiptOptions = {
  readonly expectedFrom?: string;
  readonly expectedTo?: string;
  readonly expectedTransfer?: ExpectedTransfer;
  readonly hash: Hex;
  readonly minConfirmations?: number;
  readonly reader?: ReceiptReader;
  readonly rpcUrl?: string;
};

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const DEFAULT_JPYC_PRICE = "1";
const DEFAULT_MIN_CONFIRMATIONS = 3;
const JPYC_DECIMALS = 18;
const SAMPLE_SELLER_ADDRESS = "0x0000000000000000000000000000000000000402";

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

function isTxHash(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isPrivateKey(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function equalsHex(left: Hex, right: Hex): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function isEvmAddress(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isUint256Topic(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function normalizeAddress(value: string, name: string): Hex {
  if (!isEvmAddress(value)) {
    throw new Error(`${name} must be a 0x-prefixed 20-byte EVM address`);
  }
  if (/^0x0{40}$/i.test(value)) {
    throw new Error(`${name} must be a non-zero EVM address`);
  }
  return value;
}

function addressFromTopic(topic: Hex): Hex | null {
  if (!isUint256Topic(topic)) {
    return null;
  }
  const address = `0x${topic.slice(-40)}`;
  return isEvmAddress(address) ? address : null;
}

function amountFromData(data: Hex): string | null {
  if (!isUint256Topic(data)) {
    return null;
  }
  return BigInt(data).toString();
}

function positiveInteger(value: string, name: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${name} must be a positive integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return parsed;
}

export function settlementMinConfirmationsFromEnv(env: NodeJS.ProcessEnv): number {
  const value = env.SETTLE_MIN_CONFIRMATIONS;
  return value === undefined || value.trim() === ""
    ? DEFAULT_MIN_CONFIRMATIONS
    : positiveInteger(value, "SETTLE_MIN_CONFIRMATIONS");
}

export function expectedSettlementSenderFromEnv(env: NodeJS.ProcessEnv): Hex {
  const privateKey = env.FACILITATOR_EVM_PRIVATE_KEY;
  if (!privateKey || privateKey.trim() === "") {
    throw new Error("missing required env: FACILITATOR_EVM_PRIVATE_KEY");
  }
  if (!isPrivateKey(privateKey)) {
    throw new Error("FACILITATOR_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return privateKeyToAccount(privateKey).address;
}

function findExpectedTransfer(receipt: TransactionReceipt, expected: ExpectedTransfer): SettlementReceiptResult["transfer"] {
  const asset = normalizeAddress(expected.asset, "expected transfer asset");
  const to = normalizeAddress(expected.to, "expected transfer recipient");
  const from = expected.from ? normalizeAddress(expected.from, "expected transfer sender") : undefined;

  for (const log of receipt.logs) {
    if (log.removed) {
      continue;
    }
    const topic0 = log.topics[0];
    const topic1 = log.topics[1];
    const topic2 = log.topics[2];
    if (!topic0 || !equalsHex(topic0, TRANSFER_TOPIC) || !topic1 || !topic2 || !equalsHex(log.address, asset)) {
      continue;
    }
    const transferFrom = addressFromTopic(topic1);
    const transferTo = addressFromTopic(topic2);
    const amount = amountFromData(log.data);
    if (!transferFrom || !transferTo || !amount) {
      continue;
    }
    if (from && !equalsHex(transferFrom, from)) {
      continue;
    }
    if (!equalsHex(transferTo, to) || amount !== expected.amount) {
      continue;
    }
    return {
      amount,
      asset: log.address,
      from: transferFrom,
      to: transferTo
    };
  }

  throw new Error("expected JPYC transfer log not found in settlement receipt");
}

export function parseTxHash(value: string): Hex {
  if (!isTxHash(value)) {
    throw new Error("settlement tx must be a 32-byte 0x-prefixed transaction hash");
  }
  return value;
}

export function expectedTransferFromEnv(env: NodeJS.ProcessEnv): ExpectedTransfer {
  const seller = env.SELLER_EVM_ADDRESS;
  if (!seller || seller.trim() === "") {
    throw new Error("missing required env: SELLER_EVM_ADDRESS");
  }
  if (seller.toLowerCase() === SAMPLE_SELLER_ADDRESS.toLowerCase()) {
    throw new Error("SELLER_EVM_ADDRESS must be a real seller address, not the sample address");
  }
  const buyerPrivateKey = env.BUYER_EVM_PRIVATE_KEY;
  const expected: ExpectedTransfer = {
    amount: positiveDecimalToAtomicUnits(env.JPYC_PRICE ?? DEFAULT_JPYC_PRICE, JPYC_DECIMALS, "JPYC_PRICE"),
    asset: normalizeAddress(env.JPYC_POLYGON_ADDRESS ?? DEFAULT_JPYC_POLYGON_ADDRESS, "expected transfer asset"),
    to: normalizeAddress(seller, "expected transfer recipient")
  };
  if (!buyerPrivateKey) {
    return expected;
  }
  if (!isPrivateKey(buyerPrivateKey)) {
    throw new Error("BUYER_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return {
    ...expected,
    from: privateKeyToAccount(buyerPrivateKey).address
  };
}

export async function verifySettlementReceipt(
  options: SettlementReceiptOptions
): Promise<SettlementReceiptResult> {
  const reader = options.reader ?? createPublicClient({
    chain: polygon,
    transport: http(normalizePolygonRpcUrl(options.rpcUrl ?? requireEnv("POLYGON_RPC_URL")))
  });
  const [receipt, latestBlock] = await Promise.all([
    reader.getTransactionReceipt({ hash: options.hash }),
    reader.getBlockNumber()
  ]);

  if (!equalsHex(receipt.transactionHash, options.hash)) {
    throw new Error(`receipt hash mismatch: ${receipt.transactionHash}`);
  }
  if (receipt.status !== "success") {
    throw new Error(`settlement tx failed: ${receipt.status}`);
  }
  if (options.expectedFrom) {
    const expectedFrom = normalizeAddress(options.expectedFrom, "expected settlement sender");
    if (!equalsHex(receipt.from, expectedFrom)) {
      throw new Error(`settlement tx sender mismatch: ${receipt.from}`);
    }
  }
  if (options.expectedTo) {
    const expectedTo = normalizeAddress(options.expectedTo, "expected settlement contract");
    if (!receipt.to || !equalsHex(receipt.to, expectedTo)) {
      throw new Error(`settlement tx recipient mismatch: ${receipt.to}`);
    }
  }
  const confirmations = latestBlock >= receipt.blockNumber ? latestBlock - receipt.blockNumber + 1n : 0n;
  const minConfirmations = BigInt(options.minConfirmations ?? settlementMinConfirmationsFromEnv(process.env));
  if (confirmations < minConfirmations) {
    throw new Error(`settlement tx confirmations below minimum: ${confirmations.toString()} < ${minConfirmations.toString()}`);
  }
  const transfer = options.expectedTransfer
    ? findExpectedTransfer(receipt, options.expectedTransfer)
    : undefined;

  const result: SettlementReceiptResult = {
    blockNumber: receipt.blockNumber.toString(),
    confirmations: confirmations.toString(),
    from: receipt.from,
    gasUsed: receipt.gasUsed.toString(),
    hash: options.hash,
    status: receipt.status,
    to: receipt.to
  };

  return transfer ? { ...result, transfer } : result;
}

async function main(): Promise<void> {
  const tx = process.argv[2] ?? requireEnv("SETTLEMENT_TX");
  const rpcUrl = readEnv("POLYGON_RPC_URL");
  const expectedTransfer = expectedTransferFromEnv(process.env);
  const result = await verifySettlementReceipt({
    hash: parseTxHash(tx),
    ...(rpcUrl ? { rpcUrl: normalizePolygonRpcUrl(rpcUrl) } : {}),
    expectedFrom: expectedSettlementSenderFromEnv(process.env),
    expectedTo: readEnv("JPYC_POLYGON_ADDRESS") ?? DEFAULT_JPYC_POLYGON_ADDRESS,
    expectedTransfer,
    minConfirmations: settlementMinConfirmationsFromEnv(process.env)
  });

  console.log(JSON.stringify(result, null, 2));

  if (result.status !== "success") {
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadDotenv();
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
