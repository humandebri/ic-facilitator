// scripts/rpc_response_sizes.ts: Polygon JSON-RPC の実レスポンスサイズと推奨上限を計測する。
import { pathToFileURL } from "node:url";

import { loadDotenv } from "./env_file";
import { normalizePolygonRpcUrl } from "./rpc_url";

const CURRENT_RESPONSE_LIMIT = 20_000;
const RESPONSE_PRICE_PER_BYTE = 800;
const DEFAULT_SUBNET_NODES = 13;
const JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const BATCH_SETTLEMENT_ADDRESS = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";

export type JsonRpcResponse = {
  readonly error?: unknown;
  readonly id?: unknown;
  readonly jsonrpc?: unknown;
  readonly result?: unknown;
};

export type RpcSizeMeasurement = {
  readonly cyclesSavedFrom20Kb: string;
  readonly label: string;
  readonly logCount?: number;
  readonly responseWithoutLogsBytes?: number;
  readonly method: string;
  readonly rawResponseBytes: number;
  readonly recommendedResponseBytes: number;
  readonly resultBytes: number;
};

export function jsonUtf8Bytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

export function recommendedResponseBytes(observedBytes: number, method = "unknown"): number {
  if (!Number.isSafeInteger(observedBytes) || observedBytes < 0) {
    throw new Error("observedBytes must be a non-negative safe integer");
  }
  if (method === "eth_getTransactionReceipt") {
    return Math.ceil((observedBytes * 1.25) / 1_024) * 1_024;
  }
  return Math.ceil((observedBytes + 64) / 64) * 64;
}

export function responseCyclesSaved(
  responseLimit: number,
  nodes = DEFAULT_SUBNET_NODES
): bigint {
  if (responseLimit >= CURRENT_RESPONSE_LIMIT) return 0n;
  return BigInt(CURRENT_RESPONSE_LIMIT - responseLimit) *
    BigInt(RESPONSE_PRICE_PER_BYTE) * BigInt(nodes);
}

export function measureResponse(
  label: string,
  method: string,
  response: JsonRpcResponse
): RpcSizeMeasurement {
  const rawResponseBytes = jsonUtf8Bytes(response);
  const resultBytes = jsonUtf8Bytes(response.result ?? null);
  const recommended = recommendedResponseBytes(rawResponseBytes, method);
  const logs = response.result && typeof response.result === "object" &&
      "logs" in response.result && Array.isArray(response.result.logs)
    ? response.result.logs.length
    : undefined;
  const responseWithoutLogsBytes = logs === undefined
    ? undefined
    : jsonUtf8Bytes({
        ...response,
        result: { ...(response.result as Record<string, unknown>), logs: [] }
      });
  return {
    cyclesSavedFrom20Kb: responseCyclesSaved(recommended).toString(),
    label,
    ...(logs === undefined ? {} : { logCount: logs }),
    ...(responseWithoutLogsBytes === undefined ? {} : { responseWithoutLogsBytes }),
    method,
    rawResponseBytes,
    recommendedResponseBytes: recommended,
    resultBytes
  };
}

async function rpc(url: string, method: string, params: readonly unknown[]): Promise<JsonRpcResponse> {
  const response = await fetch(url, {
    body: JSON.stringify({ id: 1, jsonrpc: "2.0", method, params }),
    headers: { "content-type": "application/json" },
    method: "POST"
  });
  if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
  return await response.json() as JsonRpcResponse;
}

function transactionSamples(env: NodeJS.ProcessEnv): Array<readonly [string, string]> {
  const candidates: Array<readonly [string, string | undefined]> = [
    ["jpyc-transfer", env.SETTLEMENT_TX],
    ["batch-deposit", env.BATCH_DEPOSIT_TX],
    ["batch-claim", env.BATCH_CLAIM_TX],
    ["batch-refund", env.BATCH_REFUND_TX],
    ["batch-settle", env.BATCH_SETTLE_TX]
  ];
  return candidates.flatMap(([label, hash]) =>
    hash && /^0x[0-9a-fA-F]{64}$/.test(hash) ? [[label, hash] as const] : []
  );
}

export async function collectRpcResponseSizes(
  url: string,
  env: NodeJS.ProcessEnv = process.env
): Promise<{ measurements: RpcSizeMeasurement[]; missingReceiptSamples: string[] }> {
  const measurements: RpcSizeMeasurement[] = [];
  const calls: Array<readonly [string, string, readonly unknown[]]> = [
    ["block-number", "eth_blockNumber", []],
    ["fee-history", "eth_feeHistory", ["0x1", "latest", [50]]],
    ["jpyc-decimals", "eth_call", [{ data: "0x313ce567", to: JPYC_POLYGON_ADDRESS }, "latest"]],
    ["transaction-count", "eth_getTransactionCount", [BATCH_SETTLEMENT_ADDRESS, "pending"]],
    ["estimate-gas-read", "eth_estimateGas", [{ data: "0x313ce567", to: JPYC_POLYGON_ADDRESS }]]
  ];
  for (const [label, method, params] of calls) {
    measurements.push(measureResponse(label, method, await rpc(url, method, params)));
  }
  const samples = transactionSamples(env);
  for (const [label, hash] of samples) {
    measurements.push(measureResponse(
      label,
      "eth_getTransactionReceipt",
      await rpc(url, "eth_getTransactionReceipt", [hash])
    ));
  }
  const present = new Set(samples.map(([label]) => label));
  const expected = ["jpyc-transfer", "batch-deposit", "batch-claim", "batch-refund", "batch-settle"];
  return {
    measurements,
    missingReceiptSamples: expected.filter((label) => !present.has(label))
  };
}

async function main(): Promise<void> {
  loadDotenv();
  const rawUrl = process.env.POLYGON_RPC_URL;
  if (!rawUrl) throw new Error("missing required env: POLYGON_RPC_URL");
  const result = await collectRpcResponseSizes(normalizePolygonRpcUrl(rawUrl));
  console.log(JSON.stringify(result, null, 2));
  if (result.missingReceiptSamples.length > 0) process.exitCode = 2;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
