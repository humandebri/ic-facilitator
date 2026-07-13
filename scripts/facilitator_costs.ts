// scripts/facilitator_costs.ts: 13-node直接HTTPS outcallの機能別原価を概算する。
import { pathToFileURL } from "node:url";

const NODES = 13n;
const XDR_USD = Number(process.env.XDR_USD ?? "1.36643");
const USD_JPY = Number(process.env.USD_JPY ?? "162.34");
const POL_USD = Number(process.env.POL_USD ?? "0.07715");
const GAS_PRICE_GWEI = Number(process.env.GAS_PRICE_GWEI ?? "30");

export type Outcall = { readonly maxResponseBytes: number; readonly requestBytes: number };

export function httpsOutcallCycles(call: Outcall): bigint {
  return (3_000_000n + 60_000n * NODES) * NODES
    + (400n * BigInt(call.requestBytes) + 800n * BigInt(call.maxResponseBytes)) * NODES;
}

const calls = {
  block: { requestBytes: 263, maxResponseBytes: 128 },
  call: { requestBytes: 480, maxResponseBytes: 192 },
  estimateSmall: { requestBytes: 1_400, maxResponseBytes: 128 },
  estimate100: { requestBytes: 96_834, maxResponseBytes: 128 },
  fee: { requestBytes: 281, maxResponseBytes: 320 },
  nonce: { requestBytes: 325, maxResponseBytes: 128 },
  receipt: { requestBytes: 341, maxResponseBytes: 4_096 },
  sendSmall: { requestBytes: 1_600, maxResponseBytes: 512 },
  send100: { requestBytes: 96_964, maxResponseBytes: 512 }
} as const;

const scenarios = {
  supported: [],
  verify: [],
  pendingRefresh: [calls.receipt],
  confirmedRefresh: [calls.receipt, calls.block],
  batchSettleNoop: [calls.call],
  normalSettle: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchClaim100: [calls.nonce, calls.fee, calls.estimate100, calls.send100, calls.receipt, calls.block]
} as const;

function scenarioCycles(items: readonly Outcall[]): bigint {
  return items.reduce((total, item) => total + httpsOutcallCycles(item), 0n);
}

function cyclesYen(cycles: bigint): number {
  return Number(cycles) / 1e12 * XDR_USD * USD_JPY;
}

function polygonGasYen(gas: number): number {
  const pol = gas * GAS_PRICE_GWEI / 1e9;
  return pol * POL_USD * USD_JPY;
}

export function facilitatorCostReport() {
  const scenarioReport = Object.fromEntries(Object.entries(scenarios).map(([name, items]) => {
    const cycles = scenarioCycles(items);
    const hasInstructionMeasurement = false;
    return [name, {
      outcallCost: { cycles: cycles.toString(), yen: cyclesYen(cycles) },
      totalCost: hasInstructionMeasurement ? { status: "available" } : { status: "unavailable", reason: "instruction cycles have not been measured" }
    }];
  }));
  return {
    assumptions: { gasPriceGwei: GAS_PRICE_GWEI, nodes: Number(NODES), polUsd: POL_USD, replicated: false, requestBytes: "JSON-RPC body plus an explicit 200-byte URL/header allowance per call", normalSettle: "nonce + feeHistory + estimateGas + sendRawTransaction + receipt + blockNumber", usdJpy: USD_JPY, xdrUsd: XDR_USD },
    polygonGasSamples: { revertedClaim100: { gas: 1_029_750, yen: polygonGasYen(1_029_750) } },
    recommendedFeesJpyc: { batch: 10, normal: 1 },
    scenarios: scenarioReport
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  console.log(JSON.stringify(facilitatorCostReport(), null, 2));
}
