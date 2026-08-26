// scripts/facilitator_costs.ts: MainnetのPOL単価とAmoy実測gasUsedを使って原価を概算する。
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadDotenv } from "./env_file";

loadDotenv();

const NODES = 13n;
const XDR_USD = Number(process.env.XDR_USD ?? "1.36643");
const USD_JPY = Number(process.env.USD_JPY ?? "162.34");
const POL_USD = Number(process.env.POL_USD ?? "0.07715");
const GAS_PRICE_GWEI = Number(process.env.GAS_PRICE_GWEI ?? "300");
const SAFETY_MULTIPLIER = Number(process.env.FEE_SAFETY_MULTIPLIER ?? "1.2");
const AMOY_REPORT_PATH = resolve(process.cwd(), ".amoy/fee-benchmark.json");
const GAS_STATION_URL = "https://gasstation.polygon.technology/v2";

export type Outcall = { readonly maxResponseBytes: number; readonly requestBytes: number };
export type BenchmarkAction = {
  readonly action: string;
  readonly gasUsed: string;
  readonly status: "success" | "reverted";
};
export type AmoyBenchmarkReport = {
  readonly actions?: {
    readonly exact?: readonly BenchmarkAction[];
    readonly batch?: readonly BenchmarkAction[];
  };
};
export type MainnetGasPriceReport = {
  readonly gasPriceGwei: number;
  readonly stressGasPriceGwei: number | undefined;
  readonly gasStation: unknown;
  readonly feeHistory: unknown;
  readonly source: string;
};

type GasStationTier = { readonly maxFee?: unknown };
type GasStationResponse = {
  readonly safeLow?: GasStationTier;
  readonly standard?: GasStationTier;
  readonly fast?: GasStationTier;
};

function positiveNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

export function selectMainnetGasPrice(
  gasStation: unknown,
  override: string | undefined = process.env.MAINNET_GAS_PRICE_GWEI
): { readonly gasPriceGwei: number; readonly stressGasPriceGwei: number | undefined; readonly source: string } {
  const tiers = gasStation as GasStationResponse;
  const standard = tiers.standard?.maxFee;
  const fast = tiers.fast?.maxFee;
  const stressGasPriceGwei = positiveNumber(fast) ? fast : undefined;

  if (override !== undefined) {
    const gasPriceGwei = Number(override);
    if (!positiveNumber(gasPriceGwei)) throw new Error("MAINNET_GAS_PRICE_GWEI must be positive");
    return { gasPriceGwei, stressGasPriceGwei, source: "MAINNET_GAS_PRICE_GWEI override" };
  }

  if (!positiveNumber(standard)) {
    throw new Error("Polygon Gas Station standard.maxFee is missing or invalid");
  }
  return {
    gasPriceGwei: standard,
    stressGasPriceGwei,
    source: "Polygon Gas Station mainnet standard.maxFee"
  };
}

export function httpsOutcallCycles(call: Outcall): bigint {
  return (3_000_000n + 60_000n * NODES) * NODES
    + (400n * BigInt(call.requestBytes) + 800n * BigInt(call.maxResponseBytes)) * NODES;
}

const calls = {
  block: { requestBytes: 263, maxResponseBytes: 128 },
  call: { requestBytes: 480, maxResponseBytes: 192 },
  estimateSmall: { requestBytes: 1_400, maxResponseBytes: 128 },
  estimate10: { requestBytes: 10_200, maxResponseBytes: 128 },
  estimate50: { requestBytes: 48_600, maxResponseBytes: 128 },
  estimate100: { requestBytes: 96_834, maxResponseBytes: 128 },
  fee: { requestBytes: 281, maxResponseBytes: 320 },
  nonce: { requestBytes: 325, maxResponseBytes: 128 },
  receipt: { requestBytes: 341, maxResponseBytes: 4_096 },
  sendSmall: { requestBytes: 1_600, maxResponseBytes: 512 },
  send10: { requestBytes: 10_350, maxResponseBytes: 512 },
  send50: { requestBytes: 48_750, maxResponseBytes: 512 },
  send100: { requestBytes: 96_964, maxResponseBytes: 512 }
} as const;

const scenarios = {
  supported: [],
  verify: [],
  pendingRefresh: [calls.receipt],
  confirmedRefresh: [calls.receipt, calls.block],
  batchSettleNoop: [calls.call],
  normalSettle: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchDeposit: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchClaim1: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchClaim10: [calls.nonce, calls.fee, calls.estimate10, calls.send10, calls.receipt, calls.block],
  batchClaim50: [calls.nonce, calls.fee, calls.estimate50, calls.send50, calls.receipt, calls.block],
  batchClaim100: [calls.nonce, calls.fee, calls.estimate100, calls.send100, calls.receipt, calls.block],
  batchSettle: [calls.call, calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchRefund: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchRefundWithClaim1: [calls.nonce, calls.fee, calls.estimateSmall, calls.sendSmall, calls.receipt, calls.block],
  batchRefundWithClaim10: [calls.nonce, calls.fee, calls.estimate10, calls.send10, calls.receipt, calls.block],
  batchRefundWithClaim50: [calls.nonce, calls.fee, calls.estimate50, calls.send50, calls.receipt, calls.block],
  batchRefundWithClaim100: [calls.nonce, calls.fee, calls.estimate100, calls.send100, calls.receipt, calls.block]
} as const;

function scenarioCycles(items: readonly Outcall[]): bigint {
  return items.reduce((total, item) => total + httpsOutcallCycles(item), 0n);
}

function cyclesYen(cycles: bigint): number {
  return Number(cycles) / 1e12 * XDR_USD * USD_JPY;
}

function polygonGasYen(gas: number, gasPriceGwei: number): number {
  const pol = gas * gasPriceGwei / 1e9;
  return pol * POL_USD * USD_JPY;
}

function readAmoyBenchmark(): AmoyBenchmarkReport | undefined {
  if (!existsSync(AMOY_REPORT_PATH)) return undefined;
  return JSON.parse(readFileSync(AMOY_REPORT_PATH, "utf8")) as AmoyBenchmarkReport;
}

function observedGas(report: AmoyBenchmarkReport | undefined, action: string): number | undefined {
  const entry = [...(report?.actions?.exact ?? []), ...(report?.actions?.batch ?? [])]
    .find((item) => item.action === action && item.status === "success");
  if (!entry || !/^[0-9]+$/.test(entry.gasUsed)) return undefined;
  const gas = Number(entry.gasUsed);
  return Number.isSafeInteger(gas) ? gas : undefined;
}

type Cost = {
  readonly gasUsed: number | undefined;
  readonly gasYen: number;
  readonly outcallYen: number;
  readonly totalYen: number;
  readonly safeTotalYen: number;
};

export type FeeDecision = {
  readonly feeJpyc: number;
  readonly safeCostYen: number | undefined;
  readonly status: "measured" | "fallback";
};

function costFor(
  scenario: keyof typeof scenarios,
  report: AmoyBenchmarkReport | undefined,
  action: string | undefined,
  gasPriceGwei: number
): Cost {
  const gasUsed = action ? observedGas(report, action) : undefined;
  const outcallYen = cyclesYen(scenarioCycles(scenarios[scenario]));
  return {
    gasUsed,
    gasYen: gasUsed === undefined ? 0 : polygonGasYen(gasUsed, gasPriceGwei),
    outcallYen,
    totalYen: outcallYen + (gasUsed === undefined ? 0 : polygonGasYen(gasUsed, gasPriceGwei)),
    safeTotalYen: (outcallYen + (gasUsed === undefined ? 0 : polygonGasYen(gasUsed, gasPriceGwei))) * SAFETY_MULTIPLIER
  };
}

export function chooseFee(cost: Cost, tiers: readonly number[], fallback: number): FeeDecision {
  if (cost.gasUsed === undefined) {
    return { feeJpyc: fallback, safeCostYen: undefined, status: "fallback" };
  }
  const fee = tiers.find((candidate) => cost.safeTotalYen <= candidate);
  return {
    feeJpyc: fee ?? fallback,
    safeCostYen: cost.safeTotalYen,
    status: "measured"
  };
}

export function facilitatorCostReport(options: {
  readonly amoy?: AmoyBenchmarkReport;
  readonly gasPriceGwei?: number;
} = {}) {
  const amoy = options.amoy ?? readAmoyBenchmark();
  const gasPriceGwei = options.gasPriceGwei ?? GAS_PRICE_GWEI;
  const scenarioReport = Object.fromEntries(Object.entries(scenarios).map(([name, items]) => {
    const cycles = scenarioCycles(items);
    const hasInstructionMeasurement = false;
    return [name, {
      outcallCost: { cycles: cycles.toString(), yen: cyclesYen(cycles) },
      totalCost: hasInstructionMeasurement ? { status: "available" } : { status: "unavailable", reason: "instruction cycles have not been measured" }
    }];
  }));

  const costs = {
    exact: costFor("normalSettle", amoy, "exact", gasPriceGwei),
    batchDeposit: costFor("batchDeposit", amoy, "batchDeposit", gasPriceGwei),
    batchClaim1: costFor("batchClaim1", amoy, "batchClaim1", gasPriceGwei),
    batchClaim10: costFor("batchClaim10", amoy, "batchClaim10", gasPriceGwei),
    batchClaim50: costFor("batchClaim50", amoy, "batchClaim50", gasPriceGwei),
    batchClaim100: costFor("batchClaim100", amoy, "batchClaim100", gasPriceGwei),
    batchSettle: costFor("batchSettle", amoy, "batchSettle", gasPriceGwei),
    batchRefund: costFor("batchRefund", amoy, "batchRefund", gasPriceGwei),
    batchRefundWithClaim1: costFor("batchRefundWithClaim1", amoy, "batchRefundWithClaim1", gasPriceGwei),
    batchRefundWithClaim10: costFor("batchRefundWithClaim10", amoy, "batchRefundWithClaim10", gasPriceGwei),
    batchRefundWithClaim50: costFor("batchRefundWithClaim50", amoy, "batchRefundWithClaim50", gasPriceGwei),
    batchRefundWithClaim100: costFor("batchRefundWithClaim100", amoy, "batchRefundWithClaim100", gasPriceGwei),
    batchRefundWithClaim: costFor("batchRefundWithClaim100", amoy, "batchRefundWithClaim100", gasPriceGwei),
    batchSettleNoop: costFor("batchSettleNoop", amoy, undefined, gasPriceGwei)
  };
  const feeDecisions = {
    exact: chooseFee(costs.exact, [0.5, 0.75], 1),
    batchDeposit: chooseFee(costs.batchDeposit, [0.5, 1], 10),
    batchClaim1: chooseFee(costs.batchClaim1, [0.5, 1], 10),
    batchClaim10: chooseFee(costs.batchClaim10, [0.5, 1, 2], 10),
    batchClaim50: chooseFee(costs.batchClaim50, [1, 2, 3, 5], 10),
    batchClaim100: chooseFee(costs.batchClaim100, [5, 6], 10),
    batchSettle: chooseFee(costs.batchSettle, [0.5, 1], 10),
    batchRefund: chooseFee(costs.batchRefund, [0.5, 1], 10),
    batchRefundWithClaim1: chooseFee(costs.batchRefundWithClaim1, [0.5, 1], 10),
    batchRefundWithClaim10: chooseFee(costs.batchRefundWithClaim10, [0.5, 1, 2], 10),
    batchRefundWithClaim50: chooseFee(costs.batchRefundWithClaim50, [1, 2, 3, 5], 10),
    batchRefundWithClaim100: chooseFee(costs.batchRefundWithClaim100, [5, 6], 10),
    batchRefundWithClaim: chooseFee(costs.batchRefundWithClaim100, [5, 6], 10)
  };
  const scheduleReady = [
    costs.batchClaim1, costs.batchClaim10, costs.batchClaim50, costs.batchClaim100,
    costs.batchRefundWithClaim1, costs.batchRefundWithClaim10, costs.batchRefundWithClaim50, costs.batchRefundWithClaim100
  ].every((cost) => cost.gasUsed !== undefined);
  const targets = { exact: 0.5, batch: 1 };
  const decision = {
    exact: costs.exact.gasUsed !== undefined && costs.exact.totalYen * SAFETY_MULTIPLIER <= targets.exact,
    batch: [costs.batchDeposit, costs.batchClaim100, costs.batchSettle, costs.batchRefund]
      .every((cost) => cost.gasUsed !== undefined && cost.totalYen * SAFETY_MULTIPLIER <= targets.batch),
    scheduleReady,
    safetyMultiplier: SAFETY_MULTIPLIER,
    targetsJpyc: targets
  };
  const recommendedFeesJpyc = {
    exact: feeDecisions.exact.feeJpyc,
    batch: {
      deposit: feeDecisions.batchDeposit.feeJpyc,
      claim: feeDecisions.batchClaim100.feeJpyc,
      claimSchedule: scheduleReady ? [feeDecisions.batchClaim1, feeDecisions.batchClaim10, feeDecisions.batchClaim50, feeDecisions.batchClaim100] : undefined,
      settle: feeDecisions.batchSettle.feeJpyc,
      refund: feeDecisions.batchRefund.feeJpyc,
      refundWithClaim: feeDecisions.batchRefundWithClaim100.feeJpyc,
      refundWithClaimSchedule: scheduleReady ? [feeDecisions.batchRefundWithClaim1, feeDecisions.batchRefundWithClaim10, feeDecisions.batchRefundWithClaim50, feeDecisions.batchRefundWithClaim100] : undefined
    },
    legacyBatch: feeDecisions.batchClaim100.feeJpyc
  };

  return {
    assumptions: {
      gasPriceGwei,
      nodes: Number(NODES),
      polUsd: POL_USD,
      replicated: false,
      requestBytes: "JSON-RPC body plus an explicit 200-byte URL/header allowance per call",
      usdJpy: USD_JPY,
      xdrUsd: XDR_USD
    },
    amoyBenchmark: amoy ? { path: AMOY_REPORT_PATH, loaded: true } : { path: AMOY_REPORT_PATH, loaded: false },
    polygonGasSamples: {
      revertedClaim100: { gas: 1_029_750, yen: polygonGasYen(1_029_750, gasPriceGwei) }
    },
    recommendedFeesJpyc,
    feeDecisions,
    decision,
    costs,
    scenarios: scenarioReport
  };
}

async function readJson(url: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`HTTP ${response.status} from ${url}`);
  return response.json() as Promise<unknown>;
}

async function readFeeHistory(): Promise<unknown> {
  const rpcUrl = process.env.POLYGON_RPC_URL;
  if (!rpcUrl) return { status: "unavailable", reason: "POLYGON_RPC_URL is not set" };
  try {
    return await readJson(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_feeHistory",
        params: ["0x14", "latest", [10, 25, 50, 75, 90]]
      })
    });
  } catch (error) {
    return { status: "unavailable", reason: error instanceof Error ? error.message : String(error) };
  }
}

export async function fetchMainnetGasPrice(): Promise<MainnetGasPriceReport> {
  const gasStation = await readJson(GAS_STATION_URL);
  const selected = selectMainnetGasPrice(gasStation);
  return {
    ...selected,
    gasStation,
    feeHistory: await readFeeHistory(),
  };
}

async function main(): Promise<void> {
  const liveMainnet = process.argv.includes("--live-mainnet");
  const mainnetGas = liveMainnet ? await fetchMainnetGasPrice() : undefined;
  const report = facilitatorCostReport(mainnetGas ? { gasPriceGwei: mainnetGas.gasPriceGwei } : {});
  const stressGasPriceGwei = mainnetGas?.stressGasPriceGwei;
  const stressCase = stressGasPriceGwei === undefined
    ? undefined
    : facilitatorCostReport({ gasPriceGwei: stressGasPriceGwei });
  console.log(JSON.stringify({
    ...report,
    ...(stressCase ? {
      stressCase: {
        gasPriceGwei: stressGasPriceGwei,
        recommendedFeesJpyc: stressCase.recommendedFeesJpyc,
        feeDecisions: stressCase.feeDecisions,
        costs: stressCase.costs,
        decision: stressCase.decision
      }
    } : {}),
    mainnetGasPrice: mainnetGas ?? { source: "GAS_PRICE_GWEI environment/default" }
  }, null, 2));
  if (liveMainnet && (!report.decision.exact || !report.decision.batch)) {
    process.exitCode = 2;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
