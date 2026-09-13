// scripts/facilitator_costs.ts: MainnetのPOL単価とAmoy実測gasUsedを使って原価を概算する。
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { loadDotenv } from "./env_file";

loadDotenv();

const NODES = 7n;
const XDR_USD = Number(process.env.XDR_USD ?? "1.36643");
const USD_JPY = Number(process.env.USD_JPY ?? "153.86");
const POL_USD = Number(process.env.POL_USD ?? "0.095019");
const GAS_PRICE_GWEI = Number(process.env.GAS_PRICE_GWEI ?? "335");
const SAFETY_MULTIPLIER = Number(process.env.FEE_SAFETY_MULTIPLIER ?? "1.2");
const GAS_REPORT_PATH = resolve(process.cwd(), process.env.FACILITATOR_GAS_BENCHMARK_PATH ?? "docs/local-gas-benchmark.json");
const GAS_STATION_URL = "https://gasstation.polygon.technology/v2";

export type Outcall = { readonly maxResponseBytes: number; readonly requestBytes: number };
export type BenchmarkAction = {
  readonly action: string;
  readonly gasUsed: string;
  readonly status: "success" | "reverted";
};
export type AmoyBenchmarkReport = {
  readonly network?: string;
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
  const fast = tiers.fast?.maxFee;
  const stressGasPriceGwei = positiveNumber(fast) ? fast : undefined;

  if (override !== undefined) {
    const gasPriceGwei = Number(override);
    if (!positiveNumber(gasPriceGwei)) throw new Error("MAINNET_GAS_PRICE_GWEI must be positive");
    return { gasPriceGwei, stressGasPriceGwei, source: "MAINNET_GAS_PRICE_GWEI override" };
  }

  if (!positiveNumber(GAS_PRICE_GWEI)) throw new Error("GAS_PRICE_GWEI must be positive");
  return {
    gasPriceGwei: GAS_PRICE_GWEI,
    stressGasPriceGwei,
    source: "fixed baseline: sampled Polygon block effective fees (docs/polygon-gas-baseline.json), overridable by GAS_PRICE_GWEI"
  };
}

export type OutcallPricing = {
  readonly nodes: number;
  readonly responseTimeMs: number;
};

const DEFAULT_OUTCALL_PRICING: OutcallPricing = { nodes: Number(NODES), responseTimeMs: 1_000 };

function validateOutcallPricing(pricing: OutcallPricing): void {
  if (!Number.isSafeInteger(pricing.nodes) || pricing.nodes < 1
    || !Number.isSafeInteger(pricing.responseTimeMs) || pricing.responseTimeMs < 0) {
    throw new Error("outcall nodes must be a positive integer and responseTimeMs a non-negative integer");
  }
}

// Successful non-replicated v2 outcall, without a transform. Response limits are
// used as size estimates; this is not the upfront cost_http_request_v2 reservation.
// https://github.com/dfinity/ic/blob/a9ef6104790755ea520c0d4546e61fe130136805/rs/https_outcalls/pricing/src/fees.rs
export function httpsOutcallCycles(call: Outcall, pricing: OutcallPricing = DEFAULT_OUTCALL_PRICING): bigint {
  validateOutcallPricing(pricing);
  if (![call.requestBytes, call.maxResponseBytes].every((n) => Number.isSafeInteger(n) && n >= 0)) {
    throw new Error("outcall byte sizes must be non-negative integers");
  }
  const nodes = BigInt(pricing.nodes);
  const responseBytes = BigInt(call.maxResponseBytes);
  const base = (1_100_000n + 92_000n * nodes + 50n * BigInt(call.requestBytes)) * nodes;
  const network = 50n * responseBytes + 300n * BigInt(pricing.responseTimeMs);
  const gossip = 50n * nodes * responseBytes;
  const consensus = nodes * (10n * nodes + 600n) * responseBytes;
  return base + network + gossip + consensus;
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

function scenarioCycles(items: readonly Outcall[], pricing: OutcallPricing): bigint {
  return items.reduce((total, item) => total + httpsOutcallCycles(item, pricing), 0n);
}

function cyclesYen(cycles: bigint): number {
  return Number(cycles) / 1e12 * XDR_USD * USD_JPY;
}

function polygonGasYen(gas: number, gasPriceGwei: number): number {
  const pol = gas * gasPriceGwei / 1e9;
  return pol * POL_USD * USD_JPY;
}

function readAmoyBenchmark(): AmoyBenchmarkReport | undefined {
  if (!existsSync(GAS_REPORT_PATH)) return undefined;
  return JSON.parse(readFileSync(GAS_REPORT_PATH, "utf8")) as AmoyBenchmarkReport;
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
  gasPriceGwei: number,
  pricing: OutcallPricing
): Cost {
  const gasUsed = action ? observedGas(report, action) : undefined;
  const outcallYen = cyclesYen(scenarioCycles(scenarios[scenario], pricing));
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
    feeJpyc: fee ?? Math.max(fallback, Math.ceil(cost.safeTotalYen)),
    safeCostYen: cost.safeTotalYen,
    status: "measured"
  };
}

export function facilitatorCostReport(options: {
  readonly amoy?: AmoyBenchmarkReport;
  readonly gasPriceGwei?: number;
  readonly outcallPricing?: OutcallPricing;
} = {}) {
  const pricing = options.outcallPricing ?? DEFAULT_OUTCALL_PRICING;
  validateOutcallPricing(pricing);
  const amoy = options.amoy ?? readAmoyBenchmark();
  const gasPriceGwei = options.gasPriceGwei ?? GAS_PRICE_GWEI;
  const scenarioReport = Object.fromEntries(Object.entries(scenarios).map(([name, items]) => {
    const cycles = scenarioCycles(items, pricing);
    const hasInstructionMeasurement = false;
    return [name, {
      outcallCost: { cycles: cycles.toString(), yen: cyclesYen(cycles) },
      totalCost: hasInstructionMeasurement ? { status: "available" } : { status: "unavailable", reason: "instruction cycles have not been measured" }
    }];
  }));

  const costs = {
    exact: costFor("normalSettle", amoy, "exact", gasPriceGwei, pricing),
    batchDeposit: costFor("batchDeposit", amoy, "batchDeposit", gasPriceGwei, pricing),
    batchClaim1: costFor("batchClaim1", amoy, "batchClaim1", gasPriceGwei, pricing),
    batchClaim10: costFor("batchClaim10", amoy, "batchClaim10", gasPriceGwei, pricing),
    batchClaim50: costFor("batchClaim50", amoy, "batchClaim50", gasPriceGwei, pricing),
    batchClaim100: costFor("batchClaim100", amoy, "batchClaim100", gasPriceGwei, pricing),
    batchSettle: costFor("batchSettle", amoy, "batchSettle", gasPriceGwei, pricing),
    batchRefund: costFor("batchRefund", amoy, "batchRefund", gasPriceGwei, pricing),
    batchRefundWithClaim1: costFor("batchRefundWithClaim1", amoy, "batchRefundWithClaim1", gasPriceGwei, pricing),
    batchRefundWithClaim10: costFor("batchRefundWithClaim10", amoy, "batchRefundWithClaim10", gasPriceGwei, pricing),
    batchRefundWithClaim50: costFor("batchRefundWithClaim50", amoy, "batchRefundWithClaim50", gasPriceGwei, pricing),
    batchRefundWithClaim100: costFor("batchRefundWithClaim100", amoy, "batchRefundWithClaim100", gasPriceGwei, pricing),
    batchRefundWithClaim: costFor("batchRefundWithClaim100", amoy, "batchRefundWithClaim100", gasPriceGwei, pricing),
    batchSettleNoop: costFor("batchSettleNoop", amoy, undefined, gasPriceGwei, pricing)
  };
  const claimTiers = [0.5, 0.75, ...Array.from({ length: 50 }, (_, i) => i + 1)];
  const feeDecisions = {
    exact: chooseFee(costs.exact, [0.5, 0.75], 1),
    batchDeposit: chooseFee(costs.batchDeposit, claimTiers, 10),
    batchClaim1: chooseFee(costs.batchClaim1, claimTiers, 10),
    batchClaim10: chooseFee(costs.batchClaim10, claimTiers, 10),
    batchClaim50: chooseFee(costs.batchClaim50, claimTiers, 10),
    batchClaim100: chooseFee(costs.batchClaim100, claimTiers, 10),
    batchSettle: chooseFee(costs.batchSettle, claimTiers, 10),
    batchRefund: chooseFee(costs.batchRefund, claimTiers, 10),
    batchRefundWithClaim1: chooseFee(costs.batchRefundWithClaim1, claimTiers, 10),
    batchRefundWithClaim10: chooseFee(costs.batchRefundWithClaim10, claimTiers, 10),
    batchRefundWithClaim50: chooseFee(costs.batchRefundWithClaim50, claimTiers, 10),
    batchRefundWithClaim100: chooseFee(costs.batchRefundWithClaim100, claimTiers, 10),
    batchRefundWithClaim: chooseFee(costs.batchRefundWithClaim100, claimTiers, 10)
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
      nodes: pricing.nodes,
      pricingVersion: 2,
      responseTimeMs: pricing.responseTimeMs,
      responseBytes: "configured limits used as raw and encoded response size estimates; headers/Candid overhead and retries may differ",
      polUsd: POL_USD,
      replicated: false,
      requestBytes: "JSON-RPC body plus an explicit 200-byte URL/header allowance per call",
      usdJpy: USD_JPY,
      xdrUsd: XDR_USD
    },
    gasBenchmark: { path: options.amoy ? "provided" : GAS_REPORT_PATH, loaded: Boolean(amoy), network: amoy?.network ?? "unspecified" },
    polygonGasSamples: {
      revertedClaim100: { gas: 1_029_750, yen: polygonGasYen(1_029_750, gasPriceGwei) }
    },
    recommendationStatus: "provisional",
    unmeasuredCosts: ["canister execution and storage", "retries and failed transactions", "RPC provider fees", "actual v2 responses, latency and asynchronous refunds"],
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
