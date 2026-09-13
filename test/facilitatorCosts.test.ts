import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { parseDotenv } from "../scripts/env_file";
import { chooseFee, facilitatorCostReport, httpsOutcallCycles, selectMainnetGasPrice, type AmoyBenchmarkReport } from "../scripts/facilitator_costs";

describe("facilitator cost report", () => {
  it("keeps the fixed fee configuration aligned with the saved local gas calibration", () => {
    const benchmark = JSON.parse(readFileSync("docs/local-gas-benchmark.json", "utf8")) as AmoyBenchmarkReport;
    const report = facilitatorCostReport({ amoy: benchmark, gasPriceGwei: 335 });
    const env = parseDotenv(readFileSync(".env.example", "utf8"));
    const atomic = (fee: number) => BigInt(Math.round(fee * 100)) * 10n ** 16n;
    expect(BigInt(env.SELLER_SETTLEMENT_FEE_AMOUNT!)).toBe(atomic(report.recommendedFeesJpyc.exact));
    for (const [action, fee] of Object.entries({
      DEPOSIT: report.recommendedFeesJpyc.batch.deposit,
      SETTLE: report.recommendedFeesJpyc.batch.settle,
      REFUND: report.recommendedFeesJpyc.batch.refund,
      CLAIM: report.recommendedFeesJpyc.batch.claim,
    })) expect(BigInt(env[`BATCH_${action}_FEE_AMOUNT`]!)).toBe(atomic(fee));
    for (const [prefix, schedule] of [
      ["BATCH_CLAIM", report.recommendedFeesJpyc.batch.claimSchedule],
      ["BATCH_REFUND_WITH_CLAIM", report.recommendedFeesJpyc.batch.refundWithClaimSchedule],
    ] as const) {
      expect(schedule).toHaveLength(4);
      for (const [index, count] of [1, 10, 50, 100].entries()) {
        expect(BigInt(env[`${prefix}_${count}_FEE_AMOUNT`]!)).toBe(atomic(schedule![index]!.feeJpyc));
        if (index) expect(schedule![index]!.feeJpyc).toBeGreaterThanOrEqual(schedule![index - 1]!.feeJpyc);
      }
    }
  });
  it("uses v2 non-replicated pricing on seven nodes", () => {
    expect(httpsOutcallCycles({ requestBytes: 0, maxResponseBytes: 0 })).toBe(12_508_000n);
  });

  it("accounts for response dissemination and actual waiting time", () => {
    const call = { requestBytes: 263, maxResponseBytes: 128 };
    expect(httpsOutcallCycles(call)).toBe(13_251_570n);
    expect(httpsOutcallCycles(call, { nodes: 13, responseTimeMs: 1_000 })).toBe(31_623_270n);
    expect(httpsOutcallCycles(call, { nodes: 7, responseTimeMs: 3_000 }) - httpsOutcallCycles(call)).toBe(600_000n);
    expect(() => httpsOutcallCycles(call, { nodes: 0, responseTimeMs: 1_000 })).toThrow();
    expect(() => httpsOutcallCycles(call, { nodes: 7, responseTimeMs: -1 })).toThrow();
  });

  it("marks recommendations provisional and never treats reverted gas as a success sample", () => {
    const report = facilitatorCostReport({ amoy: { actions: { batch: [
      { action: "batchClaim100", gasUsed: "1029750", status: "reverted" }
    ] } } });
    expect(report.recommendationStatus).toBe("provisional");
    expect(report.assumptions).toMatchObject({ nodes: 7, pricingVersion: 2, responseTimeMs: 1_000 });
    expect(report.feeDecisions.batchClaim100.status).toBe("fallback");
    expect(report.recommendedFeesJpyc.batch.claim).toBe(10);
    expect(report.decision.scheduleReady).toBe(false);
  });

  it("keeps free/query paths separate from transaction paths", () => {
    const report = facilitatorCostReport({ amoy: { actions: {} } });
    expect(report.scenarios.supported?.outcallCost.cycles).toBe("0");
    expect(report.scenarios.verify?.totalCost.status).toBe("unavailable");
    expect(BigInt(report.scenarios.batchClaim100!.outcallCost.cycles)).toBeGreaterThan(BigInt(report.scenarios.normalSettle!.outcallCost.cycles));
    expect(report.assumptions.replicated).toBe(false);
    expect(report.recommendedFeesJpyc).toMatchObject({
      exact: 1,
      legacyBatch: 10,
      batch: { claim: 10, deposit: 10, settle: 10, refund: 10 }
    });
  });

  it("combines Amoy gasUsed with the selected mainnet gas price", () => {
    const amoy: AmoyBenchmarkReport = {
      actions: {
        exact: [{ action: "exact", gasUsed: "100000", status: "success" }],
        batch: [
          { action: "batchDeposit", gasUsed: "100000", status: "success" },
          { action: "batchClaim100", gasUsed: "1000000", status: "success" },
          { action: "batchSettle", gasUsed: "200000", status: "success" },
          { action: "batchRefund", gasUsed: "200000", status: "success" }
        ]
      }
    };
    const report = facilitatorCostReport({ amoy, gasPriceGwei: 30 });
    expect(report.decision.exact).toBe(true);
    expect(report.decision.batch).toBe(true);
    expect(report.costs.batchClaim100.gasUsed).toBe(1000000);
    expect(report.costs.batchClaim100.totalYen).toBeGreaterThan(report.costs.batchSettle.totalYen);
    expect(report.recommendedFeesJpyc).toMatchObject({
      exact: 0.5,
      batch: { deposit: 0.5, claim: 0.75, settle: 0.5, refund: 0.5 }
    });
  });

  it("does not use fast as the normal gas-price assumption", () => {
    const gasStation = {
      standard: { maxFee: 557 },
      fast: { maxFee: 616 }
    };
    expect(selectMainnetGasPrice(gasStation, "300")).toEqual({
      gasPriceGwei: 300,
      stressGasPriceGwei: 616,
      source: "MAINNET_GAS_PRICE_GWEI override"
    });
    expect(selectMainnetGasPrice(gasStation, undefined).gasPriceGwei).toBe(335);
  });

  it("selects the cheapest fee tier at exact boundaries and covers cost after tier overflow", () => {
    const cost = (safeTotalYen: number, gasUsed: number | undefined) => ({
      gasUsed,
      gasYen: 0,
      outcallYen: 0,
      totalYen: safeTotalYen,
      safeTotalYen
    });
    expect(chooseFee(cost(0.5, 1), [0.5, 0.75], 1).feeJpyc).toBe(0.5);
    expect(chooseFee(cost(0.500001, 1), [0.5, 0.75], 1).feeJpyc).toBe(0.75);
    expect(chooseFee(cost(0.750001, 1), [0.5, 0.75], 1).feeJpyc).toBe(1);
    expect(chooseFee(cost(0.5, 0), [0.5, 0.75], 1).status).toBe("measured");
    expect(chooseFee(cost(12.1, 1), [0.5, 1], 10).feeJpyc).toBe(13);
    expect(chooseFee(cost(0.5, undefined), [0.5, 0.75], 1).status).toBe("fallback");
  });
});
