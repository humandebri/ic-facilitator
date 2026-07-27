import { describe, expect, it } from "vitest";
import { chooseFee, facilitatorCostReport, httpsOutcallCycles, selectMainnetGasPrice, type AmoyBenchmarkReport } from "../scripts/facilitator_costs";

describe("facilitator cost report", () => {
  it("uses the published 13-node HTTPS outcall formula", () => {
    expect(httpsOutcallCycles({ requestBytes: 0, maxResponseBytes: 0 })).toBe(49_140_000n);
  });

  it("keeps free/query paths separate from transaction paths", () => {
    const report = facilitatorCostReport();
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
      batch: { deposit: 0.5, claim: 5, settle: 0.5, refund: 0.5 }
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
    expect(selectMainnetGasPrice(gasStation, "300").gasPriceGwei).not.toBe(616);
    expect(selectMainnetGasPrice(gasStation, undefined).gasPriceGwei).toBe(557);
  });

  it("selects the cheapest fee tier at exact boundaries and falls back after overflow", () => {
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
    expect(chooseFee(cost(0.5, undefined), [0.5, 0.75], 1).status).toBe("fallback");
  });
});
