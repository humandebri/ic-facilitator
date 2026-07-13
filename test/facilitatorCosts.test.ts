import { describe, expect, it } from "vitest";
import { facilitatorCostReport, httpsOutcallCycles } from "../scripts/facilitator_costs";

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
  });
});
