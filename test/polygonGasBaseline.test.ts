import { describe, expect, it } from "vitest";
import { effectiveGasSamples, gasStatistics } from "../scripts/polygon_gas_baseline";

describe("Polygon normal gas baseline", () => {
  it("uses historical base plus median effective tip, excluding the next-block forecast and empty blocks", () => {
    expect(effectiveGasSamples({
      oldestBlock: "0x1",
      baseFeePerGas: ["0x3b9aca00", "0x77359400", "0xffffffffffff"],
      reward: [["0x3b9aca00"], ["0x0"]],
      gasUsedRatio: [0.5, 0],
    })).toEqual([2]);
  });

  it("reports the arithmetic mean without silently discarding expensive blocks", () => {
    expect(gasStatistics([10, 20, 30, 100])).toEqual({
      blocks: 4, meanGwei: 40, medianGwei: 20, p90Gwei: 100, minGwei: 10, maxGwei: 100,
    });
    expect(() => gasStatistics([])).toThrow();
    expect(() => gasStatistics([NaN])).toThrow();
  });

  it("rejects incomplete historical windows", () => {
    expect(() => effectiveGasSamples({
      oldestBlock: "0x1", baseFeePerGas: ["0x1"], reward: [["0x1"]], gasUsedRatio: [0.5],
    })).toThrow("incomplete");
  });
});
