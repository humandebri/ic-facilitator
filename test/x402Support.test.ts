// test/x402Support.test.ts: facilitator support の x402 v2/exact/Polygon 判定を確認する。
import { describe, expect, it } from "vitest";
import type { SupportedResponse } from "@x402/core/types";

import { supportsExpectedX402Kind } from "../src/x402Support";

describe("x402 support helpers", () => {
  it("requires x402 v2 exact EIP-3009 support on Polygon", () => {
    const kinds: SupportedResponse["kinds"] = [
      { x402Version: 1, scheme: "exact", network: "eip155:137" },
      { x402Version: 2, scheme: "exact", network: "eip155:8453" },
      { x402Version: 2, scheme: "exact", network: "eip155:137" }
    ];

    expect(supportsExpectedX402Kind(kinds)).toBe(false);
    expect(supportsExpectedX402Kind([...kinds, {
      x402Version: 2,
      scheme: "exact",
      network: "eip155:137",
      extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
    }])).toBe(true);
  });
});
