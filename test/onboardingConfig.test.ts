import { describe, expect, it } from "vitest";

import { healthMatchesWebConfig } from "../web/src/runtime_config";
import type { Health } from "../web/src/types";

const healthyPreview: Health = {
  ok: true,
  readiness: true,
  chainId: 80002,
  network: "eip155:80002",
  networkProfile: "amoy",
  token: "0x2000000000000000000000000000000000000002",
  batchSettlementContract: "0x4020074e9df2ce1dee5a9c1b5c3f541d02a10003",
  facilitatorAddress: "0x1000000000000000000000000000000000000001",
  polygonRpcConfigured: true,
};
const previewConfig = {
  chainId: 80002,
  environment: "preview",
  tokenAddress: "0x2000000000000000000000000000000000000002",
  batchSettlementContract: "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003",
} as const;

describe("onboarding runtime guard", () => {
  it("accepts a matching preview health response", () => {
    expect(healthMatchesWebConfig(healthyPreview, previewConfig)).toBe(true);
  });

  it.each([
    { chainId: 137 },
    { network: "eip155:137" },
    { networkProfile: "polygon" },
    { readiness: false },
    { token: "0x3000000000000000000000000000000000000003" },
    { batchSettlementContract: "0x3000000000000000000000000000000000000003" },
  ])("blocks signing when runtime field differs: %o", (change) => {
    expect(healthMatchesWebConfig({ ...healthyPreview, ...change }, previewConfig)).toBe(false);
  });

  it("blocks signing when the health token or contract is absent", () => {
    const { token: _token, ...withoutToken } = healthyPreview;
    const { batchSettlementContract: _contract, ...withoutContract } = healthyPreview;
    expect(healthMatchesWebConfig(withoutToken, previewConfig)).toBe(false);
    expect(healthMatchesWebConfig(withoutContract, previewConfig)).toBe(false);
  });
});
