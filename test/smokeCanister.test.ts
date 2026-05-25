// test/smokeCanister.test.ts: facilitator canister smoke が公開APIの最小形を検証することを確認する。
import { describe, expect, it } from "vitest";

import { checkCanisterSmoke } from "../scripts/smoke_canister";

const baseUrl = "https://canister.example.test";
const facilitatorAddress = "0x1000000000000000000000000000000000000402";

function responseFor(supported: unknown = {
  kinds: [{
    x402Version: 2,
    scheme: "exact",
    network: "eip155:137",
    extra: { assetTransferMethod: "permit2" }
  }],
  extensions: [],
  signers: { "eip155:*": [facilitatorAddress] }
}): typeof fetch {
  return async (input) => {
    if (String(input) === `${baseUrl}/health`) {
      return Response.json({ ok: true, network: "eip155:137", facilitatorAddress });
    }
    if (String(input) === `${baseUrl}/supported`) {
      return Response.json(supported);
    }
    return new Response("not found", { status: 404 });
  };
}

describe("canister smoke", () => {
  it("verifies facilitator health and supported shape", async () => {
    await expect(
      checkCanisterSmoke({
        env: { X402_BASE_URL: baseUrl },
        fetchFn: responseFor()
      })
    ).resolves.toMatchObject({
      baseUrl,
      facilitatorAddress,
      healthStatus: 200,
      supportedStatus: 200
    });
  });

  it("rejects invalid facilitator addresses", async () => {
    await expect(
      checkCanisterSmoke({
        env: { X402_BASE_URL: baseUrl },
        fetchFn: async (input) => {
          if (String(input) === `${baseUrl}/health`) {
            return Response.json({ ok: true, network: "eip155:137", facilitatorAddress: "0x402" });
          }
          return Response.json({ kinds: [] });
        }
      })
    ).rejects.toThrow("health.facilitatorAddress must be an EVM address");
  });

  it("rejects unsupported facilitator kinds", async () => {
    await expect(
      checkCanisterSmoke({
        env: { X402_BASE_URL: baseUrl },
        fetchFn: responseFor({ kinds: [], extensions: [], signers: {} })
      })
    ).rejects.toThrow("supported lacks x402 v2 exact/eip155:137 permit2");
  });
});
