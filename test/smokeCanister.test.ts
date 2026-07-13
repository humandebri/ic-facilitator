// test/smokeCanister.test.ts: facilitator canister smoke が公開APIの最小形を検証することを確認する。
import { describe, expect, it } from "vitest";

import { checkCanisterSmoke } from "../scripts/smoke_canister";

const baseUrl = "https://canister.example.test";
const facilitatorAddress = "0x1000000000000000000000000000000000000402";
const receiverAuthorizerPrivateKey = `0x${"2".repeat(64)}`;
const receiverAuthorizer = "0x1563915e194D8CfBA1943570603F7606A3115508";
const batchSettlementContract = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";

type SupportedKind = {
  readonly extra: Record<string, unknown>;
  readonly network: string;
  readonly scheme: string;
  readonly x402Version: number;
};

type SupportedResponse = {
  readonly extensions: readonly unknown[];
  readonly kinds: readonly SupportedKind[];
  readonly signers: Record<string, readonly string[]>;
};

function env(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
    BATCH_SETTLEMENT_CONTRACT: batchSettlementContract,
    BATCH_SETTLEMENT_FEE_AMOUNT: "100",
    BATCH_WITHDRAW_DELAY_SECONDS: "900",
    JPYC_EIP712_VERSION: "1",
    X402_BASE_URL: baseUrl,
    ...overrides
  };
}

function supportedWithBatch(): SupportedResponse {
  return {
    kinds: [{
      x402Version: 2,
      scheme: "exact",
      network: "eip155:137",
      extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
    }, {
      x402Version: 2,
      scheme: "batch-settlement",
      network: "eip155:137",
      extra: {
        assetTransferMethod: "eip3009",
        name: "JPY Coin",
        receiverAuthorizer,
        version: "1",
        withdrawDelay: 900
      }
    }],
    extensions: [],
    signers: { "eip155:*": [facilitatorAddress], "eip155:137": [facilitatorAddress] }
  };
}

function responseFor(supported: unknown = {
  kinds: [{
    x402Version: 2,
    scheme: "exact",
    network: "eip155:137",
    extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
  }],
  extensions: [],
  signers: { "eip155:137": [facilitatorAddress] }
}): typeof fetch {
  return async (input, init) => {
    if (String(input) === `${baseUrl}/health`) {
      return Response.json({ ok: true, network: "eip155:137", facilitatorAddress });
    }
    if (String(input) === `${baseUrl}/supported`) {
      return Response.json(supported);
    }
    if (String(input) === `${baseUrl}/verify` && init?.method === "POST") {
      return Response.json({ isValid: false, invalidReason: "unsupported_verify_scheme" }, { status: 400 });
    }
    return new Response("not found", { status: 404 });
  };
}

describe("canister smoke", () => {
  it("verifies facilitator health and supported shape", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor()
      })
    ).resolves.toMatchObject({
      baseUrl,
      facilitatorAddress,
      healthStatus: 200,
      supportedStatus: 200
    });
  });

  it("requires deployed RPC and normal fee to match local production config", async () => {
    const fetchFn: typeof fetch = async (input) => {
      if (String(input) === `${baseUrl}/health`) {
        return Response.json({
          ok: true,
          network: "eip155:137",
          facilitatorAddress,
          polygonRpcConfigured: true,
          sellerSettlementFeeAmount: "1000000000000000000"
        });
      }
      return responseFor()(input);
    };
    await expect(checkCanisterSmoke({
      env: env({ SELLER_SETTLEMENT_FEE_AMOUNT: "1000000000000000000" }),
      fetchFn
    })).resolves.toMatchObject({ facilitatorAddress });
    await expect(checkCanisterSmoke({
      env: env({ SELLER_SETTLEMENT_FEE_AMOUNT: "2000000000000000000" }),
      fetchFn
    })).rejects.toThrow("health.sellerSettlementFeeAmount mismatch");
  });

  it("rejects invalid facilitator addresses", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: async (input) => {
          if (String(input) === `${baseUrl}/health`) {
            return Response.json({ ok: true, network: "eip155:137", facilitatorAddress: "0x402" });
          }
          return Response.json({ kinds: [] });
        }
      })
    ).rejects.toThrow("health.facilitatorAddress must be an EVM address");
  });

  it("rejects health responses for the wrong network", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: async (input) => {
          if (String(input) === `${baseUrl}/health`) {
            return Response.json({ ok: true, network: "eip155:1", facilitatorAddress });
          }
          return Response.json({ kinds: [] });
        }
      })
    ).rejects.toThrow("health.network must be eip155:137");
  });

  it("rejects array values where response objects are required", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: async (input) => {
          if (String(input) === `${baseUrl}/health`) {
            return Response.json([]);
          }
          return Response.json({ kinds: [] });
        }
      })
    ).rejects.toThrow("health must be an object");

    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor({
          kinds: [{
            x402Version: 2,
            scheme: "exact",
            network: "eip155:137",
            extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
          }],
          extensions: [],
          signers: []
        })
      })
    ).rejects.toThrow("supported.signers must be an object");
  });

  it("rejects unsupported facilitator kinds", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor({ kinds: [], extensions: [], signers: {} })
      })
    ).rejects.toThrow("supported lacks x402 v2 exact/eip155:137 eip3009");
  });

  it("rejects wildcard EVM signers", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor({
          kinds: [{
            x402Version: 2,
            scheme: "exact",
            network: "eip155:137",
            extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
          }],
          extensions: [],
          signers: { "eip155:*": [facilitatorAddress] }
        })
      })
    ).rejects.toThrow("supported.signers must not use eip155:*");
  });

  it("requires batch wildcard signer only when batch support is required", async () => {
    const supported = supportedWithBatch();
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor({
          ...supported,
          signers: { "eip155:137": [facilitatorAddress] }
        }),
        requireBatch: true
      })
    ).rejects.toThrow("supported.signers lacks eip155:* batch facilitator address");
  });

  it("can require batch-settlement support", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).resolves.toMatchObject({
      baseUrl,
      facilitatorAddress,
      verifyStatus: 400
    });
  });

  it("rejects missing batch-settlement support when required", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor(),
        requireBatch: true
      })
    ).rejects.toThrow("supported lacks x402 v2 batch-settlement/eip155:137");
  });

  it("rejects batch smoke when /verify does not expose the batch-only endpoint", async () => {
    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: async (input) => {
          if (String(input) === `${baseUrl}/health`) {
            return Response.json({ ok: true, network: "eip155:137", facilitatorAddress });
          }
          if (String(input) === `${baseUrl}/supported`) {
            return Response.json(supportedWithBatch());
          }
          if (String(input) === `${baseUrl}/verify`) {
            return Response.json({ isValid: false, invalidReason: "invalid_request" }, { status: 400 });
          }
          return new Response("not found", { status: 404 });
        },
        requireBatch: true
      })
    ).rejects.toThrow("verify must reject exact scheme with unsupported_verify_scheme");
  });

  it("rejects batch support when receiverAuthorizer does not match env private key", async () => {
    const supported = supportedWithBatch();
    const kinds = supported.kinds.map((item) => {
      if (item.scheme !== "batch-settlement") {
        return item;
      }
      return {
        ...item,
        extra: {
          ...item.extra,
          receiverAuthorizer: "0x2000000000000000000000000000000000000402"
        }
      };
    });

    await expect(
      checkCanisterSmoke({
        env: env(),
        fetchFn: responseFor({ ...supported, kinds }),
        requireBatch: true
      })
    ).rejects.toThrow("supported.batch.extra.receiverAuthorizer does not match BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  });

  it("rejects batch smoke when local batch config is incomplete", async () => {
    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_SETTLEMENT_CONTRACT: "" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("missing env: BATCH_SETTLEMENT_CONTRACT");

    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_SETTLEMENT_CONTRACT: "0x0000000000000000000000000000000000000001" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow(`BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${batchSettlementContract}`);

  });

  it("rejects batch support when withdrawDelay or version differs from env", async () => {
    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_WITHDRAW_DELAY_SECONDS: "901" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("supported.batch.extra.withdrawDelay does not match BATCH_WITHDRAW_DELAY_SECONDS");

    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_WITHDRAW_DELAY_SECONDS: "899" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("BATCH_WITHDRAW_DELAY_SECONDS must be between 900 and 2592000");

    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_WITHDRAW_DELAY_SECONDS: "2592001" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("BATCH_WITHDRAW_DELAY_SECONDS must be between 900 and 2592000");

    await expect(
      checkCanisterSmoke({
        env: env({ JPYC_EIP712_VERSION: "2" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("supported.batch.extra.version does not match JPYC_EIP712_VERSION");
  });

  it("rejects batch smoke when settlement fee env is missing or invalid", async () => {
    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_SETTLEMENT_FEE_AMOUNT: "" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("missing env: BATCH_SETTLEMENT_FEE_AMOUNT");

    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_SETTLEMENT_FEE_AMOUNT: "0" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("BATCH_SETTLEMENT_FEE_AMOUNT must be a positive integer");

    await expect(
      checkCanisterSmoke({
        env: env({ BATCH_SETTLEMENT_FEE_AMOUNT: "340282366920938463463374607431768211456" }),
        fetchFn: responseFor(supportedWithBatch()),
        requireBatch: true
      })
    ).rejects.toThrow("BATCH_SETTLEMENT_FEE_AMOUNT must fit uint128");
  });

  it("requires a public HTTPS origin for mainnet batch smoke", async () => {
    const failFetch: typeof fetch = async () => {
      throw new Error("fetch should not be called");
    };

    await expect(
      checkCanisterSmoke({
        env: env({ ICP_ENVIRONMENT: "ic", X402_BASE_URL: "" }),
        fetchFn: failFetch,
        requireBatch: true
      })
    ).rejects.toThrow("X402_BASE_URL is required for mainnet batch smoke");

    await expect(
      checkCanisterSmoke({
        env: env({ ICP_ENVIRONMENT: "ic", X402_BASE_URL: "http://edge.local.localhost:8000" }),
        fetchFn: failFetch,
        requireBatch: true
      })
    ).rejects.toThrow("X402_BASE_URL must be a https://host[:port] origin for mainnet batch smoke");

    await expect(
      checkCanisterSmoke({
        env: env({ ICP_ENVIRONMENT: "ic", X402_BASE_URL: "https://canister.example.test/path" }),
        fetchFn: failFetch,
        requireBatch: true
      })
    ).rejects.toThrow("X402_BASE_URL must be a https://host[:port] origin for mainnet batch smoke");

    for (const value of [
      " https://canister.example.test",
      "https://canister.example.test ",
      "https://trusted.example@evil.example",
      "https://canister.example.test/",
      "https://canister.example.test?x=1",
      "https://canister.example.test#x"
    ]) {
      await expect(
        checkCanisterSmoke({
          env: env({ ICP_ENVIRONMENT: "ic", X402_BASE_URL: value }),
          fetchFn: failFetch,
          requireBatch: true
        })
      ).rejects.toThrow("X402_BASE_URL must be a https://host[:port] origin for mainnet batch smoke");
    }
  });
});
