// test/readiness.test.ts: canister-only readiness が不足条件だけを公開することを確認する。
import { describe, expect, it } from "vitest";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import type { Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildReadinessReport, buildReadinessReportWithSmoke, shouldFailReadiness } from "../scripts/readiness";

const seller = "0x1000000000000000000000000000000000000402";
const privateKey: Hex = `0x${"1".repeat(64)}`;
const baseUrl = "https://canister.example.test";
const resourceUrl = `${baseUrl}/jpyc/report`;
const hash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000402";
const jpyc: Hex = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const transferTopic: Hex = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const facilitatorKeyEnv = ["FACILITATOR", "EVM", "PRIVATE", "KEY"].join("_");
const envNamesOutput = `(
  vec { "${facilitatorKeyEnv}"; "FACILITATOR_MAX_GAS"; "FACILITATOR_MAX_SETTLEMENT_FEE_WEI"; "FACILITATOR_PUBLIC_ORIGIN"; "JPYC_EIP712_VERSION"; "POLYGON_RPC_SERVICES"; "SELLER_CREDIT_PAY_TO"; "SELLER_CREDIT_TOPUP_AMOUNT"; "SELLER_SETTLEMENT_FEE_AMOUNT"; "SETTLE_CONFIRMATION_TIMEOUT_SECONDS"; "SETTLE_MIN_CONFIRMATIONS"; "SETTLEMENT_CACHE_TTL_SECONDS";},
)`;

const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: { url: resourceUrl, description: "JPYC protected report", mimeType: "application/json" },
  accepts: [{
    scheme: "exact",
    network: "eip155:137",
    amount: "1000000000000000000",
    asset: jpyc,
    payTo: seller,
    maxTimeoutSeconds: 60,
    extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
  }]
};

function topicAddress(address: Hex): Hex {
  return `0x${"0".repeat(24)}${address.slice(2)}` as Hex;
}

function uint256(value: bigint): Hex {
  return `0x${value.toString(16).padStart(64, "0")}` as Hex;
}

function paidNegativeFetch(calls?: { value: number }): typeof fetch {
  return async (_input, init) => {
    if (calls) { calls.value += 1; }
    if (!new Headers(init?.headers).has("payment-signature")) {
      return new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
      });
    }
    return new Response(JSON.stringify({ error: "payment_required" }), { status: 402 });
  };
}

describe("jpyc readiness", () => {
  it("summarizes missing canister and buyer env without exposing values", () => {
    const report = buildReadinessReport(".", {});

    expect(report.readyForPreflight).toBe(false);
    expect(report.realSettlementVerified).toBe(false);
    expect(report.nextCommands).toContain("npm run doctor -- --mode=canister");
    expect(report.nextCommands).toContain("npm run doctor -- --mode=buyer");
    expect(JSON.stringify(report)).not.toContain(privateKey);
  }, 10_000);

  it("can include canister HTTP smoke", async () => {
    const fetchFn: typeof fetch = async (input) => {
      const url = String(input);
      if (url === `${baseUrl}/health`) {
        return Response.json({ ok: true, network: "eip155:137", facilitatorAddress: seller });
      }
      if (url.endsWith("/supported")) {
        return Response.json({
          kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:137", extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" } }],
          extensions: [],
          signers: { "eip155:137": [seller] }
        });
      }
      return new Response("not found", { status: 404 });
    };
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_BASE_URL: baseUrl,
      X402_TARGET_URL: resourceUrl
    }, { fetchFn, includeCanisterSmoke: true });

    expect(report.stages.find((stage) => stage.name === "canister-http")?.status).toBe("ok");
    expect(report.nextCommands).not.toContain("npm run readiness:jpyc -- --with-canister-smoke");
  }, 10_000);

  it("can include canister env names smoke", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, { canisterEnvNamesOutput: envNamesOutput, includeCanisterEnvSmoke: true });

    expect(report.stages.find((stage) => stage.name === "canister-env")?.status).toBe("ok");
  });

  it("can include paid negative smoke", async () => {
    const calls = { value: 0 };
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_BASE_URL: baseUrl,
      X402_TARGET_URL: resourceUrl
    }, { fetchFn: paidNegativeFetch(calls), includePaidNegativeSmoke: true });

    expect(calls.value).toBe(2);
    expect(report.stages.find((stage) => stage.name === "paid-negative-http")?.status).toBe("ok");
  });

  it("can include wallet stage", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, { includeWallet: true, walletCheck: async () => undefined });

    expect(report.stages.find((stage) => stage.name === "wallet")?.status).toBe("ok");
  });

  it("can include settlement receipt verification after payment", async () => {
    const payer = privateKeyToAccount(privateKey).address;
    const receipt: TransactionReceipt = {
      blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      blockNumber: 123n,
      contractAddress: null,
      cumulativeGasUsed: 21000n,
      effectiveGasPrice: 1n,
      from: payer,
      gasUsed: 21000n,
      logs: [{
        address: jpyc,
        blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
        blockNumber: 123n,
        data: uint256(1000000000000000000n),
        logIndex: 0,
        removed: false,
        topics: [transferTopic, topicAddress(payer), topicAddress(seller)],
        transactionHash: hash,
        transactionIndex: 0
      }],
      logsBloom: "0x",
      status: "success",
      to: jpyc,
      transactionHash: hash,
      transactionIndex: 0,
      type: "eip1559"
    };
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      JPYC_POLYGON_ADDRESS: jpyc,
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      SETTLEMENT_TX: hash,
      X402_TARGET_URL: resourceUrl
    }, {
      includeSettlementReceipt: true,
      receiptReader: { async getTransactionReceipt() { return receipt; } }
    });

    expect(report.realSettlementVerified).toBe(true);
    expect(report.stages.find((stage) => stage.name === "settlement-receipt")?.status).toBe("ok");
  });

  it("does not mark settlement verified without the buyer key", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      SETTLEMENT_TX: hash,
      X402_TARGET_URL: resourceUrl
    }, { includeSettlementReceipt: true });
    const receiptStage = report.stages.find((stage) => stage.name === "settlement-receipt");

    expect(report.realSettlementVerified).toBe(false);
    expect(receiptStage?.failures).toContain("settlement-receipt:missing required env: BUYER_EVM_PRIVATE_KEY");
    expect(report.nextCommands).toContain("npm run receipt:settlement");
    expect(shouldFailReadiness(report, true)).toBe(true);
  });
});
