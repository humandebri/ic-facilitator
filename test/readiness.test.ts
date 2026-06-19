// test/readiness.test.ts: canister-only readiness が不足条件だけを公開することを確認する。
import { describe, expect, it } from "vitest";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import type { Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildReadinessReport, buildReadinessReportWithSmoke, shouldFailReadiness } from "../scripts/readiness";
import type { BatchMainnetPreflightReader } from "../scripts/batch_mainnet_preflight";
import type { BatchSettlementReceiptReader } from "../scripts/batch_settlement_receipt";

const seller = "0x1000000000000000000000000000000000000402";
const privateKey: Hex = `0x${"1".repeat(64)}`;
const facilitatorAddress = privateKeyToAccount(privateKey).address;
const receiverAuthorizerPrivateKey: Hex = `0x${"2".repeat(64)}`;
const receiverAuthorizer = privateKeyToAccount(receiverAuthorizerPrivateKey).address;
const baseUrl = "https://canister.example.test";
const resourceUrl = `${baseUrl}/jpyc/report`;
const hash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000402";
const jpyc: Hex = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const transferTopic: Hex = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const facilitatorKeyEnv = ["FACILITATOR", "EVM", "PRIVATE", "KEY"].join("_");
const batchContract: Hex = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";
const contractCode: Hex = "0x60016000";
const batchPayer: Hex = "0x2000000000000000000000000000000000000402";
const batchChannelId: Hex = "0x95995132e1646c51d70cbebd071b3fa2340dd7d3677b7f85bc5fecf85f9e5f98";
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

const batchChannelConfigWords = [
  topicAddress(batchPayer),
  topicAddress(batchPayer),
  topicAddress(seller),
  topicAddress(receiverAuthorizer),
  topicAddress(jpyc),
  uint256(900n),
  `0x${"33".repeat(32)}` as Hex
].map((word) => word.slice(2)).join("");
const batchDepositInput: Hex = `0x140f1e75${batchChannelConfigWords}${uint256(100n).slice(2)}${topicAddress(batchPayer).slice(2)}${uint256(320n).slice(2)}${uint256(0n).slice(2)}` as Hex;

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

const batchPreflightReader: BatchMainnetPreflightReader = {
  async getBatchChannel() { return [0n, 0n]; },
  async getBatchPendingWithdrawal() { return [0n, 0]; },
  async getBatchReceiver() { return [0n, 0n]; },
  async getBatchRefundNonce() { return 0n; },
  async getBytecode() { return contractCode; },
  async getChainId() { return 137; },
  async getJpycAuthorizationState() { return false; },
  async getJpycDecimals() { return 18; },
  async getJpycName() { return "JPY Coin"; }
};

const batchSettlementReceiptReader: BatchSettlementReceiptReader = {
  async getBatchChannel() { return [100n, 50n]; },
  async getBatchReceiver() { return [50n, 20n]; },
  async getBatchRefundNonce() { return 1n; },
  async getBlockNumber() { return 125n; },
  async getTransaction() {
    return {
      from: facilitatorAddress,
      hash,
      input: batchDepositInput,
      to: batchContract
    };
  },
  async getTransactionReceipt() {
    return {
      blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      blockNumber: 123n,
      contractAddress: null,
      cumulativeGasUsed: 21000n,
      effectiveGasPrice: 1n,
      from: facilitatorAddress,
      gasUsed: 21000n,
      logs: [],
      logsBloom: "0x",
      status: "success",
      to: batchContract,
      transactionHash: hash,
      transactionIndex: 0,
      type: "eip1559"
    };
  }
};

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

  it("requires batch HTTP support when batch readiness stages are enabled", async () => {
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
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_FEE_AMOUNT: "100",
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_BASE_URL: baseUrl,
      X402_TARGET_URL: resourceUrl
    }, {
      batchPreflightReader,
      fetchFn,
      includeBatchMainnetPreflight: true,
      includeCanisterSmoke: true
    });

    const httpStage = report.stages.find((stage) => stage.name === "canister-http");
    expect(httpStage?.status).toBe("fail");
    expect(httpStage?.failures[0]).toContain("supported lacks x402 v2 batch-settlement/eip155:137");
    expect(report.nextCommands).toContain("npm run smoke:canister -- --with-batch");
    expect(report.nextCommands).not.toContain("npm run smoke:canister");
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

  it("requires batch canister env names when batch readiness stages are enabled", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_FEE_AMOUNT: "100",
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchPreflightReader,
      canisterEnvNamesOutput: envNamesOutput,
      includeBatchMainnetPreflight: true,
      includeCanisterEnvSmoke: true
    });

    const envStage = report.stages.find((stage) => stage.name === "canister-env");
    expect(envStage?.status).toBe("fail");
    expect(report.nextCommands).toContain("npm run smoke:canister:env -- --with-batch");
    expect(report.nextCommands).not.toContain("npm run smoke:canister:env");
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
      from: facilitatorAddress,
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
      receiptReader: {
        async getBlockNumber() { return 125n; },
        async getTransactionReceipt() { return receipt; }
      }
    });

    expect(report.realSettlementVerified).toBe(true);
    expect(report.stages.find((stage) => stage.name === "settlement-receipt")?.status).toBe("ok");
  });

  it("uses SETTLE_MIN_CONFIRMATIONS for settlement receipt readiness", async () => {
    const payer = privateKeyToAccount(privateKey).address;
    const receipt: TransactionReceipt = {
      blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      blockNumber: 123n,
      contractAddress: null,
      cumulativeGasUsed: 21000n,
      effectiveGasPrice: 1n,
      from: facilitatorAddress,
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
      SETTLE_MIN_CONFIRMATIONS: "4",
      SETTLEMENT_TX: hash,
      X402_TARGET_URL: resourceUrl
    }, {
      includeSettlementReceipt: true,
      receiptReader: {
        async getBlockNumber() { return 125n; },
        async getTransactionReceipt() { return receipt; }
      }
    });

    expect(report.realSettlementVerified).toBe(false);
    expect(report.stages.find((stage) => stage.name === "settlement-receipt")?.failures)
      .toContain("settlement-receipt:settlement tx confirmations below minimum: 3 < 4");
  });

  it("rejects settlement receipts from a non-facilitator sender", async () => {
    const payer = privateKeyToAccount(privateKey).address;
    const receipt: TransactionReceipt = {
      blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      blockNumber: 123n,
      contractAddress: null,
      cumulativeGasUsed: 21000n,
      effectiveGasPrice: 1n,
      from: seller,
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
      receiptReader: {
        async getBlockNumber() { return 125n; },
        async getTransactionReceipt() { return receipt; }
      }
    });

    expect(report.realSettlementVerified).toBe(false);
    expect(report.stages.find((stage) => stage.name === "settlement-receipt")?.failures)
      .toContain(`settlement-receipt:settlement tx sender mismatch: ${seller}`);
  });

  it("can include batch mainnet preflight", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_FEE_AMOUNT: "100",
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchPreflightReader,
      includeBatchMainnetPreflight: true
    });

    expect(report.stages.find((stage) => stage.name === "batch-mainnet-preflight")?.status).toBe("ok");
    expect(report.nextCommands).not.toContain("npm run preflight:batch");
  });

  it("returns concrete next commands for missing batch preflight env", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      includeBatchMainnetPreflight: true
    });

    expect(report.stages.find((stage) => stage.name === "batch-mainnet-preflight")?.status).toBe("fail");
    expect(report.nextCommands).toContain("set JPYC_EIP712_VERSION=1");
    expect(report.nextCommands).toContain(`set BATCH_SETTLEMENT_CONTRACT=${batchContract}`);
    expect(report.nextCommands).toContain("set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key");
    expect(report.nextCommands).toContain("set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer");
  });

  it("can include batch settlement receipt verification", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BATCH_CHANNEL_ID: batchChannelId,
      BATCH_DEPOSIT_AMOUNT: "100",
      BATCH_EXPECTED_MIN_BALANCE: "100",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BATCH_SETTLE_RECEIVER: seller,
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchSettlementReceiptReader,
      includeBatchSettlementReceipt: true
    });

    expect(report.stages.find((stage) => stage.name === "batch-settlement-receipt")?.status).toBe("ok");
    expect(report.nextCommands).not.toContain("npm run receipt:batch");
  });

  it("returns a concrete command when batch receipt receiver is missing", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BATCH_CHANNEL_ID: batchChannelId,
      BATCH_DEPOSIT_AMOUNT: "100",
      BATCH_EXPECTED_MIN_BALANCE: "100",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchSettlementReceiptReader,
      includeBatchSettlementReceipt: true
    });

    const stage = report.stages.find((stage) => stage.name === "batch-settlement-receipt");
    expect(stage?.status).toBe("fail");
    expect(stage?.failures).toContain("batch-settlement-receipt:missing required env: BATCH_SETTLE_RECEIVER");
    expect(report.nextCommands).toContain("set BATCH_SETTLE_RECEIVER to the expected batch receiver address");
    expect(report.nextCommands).toContain("npm run receipt:batch");
  });

  it("returns a concrete command when batch receipt amount is missing", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BATCH_CHANNEL_ID: batchChannelId,
      BATCH_EXPECTED_MIN_BALANCE: "100",
      BATCH_SETTLE_RECEIVER: seller,
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchSettlementReceiptReader,
      includeBatchSettlementReceipt: true
    });

    const stage = report.stages.find((stage) => stage.name === "batch-settlement-receipt");
    expect(stage?.status).toBe("fail");
    expect(stage?.failures).toContain("batch-settlement-receipt:missing required env: BATCH_DEPOSIT_AMOUNT");
    expect(report.nextCommands).toContain("set BATCH_DEPOSIT_AMOUNT to the deposited amount");
    expect(report.nextCommands).toContain("npm run receipt:batch");
  });

  it("returns concrete commands when batch receipt authorization evidence is missing", async () => {
    const missingAuthorizer = await buildReadinessReportWithSmoke(".", {
      BATCH_CHANNEL_ID: batchChannelId,
      BATCH_DEPOSIT_AMOUNT: "100",
      BATCH_EXPECTED_MIN_BALANCE: "100",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: seller,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchSettlementReceiptReader,
      includeBatchSettlementReceipt: true
    });

    expect(missingAuthorizer.stages.find((stage) => stage.name === "batch-settlement-receipt")?.failures)
      .toContain("batch-settlement-receipt:missing required env: BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
    expect(missingAuthorizer.nextCommands).toContain("set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key");

    const missingWithdrawDelay = await buildReadinessReportWithSmoke(".", {
      BATCH_CHANNEL_ID: batchChannelId,
      BATCH_DEPOSIT_AMOUNT: "100",
      BATCH_EXPECTED_MIN_BALANCE: "100",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: batchContract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_SETTLE_RECEIVER: seller,
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      X402_TARGET_URL: resourceUrl
    }, {
      batchSettlementReceiptReader,
      includeBatchSettlementReceipt: true
    });

    expect(missingWithdrawDelay.stages.find((stage) => stage.name === "batch-settlement-receipt")?.failures)
      .toContain("batch-settlement-receipt:missing required env: BATCH_WITHDRAW_DELAY_SECONDS");
    expect(missingWithdrawDelay.nextCommands).toContain("set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds");
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

  it("does not mark settlement verified without the facilitator key", async () => {
    const report = await buildReadinessReportWithSmoke(".", {
      BUYER_EVM_PRIVATE_KEY: privateKey,
      FACILITATOR_PUBLIC_ORIGIN: baseUrl,
      JPYC_EIP712_VERSION: "1",
      POLYGON_RPC_URL: "https://polygon.example",
      SELLER_EVM_ADDRESS: seller,
      SETTLEMENT_TX: hash,
      X402_TARGET_URL: resourceUrl
    }, { includeSettlementReceipt: true });
    const receiptStage = report.stages.find((stage) => stage.name === "settlement-receipt");

    expect(report.realSettlementVerified).toBe(false);
    expect(receiptStage?.failures).toContain("settlement-receipt:missing required env: FACILITATOR_EVM_PRIVATE_KEY");
    expect(report.nextCommands).toContain("npm run receipt:settlement");
    expect(shouldFailReadiness(report, true)).toBe(true);
  });
});
