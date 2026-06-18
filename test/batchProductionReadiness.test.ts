// test/batchProductionReadiness.test.ts: batch本番投入前レポートのready条件を確認する。
import { describe, expect, it } from "vitest";
import { encodeAbiParameters, encodeEventTopics, parseAbi } from "viem";
import type { Address, Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { buildBatchProductionReadinessReport } from "../scripts/batch_production_readiness";
import type { BatchMainnetPreflightReader } from "../scripts/batch_mainnet_preflight";
import type { BatchSettlementReceiptReader } from "../scripts/batch_settlement_receipt";

const hash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000b47";
const claimHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000c11";
const depositHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000d09";
const refundHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000f01";
const settleHash: Hex = "0x00000000000000000000000000000000000000000000000000000000000005e7";
const batchContract: Address = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";
const jpyc: Address = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const channelId: Hex = "0x95995132e1646c51d70cbebd071b3fa2340dd7d3677b7f85bc5fecf85f9e5f98";
const seller: Address = "0x1000000000000000000000000000000000000402";
const sender: Address = "0x2000000000000000000000000000000000000402";
const facilitatorPrivateKey: Hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
const facilitatorAddress = privateKeyToAccount(facilitatorPrivateKey).address;
const receiverAuthorizerPrivateKey: Hex = "0x2222222222222222222222222222222222222222222222222222222222222222";
const receiverAuthorizer: Address = "0x1563915e194D8CfBA1943570603F7606A3115508";
const writerPrincipal = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const controllerPrincipal = "r7inp-6aaaa-aaaaa-aaabq-cai";
const backupControllerPrincipal = "rrkah-fqaaa-aaaaa-aaaaq-cai";
const wasmBytes = Buffer.from("wasm");
const wasmSha256 = "336154bf67f765f8f75d16a0accee61b5ee5f6a75b2a2905703df913bd550f3e";
const canisterStatusOutput = canisterStatus(wasmSha256);
const didBytes = Buffer.from(`
type BatchChannel = record {
  channel_id : text;
  signature : text;
  channel_config : BatchChannelConfig;
  balance : text;
  charged_cumulative_amount : text;
  pending_request : opt BatchPendingRequest;
  refund_nonce : text;
  signed_max_claimable : text;
  revision : nat64;
  last_request_timestamp : nat64;
  onchain_synced_at : opt nat64;
  total_claimed : text;
  withdraw_requested_at : nat64;
};
type BatchChannelConfig = record {
  token : text;
  withdraw_delay : nat64;
  salt : text;
  receiver_authorizer : text;
  payer_authorizer : text;
  payer : text;
  receiver : text;
};
type BatchChannelUpdate = record { channel : opt BatchChannel };
type BatchChannelUpdateResult = record {
  status : text;
  current_revision : opt nat64;
  message : opt text;
  channel : opt BatchChannel;
};
type BatchDeletedChannel = record {
  deleted_at : nat64;
  deleted_by : text;
  channel : BatchChannel;
};
type BatchPendingRequest = record {
  signed_max_claimable : text;
  pending_id : text;
  expires_at : nat64;
};
service : {
  batch_channel : (text) -> (opt BatchChannel) query;
  batch_channel_count : () -> (nat64) query;
  batch_channel_storage_writer : () -> (opt principal) query;
  batch_channels : (opt nat64) -> (vec BatchChannel) query;
  batch_deleted_channel : (text) -> (opt BatchDeletedChannel) query;
  batch_deleted_channel_count : () -> (nat64) query;
  batch_deleted_channels : (opt nat64) -> (vec BatchDeletedChannel) query;
  batch_receiver_authorizer : () -> (opt text) query;
  batch_settlement_contract : () -> (opt text) query;
  batch_settlement_fee_amount : () -> (opt text) query;
  batch_update_channel : (text, opt nat64, BatchChannelUpdate) -> (BatchChannelUpdateResult);
}
`);
const baseUrl = "https://canister.example.test";
const batchEnvNamesOutput = `(
  vec { "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL"; "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"; "BATCH_SETTLEMENT_CONTRACT"; "BATCH_SETTLEMENT_FEE_AMOUNT"; "BATCH_WITHDRAW_DELAY_SECONDS"; },
)`;
const readinessChannelId = `0x${"00".repeat(32)}`;

const settledAbi = parseAbi([
  "event Settled(address indexed receiver,address indexed token,address indexed sender,uint128 amount)"
]);

function canisterStatus(moduleHash: string, options: {
  readonly controllers?: readonly string[];
  readonly cycles?: string;
  readonly freezingThreshold?: string;
} = {}): string {
  return JSON.stringify({
    module_hash: `0x${moduleHash}`,
    cycles: options.cycles ?? "2000000000000",
    settings: {
      controllers: options.controllers ?? [controllerPrincipal, backupControllerPrincipal],
      freezing_threshold: options.freezingThreshold ?? "7776000"
    }
  });
}

function isHex(value: string): value is Hex {
  return /^0x[0-9a-fA-F]*$/.test(value);
}

function hex(value: string): Hex {
  if (!isHex(value)) {
    throw new Error("invalid test hex");
  }
  return value;
}

function uint256(value: bigint): Hex {
  return hex(`0x${value.toString(16).padStart(64, "0")}`);
}

function addressWord(address: Address): Hex {
  return hex(`0x${"0".repeat(24)}${address.slice(2)}`);
}

function padHexData(value: Hex): string {
  const raw = value.slice(2);
  return raw.padEnd(Math.ceil(raw.length / 64) * 64, "0");
}

function encodeBytes(value: Hex): string {
  return `${uint256(BigInt((value.length - 2) / 2)).slice(2)}${padHexData(value)}`;
}

function encodeDynamicArray(items: readonly string[]): string {
  let offset = 32n * BigInt(items.length);
  let head = uint256(BigInt(items.length)).slice(2);
  let tail = "";
  for (const item of items) {
    head += uint256(offset).slice(2);
    offset += BigInt(item.length / 2);
    tail += item;
  }
  return `${head}${tail}`;
}

function claimTuple(configWords: string, totalClaimed: bigint): string {
  const signature = hex(`0x${"11".repeat(65)}`);
  return [
    configWords,
    uint256(100n).slice(2),
    uint256(320n).slice(2),
    uint256(totalClaimed).slice(2),
    encodeBytes(signature)
  ].join("");
}

function claimInputFor(claims: readonly { readonly configWords: string; readonly totalClaimed: bigint }[]): Hex {
  const claimsData = encodeDynamicArray(claims.map((claim) => claimTuple(claim.configWords, claim.totalClaimed)));
  const authorizerSignature = hex(`0x${"22".repeat(65)}`);
  return hex(`0xe43ce1f2${uint256(64n).slice(2)}${uint256(BigInt(64 + claimsData.length / 2)).slice(2)}${claimsData}${encodeBytes(authorizerSignature)}`);
}

function refundInputFor(configWords: string, nonce: bigint): Hex {
  const authorizerSignature = hex(`0x${"44".repeat(65)}`);
  return hex(`0xb77433e9${configWords}${uint256(1500n).slice(2)}${uint256(nonce).slice(2)}${uint256(320n).slice(2)}${encodeBytes(authorizerSignature)}`);
}

function depositInputFor(configWords: string, amount = 100n): Hex {
  return hex(`0x140f1e75${configWords}${uint256(amount).slice(2)}${addressWord(sender).slice(2)}${uint256(320n).slice(2)}${encodeBytes("0x")}`);
}

const channelConfigWords = [
  addressWord(sender),
  addressWord(sender),
  addressWord(seller),
  addressWord(receiverAuthorizer),
  addressWord(jpyc),
  uint256(900n),
  hex(`0x${"33".repeat(32)}`)
].map((word) => word.slice(2)).join("");
const claimInput: Hex = claimInputFor([{ configWords: channelConfigWords, totalClaimed: 50n }]);
const depositInput: Hex = depositInputFor(channelConfigWords);
const refundInput: Hex = refundInputFor(channelConfigWords, 0n);
const settleInput: Hex = hex(`0x9db32a8f${addressWord(seller).slice(2)}${addressWord(jpyc).slice(2)}`);

const preflightReader: BatchMainnetPreflightReader = {
  async getBatchChannel() { return [0n, 0n]; },
  async getBatchPendingWithdrawal() { return [0n, 0]; },
  async getBatchReceiver() { return [0n, 0n]; },
  async getBatchRefundNonce() { return 0n; },
  async getBytecode() { return "0x60016000"; },
  async getChainId() { return 137; },
  async getJpycAuthorizationState() { return false; },
  async getJpycDecimals() { return 18; },
  async getJpycName() { return "JPY Coin"; }
};

const receiptReader: BatchSettlementReceiptReader = {
  async getBatchChannel() { return [100n, 50n]; },
  async getBatchReceiver() { return [50n, 20n]; },
  async getBatchRefundNonce() { return 1n; },
  async getBlockNumber() { return 12n; },
  async getTransaction(args: { readonly hash: Hex }) {
    const inputs = new Map<Hex, Hex>([
      [claimHash, claimInput],
      [depositHash, depositInput],
      [refundHash, refundInput],
      [settleHash, settleInput]
    ]);
    return {
      from: facilitatorAddress,
      hash: args.hash,
      input: inputs.get(args.hash) ?? depositInput,
      to: batchContract
    };
  },
  async getTransactionReceipt(args: { readonly hash: Hex }): Promise<TransactionReceipt> {
    return {
      blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
      blockNumber: 10n,
      contractAddress: null,
      cumulativeGasUsed: 21000n,
      effectiveGasPrice: 1n,
      from: facilitatorAddress,
      gasUsed: 21000n,
      logs: [settledLog(20n, args.hash)],
      logsBloom: "0x",
      status: "success",
      to: batchContract,
      transactionHash: args.hash,
      transactionIndex: 0,
      type: "eip1559"
    };
  }
};

function env(): NodeJS.ProcessEnv {
  return {
    BATCH_CLAIM_CHANNEL_ID: channelId,
    BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED: "50",
    BATCH_CLAIM_TX: claimHash,
    BATCH_DEPOSIT_AMOUNT: "100",
    BATCH_DEPOSIT_CHANNEL_ID: channelId,
    BATCH_DEPOSIT_EXPECTED_MIN_BALANCE: "100",
    BATCH_DEPOSIT_TX: depositHash,
    BATCH_REFUND_CHANNEL_ID: channelId,
    BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE: "1",
    BATCH_REFUND_TX: refundHash,
    BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: writerPrincipal,
    BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
    BATCH_SETTLEMENT_CONTRACT: batchContract,
    BATCH_SETTLEMENT_FEE_AMOUNT: "100",
    BATCH_SETTLE_AMOUNT: "20",
    BATCH_SETTLE_RECEIVER: seller,
    BATCH_SETTLE_TOKEN: jpyc,
    BATCH_SETTLE_TX: settleHash,
    BATCH_WITHDRAW_DELAY_SECONDS: "900",
    FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey,
    X402_BASE_URL: baseUrl,
    JPYC_EIP712_VERSION: "1",
    POLYGON_RPC_URL: "https://polygon.example"
  };
}

function supportedResponse(includeBatch = true, signerAddress: Address = facilitatorAddress): unknown {
  const kinds: unknown[] = [{
    x402Version: 2,
    scheme: "exact",
    network: "eip155:137",
    extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
  }];
  if (includeBatch) {
    kinds.push({
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
    });
  }
  return {
    extensions: [],
    kinds,
    signers: includeBatch ? { "eip155:*": [signerAddress], "eip155:137": [signerAddress] } : { "eip155:137": [signerAddress] }
  };
}

function fetchForBatchSupported(includeBatch = true, healthAddress: Address = facilitatorAddress): typeof fetch {
  return async (input, init) => {
    if (String(input) === `${baseUrl}/health`) {
      return Response.json({ facilitatorAddress: healthAddress, network: "eip155:137", ok: true });
    }
    if (String(input) === `${baseUrl}/supported`) {
      return Response.json(supportedResponse(includeBatch, healthAddress));
    }
    if (String(input) === `${baseUrl}/verify` && init?.method === "POST") {
      return Response.json({ isValid: false, invalidReason: "unsupported_verify_scheme" }, { status: 400 });
    }
    return new Response("not found", { status: 404 });
  };
}

function settledLog(amount: bigint, transactionHash: Hex = hash): TransactionReceipt["logs"][number] {
  const topics = encodeEventTopics({
    abi: settledAbi,
    eventName: "Settled",
    args: { receiver: seller, sender: facilitatorAddress, token: jpyc }
  });
  const topic0 = topics[0];
  const topic1 = topics[1];
  const topic2 = topics[2];
  const topic3 = topics[3];
  if (!topic0 || !topic1 || !topic2 || !topic3 || Array.isArray(topic1) || Array.isArray(topic2) || Array.isArray(topic3)) {
    throw new Error("invalid Settled event topics");
  }
  const logTopics: [Hex, Hex, Hex, Hex] = [topic0, topic1, topic2, topic3];
  return {
    address: batchContract,
    blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
    blockNumber: 10n,
    data: encodeAbiParameters([{ type: "uint128" }], [amount]),
    logIndex: 0,
    removed: false,
    topics: logTopics,
    transactionHash,
    transactionIndex: 0
  };
}

function fileReader(options: { readonly did?: boolean; readonly didBytes?: Buffer; readonly wasm?: boolean } = {}) {
  return {
    exists(path: string) {
      if (path.endsWith(".wasm")) { return options.wasm ?? true; }
      if (path.endsWith(".did")) { return options.did ?? true; }
      return false;
    },
    read(path: string) {
      if (path.endsWith(".did")) {
        return options.didBytes ?? didBytes;
      }
      return wasmBytes;
    }
  };
}

function passingCommandRunner(command: string, args: readonly string[], _cwd = "") {
  if (command === "icp") {
    if (args.includes("status")) {
      return { output: canisterStatusOutput, status: 0 };
    }
    const batchQuery = batchStorageQueryOutput(args);
    if (batchQuery !== undefined) {
      return batchQuery;
    }
    return { output: batchEnvNamesOutput, status: 0 };
  }
  if (command === "candid-extractor") {
    return { output: didBytes.toString("utf8"), status: 0 };
  }
  return { output: "", status: 0 };
}

function batchStorageQueryOutput(args: readonly string[]): { readonly output: string; readonly status: number } | undefined {
  if (args.includes("batch_channel_storage_writer")) {
    return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
  }
  if (args.includes("batch_receiver_authorizer")) {
    return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
  }
  if (args.includes("batch_settlement_contract")) {
    return { output: `(opt "${batchContract}")`, status: 0 };
  }
  if (args.includes("batch_settlement_fee_amount")) {
    return { output: `(opt "100")`, status: 0 };
  }
  if (args.includes("batch_channel_count")) {
    return { output: "(0 : nat64)", status: 0 };
  }
  if (args.includes("batch_deleted_channel_count")) {
    return { output: "(0 : nat64)", status: 0 };
  }
  if (args.includes("batch_channel")) {
    if (!args.includes(`("${readinessChannelId}")`)) {
      return { output: "invalid readiness channel id", status: 1 };
    }
    return { output: "(null)", status: 0 };
  }
  if (args.includes("batch_deleted_channel")) {
    if (!args.includes(`("${readinessChannelId}")`)) {
      return { output: "invalid readiness deleted channel id", status: 1 };
    }
    return { output: "(null)", status: 0 };
  }
  if (args.includes("batch_channels")) {
    return { output: "(vec {})", status: 0 };
  }
  if (args.includes("batch_deleted_channels")) {
    return { output: "(vec {})", status: 0 };
  }
  if (args.includes("batch_update_channel")) {
    if (!args.includes('("0x00", null, record { channel = null })')) {
      return { output: "invalid batch_update_channel probe", status: 1 };
    }
    return {
      output: '(record { status = "invalid"; channel = null; current_revision = null; message = opt "channelId: hex must be 32 bytes" })',
      status: 0
    };
  }
  return undefined;
}

function batchChannelRecord(id = channelId): string {
  return `record {
    channel_id = "${id}";
    channel_config = record {
      payer = "${sender}";
      payer_authorizer = "${sender}";
      receiver = "${seller}";
      receiver_authorizer = "${receiverAuthorizer}";
      token = "${jpyc}";
      withdraw_delay = 900 : nat64;
      salt = "0x${"11".repeat(32)}";
    };
    charged_cumulative_amount = "10";
    signed_max_claimable = "10";
    signature = "0x${"11".repeat(65)}";
    balance = "20";
    total_claimed = "0";
    withdraw_requested_at = 0 : nat64;
    refund_nonce = "0";
    onchain_synced_at = null;
    last_request_timestamp = 1 : nat64;
    pending_request = null;
    revision = 1 : nat64;
  }`;
}

function batchDeletedChannelRecord(id = channelId): string {
  return `record {
    deleted_at = 1 : nat64;
    deleted_by = "${writerPrincipal}";
    channel = ${batchChannelRecord(id)};
  }`;
}

describe("batch production readiness", () => {
  it("reports ready when preflight, all receipts, wasm, and DID checks pass", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(true);
    expect(report.wasmSha256).toBe(wasmSha256);
    expect(report.stages.map((stage) => stage.name)).toEqual(expect.arrayContaining([
      "batch:storage-writer",
      "batch:settlement-fee",
      "batch:key-separation",
      "canister:batch-storage-writer",
      "canister:batch-receiver-authorizer",
      "canister:batch-settlement-contract",
      "canister:batch-settlement-fee",
      "canister:wasm-hash",
      "canister:operational-safety",
      "did:batch-storage-api",
      "did:generated",
      "batch:receipt-confirmations",
      "batch:receipt:deposit",
      "batch:receipt:claim",
      "batch:receipt:settle",
      "batch:receipt:refund"
    ]));
    expect(report.stages.find((stage) => stage.name === "batch:receipt:deposit")?.detail).toContain(`deposit tx=${depositHash}`);
    expect(report.stages.find((stage) => stage.name === "batch:receipt:deposit")?.detail).toContain(`channel=${channelId}`);
    expect(report.stages.find((stage) => stage.name === "batch:receipt:settle")?.detail).toContain(`settle tx=${settleHash}`);
    expect(report.stages.find((stage) => stage.name === "batch:receipt:settle")?.detail).toContain(`receiver=${seller}`);
    expect(report.stages.find((stage) => stage.name === "batch:receipt:settle")?.detail).toContain(`token=${jpyc}`);
    expect(report.nextCommands).toEqual([]);
  });

  it("can run as preflight-only before a batch tx exists", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_DEPOSIT_TX: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(true);
    expect(report.stages.some((stage) => stage.name.startsWith("batch:receipt"))).toBe(false);
    expect(report.stages.some((stage) => stage.name === "batch:storage-writer")).toBe(true);
    expect(report.stages.some((stage) => stage.name === "batch:settlement-fee")).toBe(true);
  });

  it("uses the preflight-only verify command in next commands when receipts are not required", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatus("f".repeat(64)), status: 0 };
        }
        if (command === "icp") {
          return { output: "selected environment failure", status: 1 };
        }
        return passingCommandRunner(command, args);
      },
      env: { ...env(), ICP_CANISTER: "batch-edge", ICP_ENVIRONMENT: "staging" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=staging ICP_CANISTER=batch-edge npm run verify:batch:preflight");
    expect(report.nextCommands).not.toContain("ICP_ENVIRONMENT=staging ICP_CANISTER=batch-edge npm run verify:batch");
  });

  it("fails when the batch storage writer principal is missing, invalid, or system-owned", async () => {
    const missing = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(missing.ready).toBe(false);
    expect(missing.stages).toContainEqual({
      detail: "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL is required",
      name: "batch:storage-writer",
      status: "fail"
    });

    const invalid = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-caj" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(invalid.ready).toBe(false);
    expect(invalid.stages).toContainEqual({
      detail: "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be an IC principal",
      name: "batch:storage-writer",
      status: "fail"
    });

    const anonymous = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "2vxsx-fae" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(anonymous.ready).toBe(false);
    expect(anonymous.stages).toContainEqual({
      detail: "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must be a non-system IC principal",
      name: "batch:storage-writer",
      status: "fail"
    });
  });

  it("fails when batch receiver authorizer and facilitator keys derive the same address", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: {
        ...env(),
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: facilitatorPrivateKey
      },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address",
      name: "batch:key-separation",
      status: "fail"
    });
    expect(report.nextCommands).toContain("use different private keys for FACILITATOR_EVM_PRIVATE_KEY and BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  });

  it("fails when the batch settlement fee amount is missing or invalid", async () => {
    const missing = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_SETTLEMENT_FEE_AMOUNT: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(missing.ready).toBe(false);
    expect(missing.stages).toContainEqual({
      detail: "BATCH_SETTLEMENT_FEE_AMOUNT is required",
      name: "batch:settlement-fee",
      status: "fail"
    });

    const invalid = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_SETTLEMENT_FEE_AMOUNT: "0" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(invalid.ready).toBe(false);
    expect(invalid.stages).toContainEqual({
      detail: "BATCH_SETTLEMENT_FEE_AMOUNT must be a positive integer string",
      name: "batch:settlement-fee",
      status: "fail"
    });
    expect(invalid.nextCommands).toContain("set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer");

    const overflow = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_SETTLEMENT_FEE_AMOUNT: "340282366920938463463374607431768211456" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    expect(overflow.ready).toBe(false);
    expect(overflow.stages).toContainEqual({
      detail: "BATCH_SETTLEMENT_FEE_AMOUNT must fit uint128",
      name: "batch:settlement-fee",
      status: "fail"
    });
  });

  it("returns concrete next commands for missing proof", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: { ...preflightReader, async getChainId() { return 80002; } },
      commandRunner(command, args) {
        if (command === "icp") {
          if (args.includes("status")) {
            return { output: canisterStatusOutput, status: 0 };
          }
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "git" && args[0] === "ls-files") {
          return { output: "not tracked", status: 1 };
        }
        return { output: "dirty did", status: 1 };
      },
      env: { ...env(), BATCH_DEPOSIT_TX: "" },
      fileReader: fileReader({ did: false, wasm: false }),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.nextCommands).toContain("npm run preflight:batch");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
    expect(report.nextCommands).toContain("npm run build");
    expect(report.nextCommands).toContain("npm run did:check");
  });

  it("returns a concrete next command when batch receipt receiver is missing", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_SETTLE_RECEIVER: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => (
      stage.name.startsWith("batch:receipt:") &&
      stage.detail === "missing required env: BATCH_SETTLE_RECEIVER"
    ))).toBe(true);
    expect(report.nextCommands).toContain("set BATCH_SETTLE_RECEIVER to the expected batch receiver address");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
  });

  it("returns a concrete next command when batch settle token is missing", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_SETTLE_TOKEN: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => (
      stage.name === "batch:receipt:settle" &&
      stage.detail === "missing required env: BATCH_SETTLE_TOKEN"
    ))).toBe(true);
    expect(report.nextCommands).toContain("set BATCH_SETTLE_TOKEN to the expected batch token address");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
  });

  it("returns a concrete next command when a batch receipt amount is missing", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_DEPOSIT_AMOUNT: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => (
      stage.name === "batch:receipt:deposit" &&
      stage.detail === "missing required env: BATCH_DEPOSIT_AMOUNT"
    ))).toBe(true);
    expect(report.nextCommands).toContain("set BATCH_DEPOSIT_AMOUNT to the deposited amount");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
  });

  it("returns a concrete next command when production receipt RPC URL is missing", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), POLYGON_RPC_URL: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => (
      stage.name.startsWith("batch:receipt:") &&
      stage.detail === "missing required env: POLYGON_RPC_URL"
    ))).toBe(true);
    expect(report.nextCommands).toContain("set POLYGON_RPC_URL to a Polygon HTTPS RPC URL");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
  });

  it("returns a concrete next command when production receipt RPC URL is invalid", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), POLYGON_RPC_URL: "http://polygon.example" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => (
      stage.name.startsWith("batch:receipt:") &&
      stage.detail === "POLYGON_RPC_URL must be a HTTPS RPC URL without userinfo or fragment"
    ))).toBe(true);
    expect(report.nextCommands).toContain("set POLYGON_RPC_URL to a Polygon HTTPS RPC URL");
    expect(report.nextCommands).toContain("npm run receipt:batch:all");
  });

  it("returns concrete next commands for missing batch preflight env", async () => {
    const report = await buildBatchProductionReadinessReport({
      commandRunner: passingCommandRunner,
      env: {
        ...env(),
        BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "",
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "",
        BATCH_SETTLEMENT_CONTRACT: "",
        BATCH_SETTLEMENT_FEE_AMOUNT: "",
        BATCH_WITHDRAW_DELAY_SECONDS: "",
        JPYC_EIP712_VERSION: ""
      },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.nextCommands).toContain("set JPYC_EIP712_VERSION=1");
    expect(report.nextCommands).toContain(`set BATCH_SETTLEMENT_CONTRACT=${batchContract}`);
    expect(report.nextCommands).toContain("set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key");
    expect(report.nextCommands).toContain("set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer");
    expect(report.nextCommands).toContain("set BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL to the resource server actor principal");
    expect(report.nextCommands).toContain("set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds");
  });

  it("rejects zero confirmations for production batch receipt readiness", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), SETTLE_MIN_CONFIRMATIONS: "0" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "SETTLE_MIN_CONFIRMATIONS must be a positive integer for production batch receipts",
      name: "batch:receipt-confirmations",
      status: "fail"
    });
    expect(report.nextCommands).toContain("set SETTLE_MIN_CONFIRMATIONS to 3 or higher for production batch receipt verification");
    expect(report.nextCommands).not.toContain("npm run receipt:batch:all");
  });

  it("rejects under-three confirmations for production batch receipt readiness", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      batchSettlementReceiptReader: receiptReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), SETTLE_MIN_CONFIRMATIONS: "2" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported()
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "SETTLE_MIN_CONFIRMATIONS must be 3 or higher for production batch receipts",
      name: "batch:receipt-confirmations",
      status: "fail"
    });
    expect(report.nextCommands).toContain("set SETTLE_MIN_CONFIRMATIONS to 3 or higher for production batch receipt verification");
    expect(report.nextCommands).not.toContain("npm run receipt:batch:all");
  });

  it("fails when JPYC env points away from the fixed canister token", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: {
        ...env(),
        JPYC_POLYGON_ADDRESS: "0x0000000000000000000000000000000000000002"
      },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages.some((stage) => stage.name === "batch:preflight:env:JPYC_POLYGON_ADDRESS")).toBe(true);
  });

  it("fails when deployed canister lacks batch env names", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp") {
          if (args.includes("status")) {
            return { output: canisterStatusOutput, status: 0 };
          }
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: `(vec { "BATCH_SETTLEMENT_CONTRACT"; })`, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "missing canister batch env names: BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL, BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY, BATCH_SETTLEMENT_FEE_AMOUNT, BATCH_WITHDRAW_DELAY_SECONDS",
      name: "canister:batch-env",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic ICP_CANISTER=edge npm run smoke:canister:env -- --with-batch");
    expect(report.nextCommands.filter((command) => command === "ICP_ENVIRONMENT=ic npm run ic:env:mainnet")).toHaveLength(1);
  });

  it("fails when deployed canister env_names output contains extra text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: `warning "BATCH_SETTLEMENT_CONTRACT" ${batchEnvNamesOutput}`, status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "unexpected env_names output",
      name: "canister:batch-env",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
  });

  it("fails when deployed batch_channel output contains extra text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: `(opt record { channel_id = "${readinessChannelId}" }) trailing`, status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `unexpected batch_channel output: (opt record { channel_id = "${readinessChannelId}" }) trailing`,
      name: "canister:batch-storage-api",
      status: "fail"
    });
  });

  it("fails when deployed batch_channels output is non-empty while count is zero", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec { garbage })", status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "unexpected batch_channels output: (vec { garbage })",
      name: "canister:batch-storage-api",
      status: "fail"
    });
  });

  it("fails when deployed batch_deleted_channel_count output contains extra text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_deleted_channel_count")) {
          return { output: 'warning "stale" (0 : nat64)', status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: 'unexpected batch_deleted_channel_count output: warning "stale" (0 : nat64)',
      name: "canister:batch-storage-api",
      status: "fail"
    });
  });

  it("fails when deployed batch_deleted_channels output is non-empty while count is zero", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_deleted_channels")) {
          return { output: `(vec { ${batchDeletedChannelRecord()} })`, status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "batch_deleted_channel_count is 0 but batch_deleted_channels returned non-empty output",
      name: "canister:batch-storage-api",
      status: "fail"
    });
  });

  it("accepts non-empty deployed batch_deleted_channels output when count matches", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_deleted_channel_count")) {
          return { output: "(1 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_deleted_channels")) {
          return { output: `(vec { ${batchDeletedChannelRecord()} })`, status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.stages.find((stage) => stage.name === "canister:batch-storage-api")).toEqual({
      detail: "edge@ic batch channel storage APIs ok count=0 deleted=1",
      name: "canister:batch-storage-api",
      status: "ok"
    });
  });

  it("requires an explicit public base URL for mainnet batch smoke", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), X402_BASE_URL: "" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "X402_BASE_URL is required for mainnet batch readiness",
      name: "canister:batch-supported",
      status: "fail"
    });
    expect(report.nextCommands).toContain("set X402_BASE_URL to the deployed canister HTTPS origin");
  });

  it("fails when deployed canister facilitator address differs from local env", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(true, seller),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `health.facilitatorAddress mismatch: expected ${facilitatorAddress.toLowerCase()}, got ${seller.toLowerCase()}`,
      name: "canister:batch-supported",
      status: "fail"
    });
  });

  it("rejects non-HTTPS mainnet batch smoke origins before fetch", async () => {
    for (const value of [
      "http://edge.local.localhost:8000",
      " https://canister.example.test",
      "https://canister.example.test "
    ]) {
      const report = await buildBatchProductionReadinessReport({
        batchPreflightReader: preflightReader,
        commandRunner: passingCommandRunner,
        env: { ...env(), X402_BASE_URL: value },
        fileReader: fileReader(),
        fetchFn: fetchForBatchSupported(),
        requireBatchReceipt: false
      });

      expect(report.ready).toBe(false);
      expect(report.stages).toContainEqual({
        detail: "X402_BASE_URL must be a https://host[:port] origin for mainnet batch readiness",
        name: "canister:batch-supported",
        status: "fail"
      });
      expect(report.nextCommands).toContain("set X402_BASE_URL to a https://host[:port] origin");
    }
  });

  it("fails when deployed canister storage writer differs from local env", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "rrkah-fqaaa-aaaaa-aaaaq-cai")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `expected ${writerPrincipal}, got rrkah-fqaaa-aaaaa-aaaaq-cai`,
      name: "canister:batch-storage-writer",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
  });

  it("fails when deployed canister batch settlement fee differs from local env", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "101")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "expected 100, got 101",
      name: "canister:batch-settlement-fee",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
  });

  it("fails when deployed canister batch settlement contract differs from local env", async () => {
    const otherContract = "0x0000000000000000000000000000000000000402";
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${otherContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `expected ${batchContract.toLowerCase()}, got ${otherContract}`,
      name: "canister:batch-settlement-contract",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
  });

  it("fails when local batch settlement contract is not the official x402 contract", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: {
        ...env(),
        BATCH_SETTLEMENT_CONTRACT: "0x0000000000000000000000000000000000000001"
      },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${batchContract}`,
      name: "canister:batch-settlement-contract",
      status: "fail"
    });
  });

  it("fails when deployed canister receiver authorizer differs from local env", async () => {
    const otherAuthorizer = "0x0000000000000000000000000000000000000402";
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${otherAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `expected ${receiverAuthorizer.toLowerCase()}, got ${otherAuthorizer}`,
      name: "canister:batch-receiver-authorizer",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
  });

  it("rejects malformed quoted canister query output instead of parsing the first string", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `warning "stale" (opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "batch receiver authorizer is not configured on canister",
      name: "canister:batch-receiver-authorizer",
      status: "fail"
    });
  });

  it("fails when deployed canister wasm hash differs from local build", async () => {
    const remoteHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatus(remoteHash), status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `expected ${wasmSha256}, got ${remoteHash}`,
      name: "canister:wasm-hash",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:deploy:mainnet");
  });

  it("fails when deployed canister lacks production controller and cycles safety", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: canisterStatus(wasmSha256, {
              controllers: [writerPrincipal],
              cycles: "999999999999",
              freezingThreshold: "2592000"
            }),
            status: 0
          };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "canister must have at least two non-system controllers",
      name: "canister:operational-safety",
      status: "fail"
    });
    expect(report.nextCommands).toContain("icp canister settings update edge --add-controller <backup-principal> -e ic");
  });

  it("uses the selected canister and environment in operational safety next commands", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: canisterStatus(wasmSha256, {
              controllers: [writerPrincipal],
              cycles: "2000000000000",
              freezingThreshold: "2592000"
            }),
            status: 0
          };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: { ...env(), ICP_CANISTER: "batch-edge", ICP_ENVIRONMENT: "staging" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.nextCommands).toContain("icp canister settings update batch-edge --freezing-threshold 7776000 -e staging");
    expect(report.nextCommands).toContain("icp canister settings update batch-edge --add-controller <backup-principal> -e staging");
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=staging ICP_CANISTER=batch-edge npm run verify:batch:preflight");
  });

  it("fails when the batch storage writer is also a canister controller", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: canisterStatus(wasmSha256, {
              controllers: [writerPrincipal, backupControllerPrincipal],
              cycles: "2000000000000",
              freezingThreshold: "7776000"
            }),
            status: 0
          };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL must not be a canister controller",
      name: "canister:operational-safety",
      status: "fail"
    });
    expect(report.nextCommands).toContain("set BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL to a non-controller resource server actor principal");
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
    expect(report.nextCommands).toContain(`icp canister settings update edge --remove-controller ${writerPrincipal} -e ic`);
    expect(report.nextCommands).toContain("icp canister settings update edge --add-controller <backup-principal> -e ic");
    expect(report.nextCommands.indexOf("icp canister settings update edge --add-controller <backup-principal> -e ic"))
      .toBeLessThan(report.nextCommands.indexOf(`icp canister settings update edge --remove-controller ${writerPrincipal} -e ic`));
  });

  it("uses the selected canister and environment in canister env and deploy next commands", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatus("f".repeat(64)), status: 0 };
        }
        if (command === "icp") {
          return { output: "selected environment failure", status: 1 };
        }
        return { output: "", status: 0 };
      },
      env: { ...env(), ICP_CANISTER: "batch-edge", ICP_ENVIRONMENT: "staging" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.nextCommands).toContain("scripts/set_canister_env.sh staging batch-edge");
    expect(report.nextCommands).toContain("icp deploy -e staging batch-edge --yes");
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=staging ICP_CANISTER=batch-edge npm run verify:batch:preflight");
    expect(report.nextCommands).not.toContain("ICP_ENVIRONMENT=ic npm run ic:env:mainnet");
    expect(report.nextCommands).not.toContain("ICP_ENVIRONMENT=ic npm run ic:deploy:mainnet");
  });

  it("fails when operational safety cycles or configured cycle floor are invalid", async () => {
    const lowCycles = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: canisterStatus(wasmSha256, { cycles: "999999999999" }),
            status: 0
          };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
          return { output: batchEnvNamesOutput, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(lowCycles.ready).toBe(false);
    expect(lowCycles.stages).toContainEqual({
      detail: "cycles below 1000000000000",
      name: "canister:operational-safety",
      status: "fail"
    });

    const invalidFloor = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_MIN_CANISTER_CYCLES: "0" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(invalidFloor.ready).toBe(false);
    expect(invalidFloor.stages).toContainEqual({
      detail: "BATCH_MIN_CANISTER_CYCLES must be a positive integer string",
      name: "canister:operational-safety",
      status: "fail"
    });
  });

  it("does not trust unrelated canister status JSON fields for operational safety", async () => {
    const unrelatedControllers = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: JSON.stringify({
              module_hash: `0x${wasmSha256}`,
              cycles: "2000000000000",
              controller_hint: [writerPrincipal, backupControllerPrincipal],
              settings: {
                controllers: [writerPrincipal],
                freezing_threshold: "7776000"
              }
            }),
            status: 0
          };
        }
        return passingCommandRunner(command, args);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(unrelatedControllers.ready).toBe(false);
    expect(unrelatedControllers.stages).toContainEqual({
      detail: "canister must have at least two non-system controllers",
      name: "canister:operational-safety",
      status: "fail"
    });

    const unrelatedFreezingThreshold = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: JSON.stringify({
              module_hash: `0x${wasmSha256}`,
              cycles: "2000000000000",
              stale_settings: {
                freezing_threshold: "7776000"
              },
              settings: {
                controllers: [controllerPrincipal, backupControllerPrincipal]
              }
            }),
            status: 0
          };
        }
        return passingCommandRunner(command, args);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(unrelatedFreezingThreshold.ready).toBe(false);
    expect(unrelatedFreezingThreshold.stages).toContainEqual({
      detail: "canister status did not include freezing threshold",
      name: "canister:operational-safety",
      status: "fail"
    });

    const unrelatedCycles = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("status")) {
          return {
            output: JSON.stringify({
              module_hash: `0x${wasmSha256}`,
              metrics: {
                cycles: "2000000000000"
              },
              settings: {
                controllers: [controllerPrincipal, backupControllerPrincipal],
                freezing_threshold: "7776000"
              }
            }),
            status: 0
          };
        }
        return passingCommandRunner(command, args);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(unrelatedCycles.ready).toBe(false);
    expect(unrelatedCycles.stages).toContainEqual({
      detail: "canister status did not include cycles balance",
      name: "canister:operational-safety",
      status: "fail"
    });
  });

  it("fails when deployed canister lacks batch storage query API", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp") {
          return { output: "method not found: batch_channel_count", status: 1 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "method not found: batch_channel_count",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel count output contains extra text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: 'warning "stale" (0 : nat64)', status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: 'unexpected batch_channel_count output: warning "stale" (0 : nat64)',
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel list query is not available", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp") {
          return { output: "method not found: batch_channels", status: 1 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "method not found: batch_channels",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel update API is not available", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec {})", status: 0 };
        }
        if (command === "icp" && args.includes("batch_update_channel")) {
          return { output: "method not found: batch_update_channel", status: 1 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "method not found: batch_update_channel",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when batch channel update probe is rejected by storage access control", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_update_channel")) {
          return { output: "caller is not authorized to update batch channel storage", status: 1 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "caller is not authorized to update batch channel storage",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when batch channel update probe is rejected for anonymous caller", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_update_channel")) {
          return { output: "anonymous caller is not authorized to update batch channel storage", status: 1 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "anonymous caller is not authorized to update batch channel storage",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when batch channel update probe returns invalid status without result fields", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_update_channel")) {
          return { output: '(record { status = "invalid" })', status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: '(record { status = "invalid" })',
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when batch channel update probe returns an unrelated invalid result", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "icp" && args.includes("batch_update_channel")) {
          return {
            output: '(record { status = "invalid"; channel = null; current_revision = null; message = opt "unrelated validation failure" })',
            status: 0
          };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: '(record { status = "invalid"; channel = null; current_revision = null; message = opt "unrelated validation failure" })',
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister channel count is nonzero but list returns no channels", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(2 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          if (!args.includes("(opt (2 : nat64))")) {
            return { output: "unexpected list limit", status: 1 };
          }
          return { output: "(vec {})", status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "batch_channel_count is 2 but batch_channels returned no channel records",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister channel count differs from listed channel records", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(2 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: `(vec { ${batchChannelRecord()} })`, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "batch_channel_count is 2 but batch_channels returned 1 channel records",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel list only contains channel_id text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(1 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: `(vec { "channel_id" })`, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: 'unexpected batch_channels output: (vec { "channel_id" })',
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel list returns partial records", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(1 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: `(vec { record { channel_id = "${channelId}" } })`, status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `unexpected batch_channels output: (vec { record { channel_id = "${channelId}" } })`,
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel list returns unsafe field values", async () => {
    const unsafeRefundNonce = batchChannelRecord().replace('refund_nonce = "0";', `refund_nonce = "${Number.MAX_SAFE_INTEGER + 1}";`);
    const zeroReceiver = batchChannelRecord().replace(`receiver = "${seller}";`, `receiver = "0x${"0".repeat(40)}";`);
    const cases: readonly { readonly detail: string; readonly record: string }[] = [
      { detail: `unexpected batch_channels output: (vec { ${unsafeRefundNonce} })`, record: unsafeRefundNonce },
      { detail: `unexpected batch_channels output: (vec { ${zeroReceiver} })`, record: zeroReceiver }
    ];
    for (const { record, detail } of cases) {
      const report = await buildBatchProductionReadinessReport({
        batchPreflightReader: preflightReader,
        commandRunner(command, args) {
          if (command === "icp" && args.includes("env_names")) {
            return { output: batchEnvNamesOutput, status: 0 };
          }
          if (command === "icp" && args.includes("batch_channel_storage_writer")) {
            return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
          }
          if (command === "icp" && args.includes("batch_receiver_authorizer")) {
            return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
          }
          if (command === "icp" && args.includes("batch_settlement_contract")) {
            return { output: `(opt "${batchContract}")`, status: 0 };
          }
          if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
            return { output: `(opt "100")`, status: 0 };
          }
          if (command === "icp" && args.includes("status")) {
            return { output: canisterStatusOutput, status: 0 };
          }
          if (command === "icp" && args.includes("batch_channel_count")) {
            return { output: "(1 : nat64)", status: 0 };
          }
          if (command === "icp" && args.includes("batch_channel")) {
            return { output: "(null)", status: 0 };
          }
          if (command === "icp" && args.includes("batch_channels")) {
            return { output: `(vec { ${record} })`, status: 0 };
          }
          return { output: "", status: 0 };
        },
        env: env(),
        fileReader: fileReader(),
        fetchFn: fetchForBatchSupported(),
        requireBatchReceipt: false
      });

      expect(report.ready).toBe(false);
      expect(report.stages).toContainEqual({
        detail,
        name: "canister:batch-storage-api",
        status: "fail"
      });
      expect(report.nextCommands).toContain("npm run build");
    }
  });

  it("fails when deployed canister deleted batch channel list returns unsafe field values", async () => {
    const unsafeDeletedRecord = batchDeletedChannelRecord().replace('refund_nonce = "0";', `refund_nonce = "${Number.MAX_SAFE_INTEGER + 1}";`);
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec {})", status: 0 };
        }
        if (command === "icp" && args.includes("batch_deleted_channel_count")) {
          return { output: "(1 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_deleted_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_deleted_channels")) {
          return { output: `(vec { ${unsafeDeletedRecord} })`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_update_channel")) {
          return {
            output: '(record { status = "invalid"; channel = null; current_revision = null; message = opt "channelId: hex must be 32 bytes" })',
            status: 0
          };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `unexpected batch_deleted_channels output: (vec { ${unsafeDeletedRecord} })`,
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel list output contains extra text", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(null)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "warning: stale output (vec {})", status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "unexpected batch_channels output: warning: stale output (vec {})",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister has more batch channels than the list limit", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(1_001 : nat64)", status: 0 };
        }
        if (command === "icp") {
          const batchQuery = batchStorageQueryOutput(args);
          if (batchQuery !== undefined) {
            return batchQuery;
          }
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "batch channel count 1001 exceeds list limit 1000",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel output is not optional", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: "(record {})", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec {})", status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "unexpected batch_channel output: (record {})",
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel output is optional but not a BatchChannel record", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: `(opt "not-a-channel")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec {})", status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `unexpected batch_channel output: (opt "not-a-channel")`,
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when deployed canister batch channel output is a partial record", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args) {
        if (command === "icp" && args.includes("env_names")) {
          return { output: batchEnvNamesOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_storage_writer")) {
          return { output: `(opt principal "${writerPrincipal}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_receiver_authorizer")) {
          return { output: `(opt "${receiverAuthorizer}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_contract")) {
          return { output: `(opt "${batchContract}")`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_settlement_fee_amount")) {
          return { output: `(opt "100")`, status: 0 };
        }
        if (command === "icp" && args.includes("status")) {
          return { output: canisterStatusOutput, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel_count")) {
          return { output: "(0 : nat64)", status: 0 };
        }
        if (command === "icp" && args.includes("batch_channel")) {
          return { output: `(opt record { channel_id = "${readinessChannelId}" })`, status: 0 };
        }
        if (command === "icp" && args.includes("batch_channels")) {
          return { output: "(vec {})", status: 0 };
        }
        return { output: "", status: 0 };
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: `unexpected batch_channel output: (opt record { channel_id = "${readinessChannelId}" })`,
      name: "canister:batch-storage-api",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run build");
  });

  it("fails when DID lacks batch channel storage API", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader({
        didBytes: Buffer.from(`
service : {
  batch_channel_count : () -> (nat64) query;
}
`)
      }),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual(expect.objectContaining({
      detail: expect.stringContaining("missing or mismatched DID batch storage API: method batch_channel"),
      name: "did:batch-storage-api",
      status: "fail"
    }));
    expect(report.nextCommands).toContain("npm run did:generate");
  });

  it("fails when DID mentions batch methods outside the service block only", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader({
        didBytes: Buffer.from(`
type NotService = record {
  batch_channel : text;
  batch_channel_count : text;
  batch_channel_storage_writer : text;
  batch_channels : text;
  batch_deleted_channel : text;
  batch_deleted_channel_count : text;
  batch_deleted_channels : text;
  batch_receiver_authorizer : text;
  batch_settlement_contract : text;
  batch_settlement_fee_amount : text;
  batch_update_channel : text;
};
service : {
}
`)
      }),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual(expect.objectContaining({
      detail: expect.stringContaining("missing or mismatched DID batch storage API: method batch_channel"),
      name: "did:batch-storage-api",
      status: "fail"
    }));
    expect(report.nextCommands).toContain("npm run did:generate");
  });

  it("fails when DID keeps a stale batch_update_channel result shape", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader({
        didBytes: Buffer.from(`
type BatchChannel = record {
  channel_id : text;
  revision : nat64;
};
type BatchChannelUpdate = record { channel : opt BatchChannel };
type BatchChannelUpdateResult = variant { ok : BatchChannel; revision_mismatch : nat64 };
type BatchDeletedChannel = record {
  deleted_at : nat64;
  deleted_by : text;
  channel : BatchChannel;
};
service : {
  batch_channel : (text) -> (opt BatchChannel) query;
  batch_channel_count : () -> (nat64) query;
  batch_channel_storage_writer : () -> (opt principal) query;
  batch_channels : (opt nat64) -> (vec BatchChannel) query;
  batch_deleted_channel : (text) -> (opt BatchDeletedChannel) query;
  batch_deleted_channel_count : () -> (nat64) query;
  batch_deleted_channels : (opt nat64) -> (vec BatchDeletedChannel) query;
  batch_receiver_authorizer : () -> (opt text) query;
  batch_settlement_contract : () -> (opt text) query;
  batch_settlement_fee_amount : () -> (opt text) query;
  batch_update_channel : (text, opt nat64, BatchChannelUpdate) -> (BatchChannelUpdateResult);
}
`)
      }),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual(expect.objectContaining({
      detail: expect.stringContaining("type BatchChannelUpdateResult"),
      name: "did:batch-storage-api",
      status: "fail"
    }));
    expect(report.nextCommands).toContain("npm run did:generate");
  });

  it("fails when committed DID differs from local wasm generated DID", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner(command, args, cwd) {
        if (command === "candid-extractor") {
          return { output: "service : {}", status: 0 };
        }
        return passingCommandRunner(command, args, cwd);
      },
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "dist/facilitator.did does not match local wasm candid-extractor output",
      name: "did:generated",
      status: "fail"
    });
    expect(report.nextCommands).toContain("npm run did:generate");
  });

  it("fails when deployed canister does not advertise batch settlement", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(false),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(false);
    expect(report.stages).toContainEqual({
      detail: "supported lacks x402 v2 batch-settlement/eip155:137",
      name: "canister:batch-supported",
      status: "fail"
    });
    expect(report.nextCommands).toContain("ICP_ENVIRONMENT=ic ICP_CANISTER=edge npm run smoke:canister -- --with-batch");
  });

  it("fails when deployed batch support does not match local batch env", async () => {
    const report = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: env(),
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });
    const mismatch = await buildBatchProductionReadinessReport({
      batchPreflightReader: preflightReader,
      commandRunner: passingCommandRunner,
      env: { ...env(), BATCH_WITHDRAW_DELAY_SECONDS: "901" },
      fileReader: fileReader(),
      fetchFn: fetchForBatchSupported(),
      requireBatchReceipt: false
    });

    expect(report.ready).toBe(true);
    expect(mismatch.ready).toBe(false);
    expect(mismatch.stages).toContainEqual({
      detail: "supported.batch.extra.withdrawDelay does not match BATCH_WITHDRAW_DELAY_SECONDS",
      name: "canister:batch-supported",
      status: "fail"
    });
  });
});
