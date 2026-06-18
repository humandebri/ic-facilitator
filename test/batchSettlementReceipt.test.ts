// test/batchSettlementReceipt.test.ts: batch settlement tx receipt と post-state 検証を確認する。
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";
import { encodeAbiParameters, encodeEventTopics, parseAbi } from "viem";
import type { Address, Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  batchSettlementReceiptOptionsForActionFromEnv,
  batchSettlementReceiptOptionsFromEnv,
  verifyBatchSettlementReceipt,
  verifyBatchSettlementReceiptsFromEnv
} from "../scripts/batch_settlement_receipt";
import type { BatchSettlementReceiptReader, BatchSettlementTransaction } from "../scripts/batch_settlement_receipt";

const hash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000b47";
const contract: Address = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";
const jpyc: Address = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const alternateToken: Address = "0x0000000000000000000000000000000000000abc";
const receiver: Address = "0x1000000000000000000000000000000000000402";
const alternateReceiver: Address = "0x1000000000000000000000000000000000000999";
const sender: Address = "0x2000000000000000000000000000000000000402";
const facilitatorPrivateKey: Hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
const facilitatorAddress = privateKeyToAccount(facilitatorPrivateKey).address;
const receiverAuthorizerPrivateKey: Hex = "0x2222222222222222222222222222222222222222222222222222222222222222";
const receiverAuthorizer = privateKeyToAccount(receiverAuthorizerPrivateKey).address;
const channelId: Hex = "0x95995132e1646c51d70cbebd071b3fa2340dd7d3677b7f85bc5fecf85f9e5f98";
const alternateChannelId: Hex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const settledAbi = parseAbi([
  "event Settled(address indexed receiver,address indexed token,address indexed sender,uint128 amount)"
]);

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

function encodeBytesArray(items: readonly Hex[]): string {
  let offset = 32n * BigInt(items.length);
  let head = uint256(BigInt(items.length)).slice(2);
  let tail = "";
  for (const item of items) {
    const encoded = encodeBytes(item);
    head += uint256(offset).slice(2);
    offset += BigInt(encoded.length / 2);
    tail += encoded;
  }
  return `${head}${tail}`;
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

type FakeReaderState = {
  readonly balance?: bigint;
  readonly latestBlock?: bigint;
  readonly receipt?: TransactionReceipt;
  readonly refundNonce?: bigint;
  readonly transactionFrom?: Address;
  readonly transactionInput?: Hex;
  readonly transactionInputs?: ReadonlyMap<Hex, Hex>;
  readonly totalClaimed?: bigint;
  readonly totalSettled?: bigint;
};

class FakeReader implements BatchSettlementReceiptReader {
  private readonly state: FakeReaderState;

  constructor(state: FakeReaderState = {}) {
    this.state = state;
  }

  async getBatchChannel(): Promise<readonly [bigint, bigint]> {
    return [this.state.balance ?? 100n, this.state.totalClaimed ?? 50n];
  }

  async getBatchReceiver(): Promise<readonly [bigint, bigint]> {
    return [this.state.totalClaimed ?? 50n, this.state.totalSettled ?? 30n];
  }

  async getBatchRefundNonce(): Promise<bigint> {
    return this.state.refundNonce ?? 2n;
  }

  async getBlockNumber(): Promise<bigint> {
    return this.state.latestBlock ?? 12n;
  }

  async getTransaction(args: { readonly hash: Hex }): Promise<BatchSettlementTransaction> {
    return {
      from: this.state.transactionFrom ?? facilitatorAddress,
      hash: args.hash,
      input: this.state.transactionInputs?.get(args.hash) ?? this.state.transactionInput ?? depositInput,
      to: contract
    };
  }

  async getTransactionReceipt(args: { readonly hash: Hex }): Promise<TransactionReceipt> {
    const base = this.state.receipt ?? receipt();
    return { ...base, transactionHash: args.hash };
  }
}

const throwingReader: BatchSettlementReceiptReader = {
  async getBatchChannel() {
    throw new Error("unexpected RPC call");
  },
  async getBatchReceiver() {
    throw new Error("unexpected RPC call");
  },
  async getBatchRefundNonce() {
    throw new Error("unexpected RPC call");
  },
  async getBlockNumber() {
    throw new Error("unexpected RPC call");
  },
  async getTransaction() {
    throw new Error("unexpected RPC call");
  },
  async getTransactionReceipt() {
    throw new Error("unexpected RPC call");
  }
};

function channelConfigWordsFor(
  configReceiver: Address,
  token: Address = jpyc,
  configReceiverAuthorizer: Address = receiverAuthorizer,
  withdrawDelay = 900n
): string {
  return [
    addressWord(sender),
    addressWord(sender),
    addressWord(configReceiver),
    addressWord(configReceiverAuthorizer),
    addressWord(token),
    uint256(withdrawDelay),
    hex(`0x${"33".repeat(32)}`)
  ].map((word) => word.slice(2)).join("");
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
  const claimTails = claims.map((claim) => claimTuple(claim.configWords, claim.totalClaimed));
  const claimsData = encodeDynamicArray(claimTails);
  const authorizerSignature = hex(`0x${"22".repeat(65)}`);
  return hex(`0xe43ce1f2${uint256(64n).slice(2)}${uint256(BigInt(64 + claimsData.length / 2)).slice(2)}${claimsData}${encodeBytes(authorizerSignature)}`);
}

function refundInputFor(configWords: string, nonce: bigint): Hex {
  const authorizerSignature = hex(`0x${"44".repeat(65)}`);
  return hex(`0xb77433e9${configWords}${uint256(1500n).slice(2)}${uint256(nonce).slice(2)}${uint256(320n).slice(2)}${encodeBytes(authorizerSignature)}`);
}

function depositInputFor(configWords: string, amount = 90n): Hex {
  return hex(`0x140f1e75${configWords}${uint256(amount).slice(2)}${addressWord(sender).slice(2)}${uint256(320n).slice(2)}${encodeBytes("0x")}`);
}

const channelConfigWords = channelConfigWordsFor(receiver);
const alternateReceiverChannelConfigWords = channelConfigWordsFor(alternateReceiver);
const alternateTokenChannelConfigWords = channelConfigWordsFor(receiver, alternateToken);
const alternateReceiverAuthorizerChannelConfigWords = channelConfigWordsFor(receiver, jpyc, alternateReceiver);
const alternateWithdrawDelayChannelConfigWords = channelConfigWordsFor(receiver, jpyc, receiver, 901n);
const claimInput: Hex = claimInputFor([{ configWords: channelConfigWords, totalClaimed: 50n }]);
const highClaimInput: Hex = claimInputFor([{ configWords: channelConfigWords, totalClaimed: 51n }]);
const lowClaimInput: Hex = claimInputFor([{ configWords: channelConfigWords, totalClaimed: 49n }]);
const mixedReceiverClaimInput: Hex = claimInputFor([
  { configWords: channelConfigWords, totalClaimed: 50n },
  { configWords: alternateReceiverChannelConfigWords, totalClaimed: 50n }
]);
const alternateTokenClaimInput: Hex = claimInputFor([{ configWords: alternateTokenChannelConfigWords, totalClaimed: 50n }]);
const depositInput: Hex = depositInputFor(channelConfigWords);
const alternateReceiverDepositInput: Hex = depositInputFor(alternateReceiverChannelConfigWords);
const alternateTokenDepositInput: Hex = depositInputFor(alternateTokenChannelConfigWords);
const alternateReceiverAuthorizerDepositInput: Hex = depositInputFor(alternateReceiverAuthorizerChannelConfigWords);
const alternateWithdrawDelayDepositInput: Hex = depositInputFor(alternateWithdrawDelayChannelConfigWords);
const refundInput: Hex = refundInputFor(channelConfigWords, 1n);
const alternateReceiverRefundInput: Hex = refundInputFor(alternateReceiverChannelConfigWords, 1n);
const settleInput: Hex = hex(`0x9db32a8f${addressWord(receiver).slice(2)}${addressWord(jpyc).slice(2)}`);
const wrongSettleReceiverInput: Hex = hex(`0x9db32a8f${addressWord(alternateReceiver).slice(2)}${addressWord(jpyc).slice(2)}`);
const dirtyPaddedSettleInput: Hex = hex(`0x9db32a8f${"01".repeat(12)}${receiver.slice(2)}${addressWord(jpyc).slice(2)}`);
const refundMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([refundInput])}`);
const refundWithClaimMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([claimInput, refundInput])}`);
const refundWithMixedReceiverClaimMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([mixedReceiverClaimInput, refundInput])}`);
const refundWithUnknownCallMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([refundInput, "0x12345678"])}`);
const refundWithOtherChannelMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([refundInput, alternateReceiverRefundInput])}`);
const overlappingMulticallInput: Hex = hex(`0xac9650d8${uint256(32n).slice(2)}${uint256(1n).slice(2)}${uint256(0n).slice(2)}${encodeBytes(refundInput)}`);
const overlappingClaimInput: Hex = hex(`0xe43ce1f2${uint256(64n).slice(2)}${uint256(320n).slice(2)}${uint256(1n).slice(2)}${uint256(0n).slice(2)}${claimTuple(channelConfigWords, 50n)}${encodeBytes(hex(`0x${"22".repeat(65)}`))}`);
const claimHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000c11";
const depositHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000d09";
const refundHash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000f01";
const settleHash: Hex = "0x00000000000000000000000000000000000000000000000000000000000005e7";

function receipt(overrides: Partial<TransactionReceipt> = {}): TransactionReceipt {
  return {
    blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
    blockNumber: 10n,
    contractAddress: null,
    cumulativeGasUsed: 21000n,
    effectiveGasPrice: 1n,
    from: facilitatorAddress,
    gasUsed: 21000n,
    logs: [],
    logsBloom: "0x",
    status: "success",
    to: contract,
    transactionHash: hash,
    transactionIndex: 0,
    type: "eip1559",
    ...overrides
  };
}

function settledLog(
  amount: bigint,
  logIndex = 0,
  removed = false,
  logSender: Address = facilitatorAddress,
  transactionHash: Hex = hash
): TransactionReceipt["logs"][number] {
  const topics = encodeEventTopics({
    abi: settledAbi,
    eventName: "Settled",
    args: { receiver, sender: logSender, token: jpyc }
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
    address: contract,
    blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
    blockNumber: 10n,
    data: encodeAbiParameters([{ type: "uint128" }], [amount]),
    logIndex,
    removed,
    topics: logTopics,
    transactionHash,
    transactionIndex: 0
  };
}

describe("batch settlement receipt", () => {
  it("verifies deposit receipts with post-state balance", async () => {
    const result = await verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "90",
      hash,
      reader: new FakeReader({ balance: 100n })
    });

    expect(result.channelState).toEqual({
      balance: "100",
      channelId,
      totalClaimed: "50"
    });
  });

  it("rejects deposit receipts when calldata amount differs from the proof env", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "91",
      expectedMinBalance: "90",
      hash,
      reader: new FakeReader({ balance: 100n, transactionInput: depositInput })
    })).rejects.toThrow("batch deposit amount mismatch");
  });

  it("rejects claim receipts when totalClaimed is below expectation", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "51",
      hash,
      reader: new FakeReader({ totalClaimed: 50n, transactionInput: highClaimInput })
    })).rejects.toThrow("batch channel totalClaimed below expected");
  });

  it("rejects claim receipts when calldata totalClaimed is below expectation", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ totalClaimed: 50n, transactionInput: lowClaimInput })
    })).rejects.toThrow("batch claim calldata totalClaimed below expected");
  });

  it("rejects claim receipts when post-state is below calldata totalClaimed", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ totalClaimed: 50n, transactionInput: highClaimInput })
    })).rejects.toThrow("batch channel totalClaimed below calldata");
  });

  it("rejects claim receipts that mix receiver-scoped batches", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ totalClaimed: 50n, transactionInput: mixedReceiverClaimInput })
    })).rejects.toThrow("batch claim calldata mixes receivers");
  });

  it("verifies settle receipts using Settled event and receiver state", async () => {
    const result = await verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n)] }), totalClaimed: 60n, totalSettled: 40n, transactionInput: settleInput }),
      receiver,
      token: jpyc
    });

    expect(result.receiverState).toEqual({
      receiver,
      settledAmount: "25",
      token: jpyc,
      totalClaimed: "60",
      totalSettled: "40"
    });
  });

  it("sums multiple Settled events for the expected receiver and token", async () => {
    const result = await verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "30",
      hash,
      reader: new FakeReader({
        receipt: receipt({ logs: [settledLog(10n, 0), settledLog(20n, 1)] }),
        totalClaimed: 60n,
        totalSettled: 40n,
        transactionInput: settleInput
      }),
      receiver,
      token: jpyc
    });

    expect(result.receiverState?.settledAmount).toBe("30");
  });

  it("requires an explicit token for direct settle receipt checks", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: throwingReader,
      receiver
    })).rejects.toThrow("BATCH_SETTLE_TOKEN is required for settle receipt checks");
  });

  it("rejects settle receipts when receiver post-state is below event amount", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n)] }), totalClaimed: 60n, totalSettled: 24n, transactionInput: settleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch receiver totalSettled below event amount");
  });

  it("rejects settle receipts when receiver claimed state is below settled state", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n)] }), totalClaimed: 39n, totalSettled: 40n, transactionInput: settleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch receiver totalClaimed below totalSettled");
  });

  it("rejects settle receipts without the expected event", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ transactionInput: settleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("expected batch Settled event not found");
  });

  it("rejects settle receipts that only contain removed Settled logs", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n, 0, true)] }), transactionInput: settleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("expected batch Settled event not found");
  });

  it("rejects settle receipts when the Settled event sender is not the tx sender", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n, 0, false, sender)] }), transactionInput: settleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("expected batch Settled event not found");
  });

  it("verifies refund receipts with nonce and optional claimed amount", async () => {
    const result = await verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ refundNonce: 2n, totalClaimed: 50n, transactionInput: refundWithClaimMulticallInput })
    });

    expect(result.channelState?.refundNonce).toBe("2");
  });

  it("rejects refund multicalls when embedded claim scope is invalid", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ refundNonce: 2n, totalClaimed: 50n, transactionInput: refundWithMixedReceiverClaimMulticallInput })
    })).rejects.toThrow("batch claim calldata mixes receivers");
  });

  it("rejects refund multicalls when post-state is below embedded claim totalClaimed", async () => {
    const input = hex(`0xac9650d8${uint256(32n).slice(2)}${encodeBytesArray([highClaimInput, refundInput])}`);
    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ refundNonce: 2n, totalClaimed: 50n, transactionInput: input })
    })).rejects.toThrow("batch channel totalClaimed below calldata");
  });

  it("rejects refund receipts when post-state nonce is below calldata nonce", async () => {
    const input = refundInputFor(channelConfigWords, 2n);
    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      hash,
      reader: new FakeReader({ refundNonce: 2n, transactionInput: input })
    })).rejects.toThrow("batch refundNonce below calldata");
  });

  it("rejects refund multicalls with unsupported calls or refunds for another channel", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      hash,
      reader: new FakeReader({ refundNonce: 2n, transactionInput: refundWithUnknownCallMulticallInput })
    })).rejects.toThrow("batch refund multicall contains unsupported call");

    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      hash,
      reader: new FakeReader({ refundNonce: 2n, transactionInput: refundWithOtherChannelMulticallInput })
    })).rejects.toThrow("batch refund calldata channelId mismatch");
  });

  it("rejects non-canonical dynamic calldata offsets", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "2",
      hash,
      reader: new FakeReader({ refundNonce: 2n, transactionInput: overlappingMulticallInput })
    })).rejects.toThrow("batch multicall bytes element offset overlaps array head");

    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ totalClaimed: 50n, transactionInput: overlappingClaimInput })
    })).rejects.toThrow("batch claim calldata offset overlaps array head");
  });

  it("verifies all production readiness receipt env entries", async () => {
    const result = await verifyBatchSettlementReceiptsFromEnv({
      env: {
        BATCH_CLAIM_CHANNEL_ID: channelId,
        BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED: "50",
        BATCH_CLAIM_TX: claimHash,
        BATCH_DEPOSIT_CHANNEL_ID: channelId,
        BATCH_DEPOSIT_AMOUNT: "90",
        BATCH_DEPOSIT_EXPECTED_MIN_BALANCE: "100",
        BATCH_DEPOSIT_TX: depositHash,
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
        BATCH_WITHDRAW_DELAY_SECONDS: "900",
        FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey,
        BATCH_REFUND_CHANNEL_ID: channelId,
        BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE: "2",
        BATCH_REFUND_EXPECTED_TOTAL_CLAIMED: "50",
        BATCH_REFUND_TX: refundHash,
        BATCH_SETTLEMENT_CONTRACT: contract,
        BATCH_SETTLE_AMOUNT: "25",
        BATCH_SETTLE_RECEIVER: receiver,
        BATCH_SETTLE_TOKEN: jpyc,
        BATCH_SETTLE_TX: settleHash
      },
      reader: new FakeReader({
        receipt: receipt({ logs: [settledLog(25n, 0, false, facilitatorAddress, settleHash)] }),
        refundNonce: 2n,
        totalClaimed: 50n,
        transactionInputs: new Map([
          [claimHash, claimInput],
          [depositHash, depositInput],
          [refundHash, refundInput],
          [settleHash, settleInput]
        ])
      })
    });

    expect(result.map((entry) => entry.action)).toEqual(["deposit", "claim", "settle", "refund"]);
  });

  it("rejects receipts when the tx sender is not the facilitator key address", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedFrom: facilitatorAddress,
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ receipt: receipt({ from: sender }) })
    })).rejects.toThrow("batch settlement receipt sender mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedFrom: facilitatorAddress,
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ transactionFrom: sender })
    })).rejects.toThrow("batch settlement transaction sender mismatch");
  });

  it("rejects receipts when fetched transaction and receipt senders diverge without an expected sender", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ receipt: receipt({ from: sender }) })
    })).rejects.toThrow("batch settlement receipt/transaction sender mismatch");
  });

  it("rejects receipt logs that do not belong to the same receipt", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({
        receipt: receipt({
          logs: [{
            ...settledLog(25n),
            transactionHash: "0x0000000000000000000000000000000000000000000000000000000000000bad"
          }]
        }),
        transactionInput: settleInput
      }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch receipt log transaction hash mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({
        receipt: receipt({
          logs: [{
            ...settledLog(25n),
            blockNumber: 9n
          }]
        }),
        transactionInput: settleInput
      }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch receipt log block number mismatch");
  });

  it("requires the facilitator key when building receipt checks from env", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_SETTLEMENT_CONTRACT");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash
    })).toThrow("missing required env: FACILITATOR_EVM_PRIVATE_KEY");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: "0x1"
    })).toThrow("FACILITATOR_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  });

  it("requires the receiver authorizer key for production receipt evidence", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: receiver,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "0x1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: receiver,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  });

  it("requires the expected batch receiver for production receipt evidence", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_SETTLE_RECEIVER");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: "0x0000000000000000000000000000000000000000",
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_SETTLE_RECEIVER must be a non-zero 0x-prefixed EVM address");
  });

  it("defaults batch receipt confirmation proof to three blocks", () => {
    expect(batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }).minConfirmations).toBe(3);

    expect(batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey,
      SETTLE_MIN_CONFIRMATIONS: "0"
    }).minConfirmations).toBe(0);
  });

  it("uses three confirmations by default when receipt verifier is called directly", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ latestBlock: 10n })
    })).rejects.toThrow("batch settlement tx confirmations below minimum: 1 < 3");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      minConfirmations: 0,
      reader: new FakeReader({ latestBlock: 10n })
    })).resolves.toMatchObject({ confirmations: "1" });
  });

  it("reports missing CLI env without a stack trace", () => {
    const result = spawnSync(process.execPath, ["--import", "tsx", "scripts/batch_settlement_receipt.ts"], {
      cwd: process.cwd(),
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "" }
    });

    expect(result.status).toBe(1);
    expect(result.stderr.trim()).toBe("missing required env: BATCH_SETTLEMENT_CONTRACT");
    expect(result.stderr).not.toContain("at requireEnvFrom");
  }, 15_000);

  it("requires the official x402 batch settlement contract for receipt evidence", async () => {
    const otherContract: Address = "0x0000000000000000000000000000000000000001";

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: otherContract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow(`BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${contract}`);

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract: otherContract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader()
    })).rejects.toThrow(`contract must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${contract}`);
  });

  it("requires a HTTPS Polygon RPC endpoint without userinfo or fragment", () => {
    for (const value of [
      "http://polygon.example",
      "https://trusted.example@evil.example",
      "https://polygon.example/#x",
      "https://polygon.example/v2/key#x"
    ]) {
      expect(() => batchSettlementReceiptOptionsFromEnv({
        BATCH_CHANNEL_ID: channelId,
        BATCH_DEPOSIT_AMOUNT: "90",
        BATCH_EXPECTED_MIN_BALANCE: "1",
        BATCH_SETTLEMENT_ACTION: "deposit",
        BATCH_SETTLEMENT_CONTRACT: contract,
        BATCH_SETTLEMENT_TX: hash,
        BATCH_SETTLE_RECEIVER: receiver,
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
        BATCH_WITHDRAW_DELAY_SECONDS: "900",
        FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey,
        POLYGON_RPC_URL: value
      })).toThrow("POLYGON_RPC_URL must be a HTTPS RPC URL without userinfo or fragment");
    }

    for (const value of [
      "https://polygon.example:443",
      "https://polygon-mainnet.example/v2/api-key",
      "https://polygon-mainnet.example/rpc?apikey=abc"
    ]) {
      expect(batchSettlementReceiptOptionsFromEnv({
        BATCH_CHANNEL_ID: channelId,
        BATCH_DEPOSIT_AMOUNT: "90",
        BATCH_EXPECTED_MIN_BALANCE: "1",
        BATCH_SETTLEMENT_ACTION: "deposit",
        BATCH_SETTLEMENT_CONTRACT: contract,
        BATCH_SETTLEMENT_TX: hash,
        BATCH_SETTLE_RECEIVER: receiver,
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
        BATCH_WITHDRAW_DELAY_SECONDS: "900",
        FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey,
        POLYGON_RPC_URL: value
      }).rpcUrl).toBe(value);
    }
  });

  it("requires official batch withdraw delay range for receipt evidence", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_WITHDRAW_DELAY_SECONDS");

    for (const value of ["899", "2592001"]) {
      expect(() => batchSettlementReceiptOptionsFromEnv({
        BATCH_CHANNEL_ID: channelId,
        BATCH_DEPOSIT_AMOUNT: "90",
        BATCH_EXPECTED_MIN_BALANCE: "1",
        BATCH_SETTLEMENT_ACTION: "deposit",
        BATCH_SETTLEMENT_CONTRACT: contract,
        BATCH_SETTLEMENT_TX: hash,
        BATCH_SETTLE_RECEIVER: receiver,
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
        BATCH_WITHDRAW_DELAY_SECONDS: value,
        FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
      })).toThrow("BATCH_WITHDRAW_DELAY_SECONDS must be between 900 and 2592000");
    }

    for (const value of ["900", "2592000"]) {
      expect(batchSettlementReceiptOptionsFromEnv({
        BATCH_CHANNEL_ID: channelId,
        BATCH_DEPOSIT_AMOUNT: "90",
        BATCH_EXPECTED_MIN_BALANCE: "1",
        BATCH_SETTLEMENT_ACTION: "deposit",
        BATCH_SETTLEMENT_CONTRACT: contract,
        BATCH_SETTLEMENT_TX: hash,
        BATCH_SETTLE_RECEIVER: receiver,
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
        BATCH_WITHDRAW_DELAY_SECONDS: value,
        FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
      }).expectedWithdrawDelay).toBe(BigInt(value));
    }
  });

  it("requires deposit amount for production deposit receipt checks", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_CHANNEL_ID");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_EXPECTED_MIN_BALANCE");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_EXPECTED_MIN_BALANCE: "1",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_DEPOSIT_AMOUNT");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_DEPOSIT_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_EXPECTED_MIN_BALANCE: "1",
      BATCH_DEPOSIT_TX: depositHash,
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "deposit")).toThrow("missing required env: BATCH_DEPOSIT_AMOUNT");
  });

  it("rejects zero expected values for production channel-state receipt evidence", () => {
    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_DEPOSIT_AMOUNT: "90",
      BATCH_EXPECTED_MIN_BALANCE: "0",
      BATCH_SETTLEMENT_ACTION: "deposit",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: hash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_EXPECTED_MIN_BALANCE must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_EXPECTED_TOTAL_CLAIMED: "0",
      BATCH_SETTLEMENT_ACTION: "claim",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: claimHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_EXPECTED_TOTAL_CLAIMED must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_CHANNEL_ID: channelId,
      BATCH_EXPECTED_MIN_REFUND_NONCE: "0",
      BATCH_SETTLEMENT_ACTION: "refund",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: refundHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_EXPECTED_MIN_REFUND_NONCE must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_CLAIM_CHANNEL_ID: channelId,
      BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED: "0",
      BATCH_CLAIM_TX: claimHash,
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "claim")).toThrow("BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_REFUND_CHANNEL_ID: channelId,
      BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE: "0",
      BATCH_REFUND_TX: refundHash,
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      BATCH_WITHDRAW_DELAY_SECONDS: "900",
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "refund")).toThrow("BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_SETTLEMENT_ACTION: "settle",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: settleHash,
      BATCH_SETTLE_AMOUNT: "0",
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("BATCH_SETTLE_AMOUNT must be a positive integer string");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_AMOUNT: "0",
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      BATCH_SETTLE_TX: settleHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "settle")).toThrow("BATCH_SETTLE_AMOUNT must be a positive integer string");
  });

  it("rejects zero deposit amount as production deposit receipt evidence", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "0",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader()
    })).rejects.toThrow("BATCH_DEPOSIT_AMOUNT must be a positive integer string");
  });

  it("rejects incomplete direct receipt proof before any RPC call", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedMinBalance: "1",
      hash,
      reader: throwingReader
    })).rejects.toThrow("BATCH_DEPOSIT_AMOUNT is required for this batch receipt check");

    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      hash,
      reader: throwingReader
    })).rejects.toThrow("BATCH_EXPECTED_TOTAL_CLAIMED is required for this batch receipt check");

    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      hash,
      reader: throwingReader
    })).rejects.toThrow("BATCH_EXPECTED_MIN_REFUND_NONCE is required for this batch receipt check");

    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      hash,
      reader: throwingReader,
      receiver,
      token: jpyc
    })).rejects.toThrow("BATCH_SETTLE_AMOUNT is required for this batch receipt check");
  });

  it("rejects invalid direct min confirmations before any RPC call", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      minConfirmations: -1,
      reader: throwingReader
    })).rejects.toThrow("SETTLE_MIN_CONFIRMATIONS must be a non-negative safe integer");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      minConfirmations: Number.MAX_SAFE_INTEGER + 1,
      reader: throwingReader
    })).rejects.toThrow("SETTLE_MIN_CONFIRMATIONS must be a non-negative safe integer");
  });

  it("requires settled amount for all-action production settle checks", () => {
    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      BATCH_SETTLE_TX: settleHash,
      BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: receiverAuthorizerPrivateKey,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "settle")).toThrow("missing required env: BATCH_SETTLEMENT_CONTRACT");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      BATCH_SETTLE_TX: settleHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "settle")).toThrow("missing required env: BATCH_SETTLE_AMOUNT");

    expect(() => batchSettlementReceiptOptionsFromEnv({
      BATCH_SETTLEMENT_ACTION: "settle",
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLEMENT_TX: settleHash,
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    })).toThrow("missing required env: BATCH_SETTLE_AMOUNT");

    expect(() => batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_AMOUNT: "25",
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TX: settleHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "settle")).toThrow("missing required env: BATCH_SETTLE_TOKEN");

    const options = batchSettlementReceiptOptionsForActionFromEnv({
      BATCH_SETTLEMENT_CONTRACT: contract,
      BATCH_SETTLE_AMOUNT: "25",
      BATCH_SETTLE_RECEIVER: receiver,
      BATCH_SETTLE_TOKEN: jpyc,
      BATCH_SETTLE_TX: settleHash,
      FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey
    }, "settle");
    expect(options.expectedReceiverAuthorizer).toBeUndefined();
    expect(options.expectedWithdrawDelay).toBeUndefined();
  });

  it("rejects failed, wrong-recipient, and under-confirmed receipts", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ receipt: receipt({ status: "reverted" }) })
    })).rejects.toThrow("batch settlement tx failed");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ receipt: receipt({ to: receiver }) })
    })).rejects.toThrow("batch settlement tx recipient mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      minConfirmations: 4,
      reader: new FakeReader({ latestBlock: 12n })
    })).rejects.toThrow("batch settlement tx confirmations below minimum");
  });

  it("rejects receipts when the transaction input does not match the requested action", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ transactionInput: depositInput })
    })).rejects.toThrow("batch claim tx selector mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "refund",
      channelId,
      contract,
      expectedMinRefundNonce: "1",
      hash,
      reader: new FakeReader({ transactionInput: "0xac9650d8" })
    })).rejects.toThrow("batch multicall calldata is truncated");
  });

  it("rejects receipts when calldata channel or settle args do not match the proof env", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId: alternateChannelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ transactionInput: depositInput })
    })).rejects.toThrow("batch deposit calldata channelId mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n)] }), transactionInput: wrongSettleReceiverInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch settle receiver mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "settle",
      contract,
      expectedSettledAmount: "25",
      hash,
      reader: new FakeReader({ receipt: receipt({ logs: [settledLog(25n)] }), transactionInput: dirtyPaddedSettleInput }),
      receiver,
      token: jpyc
    })).rejects.toThrow("batch settle calldata has non-zero address padding");
  });

  it("rejects deposit and claim receipts whose calldata is not scoped to JPYC and the expected receiver", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ transactionInput: alternateTokenDepositInput })
    })).rejects.toThrow("batch deposit calldata token mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      hash,
      reader: new FakeReader({ transactionInput: alternateReceiverDepositInput }),
      receiver
    })).rejects.toThrow("batch deposit calldata receiver mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "claim",
      channelId,
      contract,
      expectedTotalClaimed: "50",
      hash,
      reader: new FakeReader({ transactionInput: alternateTokenClaimInput })
    })).rejects.toThrow("batch claim calldata token mismatch");
  });

  it("rejects receipts whose calldata receiver authorizer or withdraw delay differs from the proof env", async () => {
    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      expectedReceiverAuthorizer: receiver,
      hash,
      reader: new FakeReader({ transactionInput: alternateReceiverAuthorizerDepositInput })
    })).rejects.toThrow("batch deposit calldata receiverAuthorizer mismatch");

    await expect(verifyBatchSettlementReceipt({
      action: "deposit",
      channelId,
      contract,
      expectedDepositAmount: "90",
      expectedMinBalance: "1",
      expectedWithdrawDelay: 900n,
      hash,
      reader: new FakeReader({ transactionInput: alternateWithdrawDelayDepositInput })
    })).rejects.toThrow("batch deposit calldata withdrawDelay mismatch");
  });
});
