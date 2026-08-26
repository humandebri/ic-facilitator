// test/settlementReceipt.test.ts: settlement tx receipt の成功判定と hash validation を確認する。
import { describe, expect, it } from "vitest";
import type { Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { expectedSettlementSenderFromEnv, expectedTransferFromEnv, parseTxHash, verifySettlementReceipt } from "../scripts/settlement_receipt";

const hash: Hex = "0x0000000000000000000000000000000000000000000000000000000000000402";
const jpyc: Hex = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const payer: Hex = "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993";
const facilitatorPrivateKey: Hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
const facilitatorAddress = privateKeyToAccount(facilitatorPrivateKey).address;
const sampleSeller: Hex = "0x0000000000000000000000000000000000000402";
const seller: Hex = "0x1000000000000000000000000000000000000402";
const transferTopic: Hex = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const receipt: TransactionReceipt = {
  blockHash: "0x0000000000000000000000000000000000000000000000000000000000000001",
  blockNumber: 123n,
  contractAddress: null,
  cumulativeGasUsed: 21000n,
  effectiveGasPrice: 1n,
  from: payer,
  gasUsed: 21000n,
  logs: [],
  logsBloom: "0x",
  status: "success",
  to: jpyc,
  transactionHash: hash,
  transactionIndex: 0,
  type: "eip1559"
};

function isTopic(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function topicAddress(address: Hex): Hex {
  const topic = `0x${"0".repeat(24)}${address.slice(2)}`;
  if (!isTopic(topic)) {
    throw new Error("invalid topic address");
  }
  return topic;
}

function uint256(value: bigint): Hex {
  const topic = `0x${value.toString(16).padStart(64, "0")}`;
  if (!isTopic(topic)) {
    throw new Error("invalid uint256");
  }
  return topic;
}

describe("settlement receipt", () => {
  it("parses transaction hashes", () => {
    expect(parseTxHash(hash)).toBe(hash);
    expect(() => parseTxHash("0x1234")).toThrow("settlement tx must be");
  });

  it("requires facilitator key to build expected settlement sender checks", () => {
    expect(() => expectedSettlementSenderFromEnv({})).toThrow("missing required env: FACILITATOR_EVM_PRIVATE_KEY");
    expect(() => expectedSettlementSenderFromEnv({ FACILITATOR_EVM_PRIVATE_KEY: "0x1234" }))
      .toThrow("FACILITATOR_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
    expect(expectedSettlementSenderFromEnv({ FACILITATOR_EVM_PRIVATE_KEY: facilitatorPrivateKey }))
      .toBe(facilitatorAddress);
  });

  it("requires seller to build expected transfer checks", () => {
    expect(() => expectedTransferFromEnv({})).toThrow("missing required env: SELLER_EVM_ADDRESS");
    expect(() => expectedTransferFromEnv({ SELLER_EVM_ADDRESS: "0x0000000000000000000000000000000000000000" }))
      .toThrow("expected transfer recipient must be a non-zero EVM address");
    expect(() => expectedTransferFromEnv({ SELLER_EVM_ADDRESS: sampleSeller }))
      .toThrow("SELLER_EVM_ADDRESS must be a real seller address");
    expect(expectedTransferFromEnv({
      BUYER_EVM_PRIVATE_KEY: facilitatorPrivateKey,
      JPYC_PRICE: "0.5",
      SELLER_EVM_ADDRESS: seller
    })).toEqual({
      amount: "500000000000000000",
      asset: jpyc,
      from: facilitatorAddress,
      to: seller
    });
  });

  it("verifies the expected JPYC settlement contract", async () => {
    await expect(verifySettlementReceipt({
      expectedTo: jpyc,
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return receipt;
        }
      }
    })).resolves.toMatchObject({ to: jpyc });

    await expect(verifySettlementReceipt({
      expectedTo: jpyc,
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return { ...receipt, to: seller };
        }
      }
    })).rejects.toThrow("settlement tx recipient mismatch");
  });

  it("verifies the expected settlement sender", async () => {
    await expect(verifySettlementReceipt({
      expectedFrom: payer,
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return receipt;
        }
      }
    })).resolves.toMatchObject({ from: payer });

    await expect(verifySettlementReceipt({
      expectedFrom: facilitatorAddress,
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return receipt;
        }
      }
    })).rejects.toThrow("settlement tx sender mismatch");
  });


  it("rejects non-positive expected JPYC transfer amounts", () => {
    expect(() =>
      expectedTransferFromEnv({
        JPYC_PRICE: "0",
        SELLER_EVM_ADDRESS: seller
      })
    ).toThrow("JPYC_PRICE must be a positive decimal string");
  });

  it("returns a compact success receipt", async () => {
    const result = await verifySettlementReceipt({
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt(args) {
          expect(args.hash).toBe(hash);
          return receipt;
        }
      }
    });

    expect(result).toEqual({
      blockNumber: "123",
      confirmations: "3",
      from: payer,
      gasUsed: "21000",
      hash,
      status: "success",
      to: jpyc
    });
  });

  it("verifies expected JPYC transfer logs", async () => {
    const amount = "1000000000000000000";
    const result = await verifySettlementReceipt({
      expectedTransfer: {
        amount,
        asset: jpyc,
        from: payer,
        to: seller
      },
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return {
            ...receipt,
            logs: [
              {
                address: jpyc,
                blockHash: receipt.blockHash,
                blockNumber: receipt.blockNumber,
                data: uint256(BigInt(amount)),
                logIndex: 0,
                removed: false,
                topics: [transferTopic, topicAddress(payer), topicAddress(seller)],
                transactionHash: hash,
                transactionIndex: receipt.transactionIndex
              }
            ]
          };
        }
      }
    });

    expect(result.transfer).toEqual({
      amount,
      asset: jpyc,
      from: payer,
      to: seller
    });
  });

  it("rejects removed JPYC transfer logs", async () => {
    const amount = "1000000000000000000";
    await expect(verifySettlementReceipt({
      expectedTransfer: {
        amount,
        asset: jpyc,
        from: payer,
        to: seller
      },
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return {
            ...receipt,
            logs: [
              {
                address: jpyc,
                blockHash: receipt.blockHash,
                blockNumber: receipt.blockNumber,
                data: uint256(BigInt(amount)),
                logIndex: 0,
                removed: true,
                topics: [transferTopic, topicAddress(payer), topicAddress(seller)],
                transactionHash: hash,
                transactionIndex: receipt.transactionIndex
              }
            ]
          };
        }
      }
    })).rejects.toThrow("expected JPYC transfer log not found in settlement receipt");
  });

  it("accepts uppercase transfer topics from RPC responses", async () => {
    const amount = "1000000000000000000";
    const upperTopic = `0x${transferTopic.slice(2).toUpperCase()}`;
    if (!isTopic(upperTopic)) {
      throw new Error("invalid uppercase topic");
    }
    const result = await verifySettlementReceipt({
      expectedTransfer: {
        amount,
        asset: jpyc,
        from: payer,
        to: seller
      },
      hash,
      reader: {
        async getBlockNumber() {
          return 125n;
        },
        async getTransactionReceipt() {
          return {
            ...receipt,
            logs: [
              {
                address: jpyc,
                blockHash: receipt.blockHash,
                blockNumber: receipt.blockNumber,
                data: uint256(BigInt(amount)),
                logIndex: 0,
                removed: false,
                topics: [upperTopic, topicAddress(payer), topicAddress(seller)],
                transactionHash: hash,
                transactionIndex: receipt.transactionIndex
              }
            ]
          };
        }
      }
    });

    expect(result.transfer?.amount).toBe(amount);
  });

  it("rejects receipts for a different transaction hash", async () => {
    await expect(
      verifySettlementReceipt({
        hash,
        reader: {
          async getBlockNumber() {
            return 125n;
          },
          async getTransactionReceipt() {
            return {
              ...receipt,
              transactionHash: "0x0000000000000000000000000000000000000000000000000000000000000002"
            };
          }
        }
      })
    ).rejects.toThrow("receipt hash mismatch");
  });

  it("rejects reverted settlement receipts", async () => {
    await expect(
      verifySettlementReceipt({
        hash,
        reader: {
          async getBlockNumber() {
            return 125n;
          },
          async getTransactionReceipt() {
            return { ...receipt, status: "reverted" };
          }
        }
      })
    ).rejects.toThrow("settlement tx failed: reverted");
  });

  it("rejects receipts without the expected JPYC transfer", async () => {
    await expect(
      verifySettlementReceipt({
        expectedTransfer: {
          amount: "1000000000000000000",
          asset: jpyc,
          from: payer,
          to: seller
        },
        hash,
        reader: {
          async getBlockNumber() {
            return 125n;
          },
          async getTransactionReceipt() {
            return receipt;
          }
        }
      })
    ).rejects.toThrow("expected JPYC transfer log not found");
  });

  it("rejects receipts below the minimum confirmation count", async () => {
    await expect(
      verifySettlementReceipt({
        hash,
        minConfirmations: 3,
        reader: {
          async getBlockNumber() {
            return 124n;
          },
          async getTransactionReceipt() {
            return receipt;
          }
        }
      })
    ).rejects.toThrow("settlement tx confirmations below minimum: 2 < 3");
  });
});
