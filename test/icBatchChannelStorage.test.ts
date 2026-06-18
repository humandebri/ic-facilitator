// test/icBatchChannelStorage.test.ts: ICP-backed x402 batch ChannelStorage の CAS retry を確認する。
import { describe, expect, it } from "vitest";
import { computeChannelId } from "@x402/evm/batch-settlement/client";
import { BatchSettlementEvmScheme } from "@x402/evm/batch-settlement/server";
import type { ChannelStorage as OfficialChannelStorage } from "@x402/evm/batch-settlement/server";
import type { FacilitatorClient } from "@x402/core/server";
import type {
  PaymentPayload,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyContext,
  VerifyResponse
} from "@x402/core/types";

import {
  IcBatchChannelStorage,
  type BatchChannel,
  type HexString,
  type IcBatchChannel,
  type IcBatchChannelStorageClient,
  type IcBatchChannelUpdate,
  type IcBatchChannelUpdateResult
} from "../src/icBatchChannelStorage";

describe("IcBatchChannelStorage", () => {
  it("implements get/list/updateChannel over the canister CAS API", async () => {
    const channel = icChannel("0x" + "11".repeat(32), 1, "100");
    channel.pending_request = livePending("200");
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client, { listLimit: 25 });
    acceptsChannelStorage(storage);
    acceptsOfficialChannelStorage(storage);

    await expect(storage.get("0x" + "11".repeat(32))).resolves.toMatchObject({
      chargedCumulativeAmount: "100"
    });
    await expect(storage.list()).resolves.toHaveLength(1);
    expect(client.lastListLimit).toEqual([25n]);

    const updated = await storage.updateChannel("0x" + "11".repeat(32), (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "200", signedMaxClaimable: "200" };
    });

    expect(updated.status).toBe("updated");
    expect(updated.channel?.chargedCumulativeAmount).toBe("200");
  });

  it("works with official BatchSettlementEvmScheme zero-accounting initial reservation hooks", async () => {
    const channelId = "0x" + "16".repeat(32);
    const client = new FakeBatchChannelClient([]);
    const storage = new IcBatchChannelStorage(client);
    acceptsChannelStorage(storage);
    acceptsOfficialChannelStorage(storage);
    const scheme = new BatchSettlementEvmScheme("0x1000000000000000000000000000000000000402", {
      storage,
      withdrawDelay: 900
    });
    const requirements = batchPaymentRequirements();
    const paymentPayload = batchDepositPaymentPayload(channelId, requirements, {
      maxClaimableAmount: requirements.amount
    });
    const context: VerifyContext = {
      declaredExtensions: {},
      paymentPayload,
      requirements
    };

    const first = await scheme.schemeHooks.onBeforeVerify?.(context);
    expect(first).toBeUndefined();
    const stored = await storage.get(channelId);
    expect(stored).toMatchObject({
      chargedCumulativeAmount: "0",
      pendingRequest: {
        signedMaxClaimable: requirements.amount
      },
      signedMaxClaimable: requirements.amount
    });
    expect(stored?.pendingRequest?.pendingId).toMatch(/^0x[0-9a-f]+$/);
    expect(scheme.readRequestContext(paymentPayload)?.channelId).toBe(channelId);

    const second = await scheme.schemeHooks.onBeforeVerify?.({
      declaredExtensions: {},
      paymentPayload: batchDepositPaymentPayload(channelId, requirements, {
        maxClaimableAmount: requirements.amount
      }),
      requirements
    });
    expect(second).toMatchObject({
      abort: true,
      message: "Channel is already processing a request"
    });

    await scheme.clearPendingRequest(paymentPayload);

    await expect(storage.get(channelId)).resolves.toBeUndefined();
    expect(client.updateCalls).toBe(2);
  });

  it("rejects missing-local nonzero initial charged create", async () => {
    const channelId = "0x" + "19".repeat(32);
    const client = new FakeBatchChannelClient([]);
    const storage = new IcBatchChannelStorage(client);
    const scheme = new BatchSettlementEvmScheme("0x1000000000000000000000000000000000000402", {
      storage,
      withdrawDelay: 900
    });
    const requirements = batchPaymentRequirements();
    const paymentPayload = batchDepositPaymentPayload(channelId, requirements, {
      maxClaimableAmount: "125"
    });

    await expect(scheme.schemeHooks.onBeforeVerify?.({
      declaredExtensions: {},
      paymentPayload,
      requirements
    })).rejects.toThrow(
      "batch channel create requires chargedCumulativeAmount 0"
    );
    await expect(storage.get(channelId)).resolves.toBeUndefined();
  });

  it("lets cleanup delete a failed zero-accounting pending reservation", async () => {
    const channelId = "0x" + "18".repeat(32);
    const channel = icChannel(channelId, 1, "0");
    channel.signed_max_claimable = "125";
    channel.pending_request = livePending("125");
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.get(channelId)).resolves.toMatchObject({
      chargedCumulativeAmount: "0",
      pendingRequest: {
        signedMaxClaimable: "125"
      },
      signedMaxClaimable: "125"
    });

    await storage.updateChannel(channelId, () => undefined);

    await expect(storage.get(channelId)).resolves.toBeUndefined();
    expect(client.updateCalls).toBe(1);
  });

  it("requires a live pending request when creating a new channel", async () => {
    const channelId = "0x" + "17".repeat(32);
    const missingClient = new FakeBatchChannelClient([]);
    const missingStorage = new IcBatchChannelStorage(missingClient);
    await expect(missingStorage.updateChannel(channelId, () => fromIcFixture(icChannel(channelId, 0, "100"))))
      .rejects.toThrow("batch channel create requires pendingRequest");
    expect(missingClient.updateCalls).toBe(0);

    const expiredClient = new FakeBatchChannelClient([]);
    const expiredStorage = new IcBatchChannelStorage(expiredClient);
    await expect(expiredStorage.updateChannel(channelId, () => {
      const channel = icChannel(channelId, 0, "100");
      channel.pending_request = [{
        pending_id: "request-expired",
        signed_max_claimable: "100",
        expires_at: BigInt(Date.now() - 1)
      }];
      return fromIcFixture(channel);
    })).rejects.toThrow("batch channel create requires live pendingRequest");
    expect(expiredClient.updateCalls).toBe(0);

    const mismatchClient = new FakeBatchChannelClient([]);
    const mismatchStorage = new IcBatchChannelStorage(mismatchClient);
    await expect(mismatchStorage.updateChannel(channelId, () => {
      const channel = icChannel(channelId, 0, "100");
      channel.pending_request = livePending("125");
      return fromIcFixture(channel);
    })).rejects.toThrow("signedMaxClaimable must match pendingRequest.signedMaxClaimable when creating");
    expect(mismatchClient.updateCalls).toBe(0);

    const cases: Array<{
      message: string;
      mutate: (channel: BatchChannel) => BatchChannel;
    }> = [
      {
        message: "batch channel create requires chargedCumulativeAmount 0",
        mutate: (channel) => ({ ...channel, chargedCumulativeAmount: "1" })
      },
      {
        message: "batch channel create requires balance 0",
        mutate: (channel) => ({ ...channel, balance: "1" })
      },
      {
        message: "batch channel create requires totalClaimed 0",
        mutate: (channel) => ({ ...channel, totalClaimed: "1" })
      },
      {
        message: "batch channel create requires refundNonce 0",
        mutate: (channel) => ({ ...channel, refundNonce: 1 })
      },
      {
        message: "batch channel create requires withdrawRequestedAt 0",
        mutate: (channel) => ({ ...channel, withdrawRequestedAt: 1 })
      },
      {
        message: "batch channel create requires onchainSyncedAt empty",
        mutate: (channel) => ({ ...channel, onchainSyncedAt: 1 })
      }
    ];

    for (const { message, mutate } of cases) {
      const client = new FakeBatchChannelClient([]);
      const storage = new IcBatchChannelStorage(client);
      await expect(storage.updateChannel(channelId, () => {
        const channel = icChannel(channelId, 0, "0");
        channel.signed_max_claimable = "100";
        channel.signature = hex("0x" + "11".repeat(65));
        channel.pending_request = livePending("100");
        return mutate(fromIcFixture(channel));
      })).rejects.toThrow(message);
      expect(client.updateCalls).toBe(0);
    }
  });

  it("retries revision conflicts without overwriting the newer channel state", async () => {
    const channelId = "0x" + "22".repeat(32);
    const current = icChannel(channelId, 1, "100");
    current.pending_request = livePending("110");
    const conflict = icChannel(channelId, 2, "120");
    conflict.pending_request = livePending("130");
    const client = new FakeBatchChannelClient([current]);
    client.conflictOnceWith(conflict);
    const storage = new IcBatchChannelStorage(client);

    const result = await storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      const next = Number(current.chargedCumulativeAmount) + 10;
      return { ...omitPendingRequest(current), chargedCumulativeAmount: String(next), signedMaxClaimable: String(next) };
    });

    expect(client.updateCalls).toBe(2);
    expect(result.status).toBe("updated");
    expect(result.channel?.chargedCumulativeAmount).toBe("130");
  });

  it("allows official channel manager style deletion", async () => {
    const channelId = "0x" + "44".repeat(32);
    const protectedChannel = icChannel(channelId, 1, "100");
    const client = new FakeBatchChannelClient([protectedChannel]);
    const storage = new IcBatchChannelStorage(client);

    const missing = await storage.updateChannel("0x" + "55".repeat(32), () => undefined);
    expect(missing).toEqual({ channel: undefined, status: "unchanged" });

    const deleted = await storage.updateChannel(channelId, () => undefined);
    expect(deleted).toEqual({ channel: undefined, status: "deleted" });
    await expect(storage.get(channelId)).resolves.toBeUndefined();
  });

  it("rejects deletion while a pending request is live", async () => {
    const channelId = "0x" + "49".repeat(32);
    const channel = icChannel(channelId, 1, "100");
    channel.balance = "100";
    channel.pending_request = livePending("100");
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.updateChannel(channelId, () => undefined)).rejects.toThrow(
      "batch channel delete requires no live pendingRequest"
    );
    expect(client.updateCalls).toBe(0);
    await expect(storage.get(channelId)).resolves.toMatchObject({
      pendingRequest: {
        pendingId: "request-100"
      }
    });
  });

  it("supports official BatchSettlementChannelManager refund cleanup", async () => {
    const channelId = "0x" + "47".repeat(32);
    const channel = icChannel(channelId, 1, "0");
    channel.balance = "100";
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);
    const scheme = new BatchSettlementEvmScheme("0x1000000000000000000000000000000000000402", {
      storage,
      withdrawDelay: 900
    });
    const settledPayloads: PaymentPayload[] = [];
    const facilitator = {
      async verify(
        _paymentPayload: PaymentPayload,
        _paymentRequirements: PaymentRequirements
      ): Promise<VerifyResponse> {
        return { isValid: true };
      },
      async settle(
        paymentPayload: PaymentPayload,
        _paymentRequirements: PaymentRequirements
      ): Promise<SettleResponse> {
        settledPayloads.push(paymentPayload);
        return {
          amount: "100",
          network: "eip155:137",
          success: true,
          transaction: "0x" + "ab".repeat(32)
        };
      },
      async getSupported(): Promise<SupportedResponse> {
        return { extensions: [], kinds: [], signers: {} };
      }
    } satisfies FacilitatorClient;

    const manager = scheme.createChannelManager(facilitator, "eip155:137");

    await expect(manager.refund([channelId])).resolves.toEqual([{
      channel: channelId,
      transaction: "0x" + "ab".repeat(32)
    }]);
    await expect(storage.get(channelId)).resolves.toBeUndefined();
    expect(settledPayloads[0]?.payload).toMatchObject({
      amount: "100",
      refundNonce: "0",
      type: "refund"
    });
  });

  it("supports official BatchSettlementChannelManager claim state updates", async () => {
    const channel = icChannel("0x" + "00".repeat(32), 1, "100");
    channel.channel_id = officialChannelId(channel);
    channel.balance = "100";
    channel.total_claimed = "0";
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);
    const scheme = new BatchSettlementEvmScheme("0x1000000000000000000000000000000000000402", {
      storage,
      withdrawDelay: 900
    });
    const settledPayloads: PaymentPayload[] = [];
    const manager = scheme.createChannelManager(fakeFacilitator(settledPayloads), "eip155:137");

    await expect(manager.claim()).resolves.toEqual([{
      transaction: "0x" + "ab".repeat(32),
      vouchers: 1
    }]);
    await expect(storage.get(channel.channel_id)).resolves.toMatchObject({
      totalClaimed: "100"
    });
    expect(settledPayloads[0]?.payload).toMatchObject({
      type: "claim"
    });
  });

  it("stores in-place channel mutations returned from the update callback", async () => {
    const channelId = "0x" + "45".repeat(32);
    const channel = icChannel(channelId, 1, "100");
    channel.pending_request = livePending("140");
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);

    const unchanged = await storage.updateChannel(channelId, (current) => current);
    expect(unchanged.status).toBe("unchanged");
    expect(client.updateCalls).toBe(0);

    const updated = await storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      current.chargedCumulativeAmount = "140";
      delete current.pendingRequest;
      current.signedMaxClaimable = "140";
      return current;
    });

    expect(updated.status).toBe("updated");
    expect(updated.channel?.chargedCumulativeAmount).toBe("140");
    expect(client.updateCalls).toBe(1);
  });

  it("rejects channel state rollbacks before writing to the canister", async () => {
    const channelId = "0x" + "46".repeat(32);
    const current = icChannel(channelId, 1, "100");
    current.signed_max_claimable = "200";
    current.balance = "50";
    current.total_claimed = "50";
    current.refund_nonce = "3";
    const client = new FakeBatchChannelClient([current]);
    const storage = new IcBatchChannelStorage(client);

    for (const [field, update, message] of [
      ["chargedCumulativeAmount", (channel: BatchChannel) => ({ ...channel, chargedCumulativeAmount: "99" }), "chargedCumulativeAmount must not decrease"],
      ["signedMaxClaimable", (channel: BatchChannel) => ({ ...channel, signedMaxClaimable: "150" }), "signedMaxClaimable must not decrease"],
      ["totalClaimed", (channel: BatchChannel) => ({ ...channel, totalClaimed: "49" }), "totalClaimed must not decrease"],
      ["refundNonce", (channel: BatchChannel) => ({ ...channel, refundNonce: 2 }), "refundNonce must not decrease"],
      ["lastRequestTimestamp", (channel: BatchChannel) => ({ ...channel, lastRequestTimestamp: 0 }), "lastRequestTimestamp must not decrease"]
    ] as const) {
      await expect(storage.updateChannel(channelId, (channel) => {
        if (channel === undefined) {
          throw new Error(`missing channel for ${field}`);
        }
        return update(channel);
      })).rejects.toThrow(message);
    }

    expect(client.updateCalls).toBe(0);
  });

  it("rejects existing channel config changes before writing to the canister", async () => {
    const channelId = "0x" + "43".repeat(32);
    const current = icChannel(channelId, 1, "100");
    const client = new FakeBatchChannelClient([current]);
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.updateChannel(channelId, (channel) => {
      if (channel === undefined) {
        throw new Error("expected current channel");
      }
      return {
        ...channel,
        channelConfig: {
          ...channel.channelConfig,
          receiver: "0x3000000000000000000000000000000000000402"
        }
      };
    })).rejects.toThrow("channelConfig must not change for an existing batch channel");
    expect(client.updateCalls).toBe(0);
  });

  it("allows checksum-only channel config casing changes", async () => {
    const channelId = "0x" + "42".repeat(32);
    const current = icChannel(channelId, 1, "100");
    current.pending_request = livePending("125");
    const client = new FakeBatchChannelClient([current]);
    const storage = new IcBatchChannelStorage(client);

    const updated = await storage.updateChannel(channelId, (channel) => {
      if (channel === undefined) {
        throw new Error("expected current channel");
      }
      return {
        ...omitPendingRequest(channel),
        channelConfig: {
          ...channel.channelConfig,
          payer: uppercaseHex(channel.channelConfig.payer),
          salt: uppercaseHex(channel.channelConfig.salt)
        },
        chargedCumulativeAmount: "125",
        signedMaxClaimable: "125"
      };
    });

    expect(updated.status).toBe("updated");
    expect(client.updateCalls).toBe(1);
  });

  it("requires a live pending request before committing a charge increase", async () => {
    const channelId = "0x" + "48".repeat(32);
    const withoutPending = new IcBatchChannelStorage(new FakeBatchChannelClient([icChannel(channelId, 1, "100")]));

    await expect(withoutPending.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "125", signedMaxClaimable: "125" };
    })).rejects.toThrow("chargedCumulativeAmount increase requires pendingRequest");

    const expired = icChannel(channelId, 1, "100");
    expired.pending_request = [{
      pending_id: "request-expired",
      signed_max_claimable: "125",
      expires_at: BigInt(Date.now() - 1)
    }];
    const expiredStorage = new IcBatchChannelStorage(new FakeBatchChannelClient([expired]));
    await expect(expiredStorage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "125", signedMaxClaimable: "125" };
    })).rejects.toThrow("chargedCumulativeAmount increase requires live pendingRequest");

    const mismatched = icChannel(channelId, 1, "100");
    mismatched.pending_request = livePending("130");
    const mismatchStorage = new IcBatchChannelStorage(new FakeBatchChannelClient([mismatched]));
    await expect(mismatchStorage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "125", signedMaxClaimable: "125" };
    })).rejects.toThrow("signedMaxClaimable must match pendingRequest.signedMaxClaimable when charge increases");

    const unconsumed = icChannel(channelId, 1, "100");
    unconsumed.pending_request = livePending("125");
    const unconsumedStorage = new IcBatchChannelStorage(new FakeBatchChannelClient([unconsumed]));
    await expect(unconsumedStorage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      const pendingRequest = current.pendingRequest;
      if (pendingRequest === undefined) {
        throw new Error("expected pending request");
      }
      return { ...current, chargedCumulativeAmount: "125", pendingRequest, signedMaxClaimable: "125" };
    })).rejects.toThrow("chargedCumulativeAmount increase must consume pendingRequest");
  });

  it("rejects list truncation before returning partial batch settlement state", async () => {
    const client = new FakeBatchChannelClient([
      icChannel("0x" + "12".repeat(32), 1, "100")
    ]);
    client.reportedCount = 2n;
    const storage = new IcBatchChannelStorage(client, { listLimit: 1 });

    await expect(storage.list()).rejects.toThrow("batch channel count 2 exceeds listLimit 1");

    client.reportedCount = 1n;
    client.forceEmptyList = true;
    await expect(storage.list()).rejects.toThrow("batch channel list returned 0 records for count 1");
  });

  it("retries transient count/list mismatches before failing settlement list reads", async () => {
    const client = new FakeBatchChannelClient([
      icChannel("0x" + "15".repeat(32), 1, "100")
    ]);
    client.reportedCounts = [2n, 1n];
    const storage = new IcBatchChannelStorage(client, { maxRetries: 1 });

    await expect(storage.list()).resolves.toHaveLength(1);
    expect(client.listCalls).toBe(2);
  });

  it("rejects duplicate channel ids in canister list output", async () => {
    const channelId = "0x" + "13".repeat(32);
    const duplicate = icChannel(channelId, 1, "100");
    const client = new FakeBatchChannelClient([
      duplicate,
      icChannel("0x" + "14".repeat(32), 1, "100")
    ]);
    client.forcedList = [duplicate, duplicate];
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.list()).rejects.toThrow("batch channel list returned duplicate channel ids");
  });

  it("rejects invalid adapter options and malformed hex fields before writing", async () => {
    expect(() => new IcBatchChannelStorage(new FakeBatchChannelClient([]), { listLimit: 0 })).toThrow("listLimit must be a positive safe integer");
    expect(() => new IcBatchChannelStorage(new FakeBatchChannelClient([]), { listLimit: 1001 })).toThrow("listLimit must be less than or equal to 1000");
    expect(() => new IcBatchChannelStorage(new FakeBatchChannelClient([]), { maxRetries: -1 })).toThrow("maxRetries must be a non-negative safe integer");

    const channelId = "0x" + "66".repeat(32);
    const channel = icChannel(channelId, 1, "100");
    channel.pending_request = livePending("120");
    const client = new FakeBatchChannelClient([channel]);
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, signature: "0xzz" };
    })).rejects.toThrow("signature must be a 65-byte 0x-prefixed hex string");

    await expect(storage.get("0x1234")).rejects.toThrow("channelId must be a 32-byte 0x-prefixed hex string");
  });

  it("rejects unknown canister update statuses instead of treating them as updated", async () => {
    const channelId = "0x" + "67".repeat(32);
    const channel = icChannel(channelId, 1, "100");
    channel.pending_request = livePending("120");
    const client = new FakeBatchChannelClient([channel]);
    client.forcedUpdateResult = {
      status: "accepted",
      channel: [],
      current_revision: [],
      message: []
    };
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "120", signedMaxClaimable: "120" };
    })).rejects.toThrow("unknown batch channel update status: accepted");
  });

  it("rejects updated canister responses without the updated channel", async () => {
    const channelId = "0x" + "68".repeat(32);
    const channel = icChannel(channelId, 1, "100");
    channel.pending_request = livePending("120");
    const client = new FakeBatchChannelClient([channel]);
    client.forcedUpdateResult = {
      status: "updated",
      channel: [],
      current_revision: [],
      message: []
    };
    const storage = new IcBatchChannelStorage(client);

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...omitPendingRequest(current), chargedCumulativeAmount: "120", signedMaxClaimable: "120" };
    })).rejects.toThrow("batch channel update status updated without channel");
  });

  it("rejects unsafe numeric channel fields instead of silently rounding", async () => {
    const channelId = "0x" + "77".repeat(32);
    const unsafe = icChannel(channelId, 1, "100");
    unsafe.refund_nonce = String(Number.MAX_SAFE_INTEGER + 1);
    const readClient = new FakeBatchChannelClient([unsafe]);
    await expect(new IcBatchChannelStorage(readClient).get(channelId)).rejects.toThrow("refundNonce exceeds MAX_SAFE_INTEGER");

    const writeClient = new FakeBatchChannelClient([icChannel(channelId, 1, "100")]);
    const storage = new IcBatchChannelStorage(writeClient);
    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, refundNonce: Number.MAX_SAFE_INTEGER + 1 };
    })).rejects.toThrow("refundNonce must be a non-negative safe integer");
  });

  it("rejects channel fields that would fail canister storage validation", async () => {
    const channelId = "0x" + "88".repeat(32);
    const malformedAddress = icChannel(channelId, 1, "100");
    malformedAddress.channel_config.receiver = "0x1234";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([malformedAddress])).get(channelId)).rejects.toThrow("receiver must be a 20-byte 0x-prefixed hex string");

    const zeroPayer = icChannel(channelId, 1, "100");
    zeroPayer.channel_config.payer = "0x0000000000000000000000000000000000000000";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([zeroPayer])).get(channelId)).rejects.toThrow("payer must not be zero address");

    const zeroPayerAuthorizer = icChannel(channelId, 1, "100");
    zeroPayerAuthorizer.channel_config.payer_authorizer = "0x0000000000000000000000000000000000000000";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([zeroPayerAuthorizer])).get(channelId)).rejects.toThrow("payerAuthorizer must not be zero address");

    const lowWithdrawDelay = icChannel(channelId, 1, "100");
    lowWithdrawDelay.channel_config.withdraw_delay = 899n;
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([lowWithdrawDelay])).get(channelId)).rejects.toThrow("withdrawDelay must be between 900 and 2592000");

    const oversizedDecimal = icChannel(channelId, 1, "1".repeat(513));
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([oversizedDecimal])).get(channelId)).rejects.toThrow("chargedCumulativeAmount exceeds 512 bytes");

    const overUint128 = icChannel(channelId, 1, "100");
    overUint128.balance = "340282366920938463463374607431768211456";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([overUint128])).get(channelId)).rejects.toThrow("balance exceeds uint128");

    const overSigned = icChannel(channelId, 1, "100");
    overSigned.signed_max_claimable = "99";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([overSigned])).get(channelId)).rejects.toThrow("chargedCumulativeAmount exceeds signedMaxClaimable");

    const overClaimed = icChannel(channelId, 1, "100");
    overClaimed.total_claimed = "101";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([overClaimed])).get(channelId)).rejects.toThrow("totalClaimed exceeds signedMaxClaimable");

    const claimedOverBalance = icChannel(channelId, 1, "100");
    claimedOverBalance.total_claimed = "50";
    claimedOverBalance.balance = "49";
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([claimedOverBalance])).get(channelId)).rejects.toThrow("totalClaimed exceeds balance");

    const emptyPendingId = icChannel(channelId, 1, "100");
    emptyPendingId.pending_request = [{
      pending_id: " ",
      signed_max_claimable: "125",
      expires_at: 1n
    }];
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([emptyPendingId])).get(channelId)).rejects.toThrow("pendingRequest.pendingId must not be empty");

    const stalePending = icChannel(channelId, 1, "100");
    stalePending.pending_request = [{
      pending_id: "request-1",
      signed_max_claimable: "99",
      expires_at: 1n
    }];
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([stalePending])).get(channelId)).rejects.toThrow("pendingRequest.signedMaxClaimable must be at least chargedCumulativeAmount");

    const expiredPending = icChannel(channelId, 1, "100");
    expiredPending.pending_request = [{
      pending_id: "request-1",
      signed_max_claimable: "125",
      expires_at: 0n
    }];
    await expect(new IcBatchChannelStorage(new FakeBatchChannelClient([expiredPending])).get(channelId)).rejects.toThrow("pendingRequest.expiresAt must be positive");

    const writeClient = new FakeBatchChannelClient([icChannel(channelId, 1, "100")]);
    const storage = new IcBatchChannelStorage(writeClient);
    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, channelConfig: { ...current.channelConfig, payer: "0x0000000000000000000000000000000000000000" } };
    })).rejects.toThrow("channelConfig must not change for an existing batch channel");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, balance: "1.5" };
    })).rejects.toThrow("balance must be a decimal integer string");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, totalClaimed: "340282366920938463463374607431768211456" };
    })).rejects.toThrow("totalClaimed exceeds uint128");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, balance: "49", totalClaimed: "50" };
    })).rejects.toThrow("totalClaimed exceeds balance");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, channelConfig: { ...current.channelConfig, withdrawDelay: 2_592_001 } };
    })).rejects.toThrow("channelConfig must not change for an existing batch channel");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, signedMaxClaimable: "99" };
    })).rejects.toThrow("signedMaxClaimable must not decrease");

    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return {
        ...current,
        pendingRequest: {
          pendingId: "request-1",
          signedMaxClaimable: "99",
          expiresAt: 1
        }
      };
    })).rejects.toThrow("pendingRequest.signedMaxClaimable must be at least chargedCumulativeAmount");
  });

  it("rejects mismatched channel ids returned from or written to the canister", async () => {
    const channelId = "0x" + "99".repeat(32);
    const otherChannelId = "0x" + "aa".repeat(32);
    const client = new FakeBatchChannelClient([]);
    client.channels.set(channelId.toLowerCase(), icChannel(otherChannelId, 1, "100"));

    await expect(new IcBatchChannelStorage(client).get(channelId)).rejects.toThrow(
      "channelId does not match requested channel id"
    );

    const writeClient = new FakeBatchChannelClient([icChannel(channelId, 1, "100")]);
    const storage = new IcBatchChannelStorage(writeClient);
    await expect(storage.updateChannel(channelId, (current) => {
      if (current === undefined) {
        throw new Error("expected current channel");
      }
      return { ...current, channelId: otherChannelId };
    })).rejects.toThrow("channelId does not match requested channel id");
  });
});

class FakeBatchChannelClient implements IcBatchChannelStorageClient {
  readonly channels = new Map<string, IcBatchChannel>();
  updateCalls = 0;
  listCalls = 0;
  lastListLimit: [bigint] | [] = [];
  reportedCount: bigint | undefined;
  reportedCounts: bigint[] = [];
  forceEmptyList = false;
  forcedList: IcBatchChannel[] | undefined;
  forcedUpdateResult: IcBatchChannelUpdateResult | undefined;
  private conflictChannel: IcBatchChannel | undefined;

  constructor(channels: IcBatchChannel[]) {
    for (const channel of channels) {
      this.channels.set(channel.channel_id.toLowerCase(), cloneIc(channel));
    }
  }

  conflictOnceWith(channel: IcBatchChannel): void {
    this.conflictChannel = cloneIc(channel);
  }

  async batch_channel(channelId: string): Promise<[IcBatchChannel] | []> {
    const channel = this.channels.get(channelId.toLowerCase());
    if (channel === undefined) {
      return [];
    }
    const result: [IcBatchChannel] = [cloneIc(channel)];
    return result;
  }

  async batch_channel_count(): Promise<bigint> {
    const nextCount = this.reportedCounts.shift();
    if (nextCount !== undefined) {
      return nextCount;
    }
    return this.reportedCount ?? BigInt(this.channels.size);
  }

  async batch_channels(limit: [bigint] | []): Promise<IcBatchChannel[]> {
    this.listCalls += 1;
    this.lastListLimit = limit;
    if (this.forceEmptyList) {
      return [];
    }
    if (this.forcedList !== undefined) {
      return this.forcedList.map(cloneIc);
    }
    const max = limit[0] === undefined ? Number.MAX_SAFE_INTEGER : Number(limit[0]);
    return Array.from(this.channels.values()).slice(0, max).map(cloneIc);
  }

  async batch_update_channel(
    channelId: string,
    expectedRevision: [bigint] | [],
    update: IcBatchChannelUpdate
  ): Promise<IcBatchChannelUpdateResult> {
    this.updateCalls += 1;
    if (this.forcedUpdateResult !== undefined) {
      return this.forcedUpdateResult;
    }
    const key = channelId.toLowerCase();
    const current = this.channels.get(key);
    const currentRevision = current?.revision;

    if (this.conflictChannel !== undefined) {
      const conflict = this.conflictChannel;
      this.conflictChannel = undefined;
      this.channels.set(key, cloneIc(conflict));
      return {
        status: "conflict",
        channel: [cloneIc(conflict)],
        current_revision: [conflict.revision],
        message: ["revision conflict"]
      };
    }

    const expected = expectedRevision[0];
    if (expected !== currentRevision) {
      return {
        status: "conflict",
        channel: current === undefined ? [] : [cloneIc(current)],
        current_revision: currentRevision === undefined ? [] : [currentRevision],
        message: ["revision conflict"]
      };
    }

    const updateChannel = update.channel[0];
    if (updateChannel === undefined) {
      if (current === undefined) {
        return { status: "unchanged", channel: [], current_revision: [], message: [] };
      }
      this.channels.delete(key);
      return { status: "deleted", channel: [], current_revision: [], message: [] };
    }

    const next = cloneIc(updateChannel);
    next.revision = (currentRevision ?? 0n) + 1n;
    this.channels.set(key, next);
    return { status: "updated", channel: [cloneIc(next)], current_revision: [next.revision], message: [] };
  }
}

function icChannel(channelId: string, revision: number, charged: string): IcBatchChannel {
  return {
    channel_id: channelId,
    channel_config: {
      payer: "0x3000000000000000000000000000000000000402",
      payer_authorizer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
      receiver: "0x1000000000000000000000000000000000000402",
      receiver_authorizer: "0x2000000000000000000000000000000000000402",
      token: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      withdraw_delay: 900n,
      salt: hex("0x" + "33".repeat(32))
    },
    charged_cumulative_amount: charged,
    signed_max_claimable: charged,
    signature: hex("0x" + "11".repeat(65)),
    balance: "0",
    total_claimed: "0",
    withdraw_requested_at: 0n,
    refund_nonce: "0",
    onchain_synced_at: [],
    last_request_timestamp: 1n,
    pending_request: [],
    revision: BigInt(revision)
  };
}

function livePending(signedMaxClaimable: string): IcBatchChannel["pending_request"] {
  return [{
    pending_id: `request-${signedMaxClaimable}`,
    signed_max_claimable: signedMaxClaimable,
    expires_at: BigInt(Date.now() + 60_000)
  }];
}

function fromIcFixture(channel: IcBatchChannel): BatchChannel {
  const pending = channel.pending_request[0];
  const out: BatchChannel = {
    balance: channel.balance,
    chargedCumulativeAmount: channel.charged_cumulative_amount,
    channelConfig: {
      payer: channel.channel_config.payer,
      payerAuthorizer: channel.channel_config.payer_authorizer,
      receiver: channel.channel_config.receiver,
      receiverAuthorizer: channel.channel_config.receiver_authorizer,
      salt: channel.channel_config.salt,
      token: channel.channel_config.token,
      withdrawDelay: Number(channel.channel_config.withdraw_delay)
    },
    channelId: hex(channel.channel_id),
    lastRequestTimestamp: Number(channel.last_request_timestamp),
    refundNonce: Number(channel.refund_nonce),
    signature: channel.signature,
    signedMaxClaimable: channel.signed_max_claimable,
    totalClaimed: channel.total_claimed,
    withdrawRequestedAt: Number(channel.withdraw_requested_at)
  };
  if (pending !== undefined) {
    out.pendingRequest = {
      expiresAt: Number(pending.expires_at),
      pendingId: pending.pending_id,
      signedMaxClaimable: pending.signed_max_claimable
    };
  }
  return out;
}

function omitPendingRequest(channel: BatchChannel): BatchChannel {
  const next = { ...channel };
  delete next.pendingRequest;
  return next;
}

function officialChannelId(channel: IcBatchChannel): string {
  return computeChannelId({
    payer: channel.channel_config.payer,
    payerAuthorizer: channel.channel_config.payer_authorizer,
    receiver: channel.channel_config.receiver,
    receiverAuthorizer: channel.channel_config.receiver_authorizer,
    salt: channel.channel_config.salt,
    token: channel.channel_config.token,
    withdrawDelay: Number(channel.channel_config.withdraw_delay)
  }, "eip155:137");
}

function fakeFacilitator(settledPayloads: PaymentPayload[]): FacilitatorClient {
  return {
    async verify(
      _paymentPayload: PaymentPayload,
      _paymentRequirements: PaymentRequirements
    ): Promise<VerifyResponse> {
      return { isValid: true };
    },
    async settle(
      paymentPayload: PaymentPayload,
      _paymentRequirements: PaymentRequirements
    ): Promise<SettleResponse> {
      settledPayloads.push(paymentPayload);
      return {
        amount: "100",
        network: "eip155:137",
        success: true,
        transaction: "0x" + "ab".repeat(32)
      };
    },
    async getSupported(): Promise<SupportedResponse> {
      return { extensions: [], kinds: [], signers: {} };
    }
  };
}

function cloneIc(channel: IcBatchChannel): IcBatchChannel {
  const out: IcBatchChannel = {
    channel_id: channel.channel_id,
    channel_config: { ...channel.channel_config },
    charged_cumulative_amount: channel.charged_cumulative_amount,
    signed_max_claimable: channel.signed_max_claimable,
    signature: channel.signature,
    balance: channel.balance,
    total_claimed: channel.total_claimed,
    withdraw_requested_at: channel.withdraw_requested_at,
    refund_nonce: channel.refund_nonce,
    onchain_synced_at: [],
    last_request_timestamp: channel.last_request_timestamp,
    pending_request: [],
    revision: channel.revision
  };
  out.onchain_synced_at = channel.onchain_synced_at[0] === undefined ? [] : [channel.onchain_synced_at[0]];
  out.pending_request = channel.pending_request[0] === undefined ? [] : [{ ...channel.pending_request[0] }];
  return out;
}

function hex(value: string): HexString {
  if (!isHexString(value)) {
    throw new Error("fixture hex must start with 0x");
  }
  return value;
}

function uppercaseHex(value: string): HexString {
  return hex(`0x${value.slice(2).toUpperCase()}`);
}

function isHexString(value: string): value is HexString {
  return value.startsWith("0x");
}

function acceptsChannelStorage(storage: {
  updateChannel(
    channelId: string,
    update: (current: BatchChannel | undefined) => BatchChannel | undefined
  ): Promise<{ channel: BatchChannel | undefined; status: "updated" | "unchanged" | "deleted" }>;
}): void {
  expect(storage).toBeDefined();
}

function acceptsOfficialChannelStorage(storage: OfficialChannelStorage): void {
  expect(storage).toBeDefined();
}

function batchPaymentRequirements(): PaymentRequirements {
  return {
    amount: "25",
    asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
    extra: {
      assetTransferMethod: "eip3009",
      name: "JPYC",
      receiverAuthorizer: "0x2000000000000000000000000000000000000402",
      version: "1",
      withdrawDelay: 900
    },
    maxTimeoutSeconds: 60,
    network: "eip155:137",
    payTo: "0x1000000000000000000000000000000000000402",
    scheme: "batch-settlement"
  };
}

function batchDepositPaymentPayload(
  channelId: string,
  accepted: PaymentRequirements,
  options: { maxClaimableAmount?: string } = {}
): PaymentPayload {
  const channelConfig: Record<string, unknown> = {
    payer: "0x3000000000000000000000000000000000000402",
    payerAuthorizer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
    receiver: "0x1000000000000000000000000000000000000402",
    receiverAuthorizer: "0x2000000000000000000000000000000000000402",
    token: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
    withdrawDelay: 900,
    salt: "0x" + "33".repeat(32)
  };
  return {
    accepted,
    payload: {
      channelConfig,
      deposit: {
        amount: "100",
        authorization: {
          erc3009Authorization: {
            salt: "0x" + "44".repeat(32),
            signature: "0x" + "22".repeat(65),
            validAfter: "0",
            validBefore: "9999999999"
          }
        }
      },
      type: "deposit",
      voucher: {
        channelId,
        maxClaimableAmount: options.maxClaimableAmount ?? "125",
        signature: "0x" + "11".repeat(65)
      }
    },
    x402Version: 2
  };
}
