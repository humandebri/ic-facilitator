// src/icBatchChannelStorage.ts: x402 batch-settlement の ChannelStorage を ICP canister CAS API で実装する。
import type {
  Channel as X402BatchChannel,
  ChannelStorage as X402BatchChannelStorage,
  ChannelUpdateResult as X402BatchChannelUpdateResult
} from "@x402/evm/batch-settlement/server";

export type HexString = `0x${string}`;
export type CandidOpt<T> = [] | [T];

export type BatchChannel = X402BatchChannel;
export type BatchChannelUpdateResult = X402BatchChannelUpdateResult;
export type BatchChannelStorage = X402BatchChannelStorage;

export type IcBatchChannel = {
  channel_id: string;
  signature: HexString;
  balance: string;
  channel_config: {
    payer: HexString;
    payer_authorizer: HexString;
    receiver: HexString;
    receiver_authorizer: HexString;
    token: HexString;
    withdraw_delay: bigint;
    salt: HexString;
  };
  charged_cumulative_amount: string;
  signed_max_claimable: string;
  total_claimed: string;
  withdraw_requested_at: bigint;
  refund_nonce: string;
  onchain_synced_at: CandidOpt<bigint>;
  last_request_timestamp: bigint;
  pending_request: CandidOpt<{
    pending_id: string;
    signed_max_claimable: string;
    expires_at: bigint;
  }>;
  revision: bigint;
};

export type IcBatchChannelUpdate = {
  channel: CandidOpt<IcBatchChannel>;
};

export type IcBatchChannelUpdateResult = {
  status: string;
  channel: CandidOpt<IcBatchChannel>;
  current_revision: CandidOpt<bigint>;
  message: CandidOpt<string>;
};

export type IcBatchChannelStorageClient = {
  batch_channel(channelId: string): Promise<[IcBatchChannel] | []>;
  batch_channel_count(): Promise<bigint>;
  batch_channels(limit: [bigint] | []): Promise<IcBatchChannel[]>;
  batch_update_channel(
    channelId: string,
    expectedRevision: [bigint] | [],
    update: IcBatchChannelUpdate
  ): Promise<IcBatchChannelUpdateResult>;
};

export type IcBatchChannelStorageOptions = {
  maxRetries?: number;
  listLimit?: number;
};

const DEFAULT_MAX_RETRIES = 5;
const DEFAULT_LIST_LIMIT = 1000;
const MAX_LIST_LIMIT = 1000;
const MAX_BATCH_STRING_BYTES = 512;
const UTF8_ENCODER = new TextEncoder();
const UINT128_MAX = (1n << 128n) - 1n;
const MIN_BATCH_WITHDRAW_DELAY_SECONDS = 900;
const MAX_BATCH_WITHDRAW_DELAY_SECONDS = 2_592_000;

export class IcBatchChannelStorage implements X402BatchChannelStorage {
  private readonly maxRetries: number;
  private readonly listLimit: number;

  constructor(
    private readonly client: IcBatchChannelStorageClient,
    options: IcBatchChannelStorageOptions = {}
  ) {
    this.maxRetries = nonNegativeSafeInteger(options.maxRetries ?? DEFAULT_MAX_RETRIES, "maxRetries");
    this.listLimit = boundedPositiveSafeInteger(options.listLimit ?? DEFAULT_LIST_LIMIT, "listLimit", MAX_LIST_LIMIT);
  }

  async get(channelId: string): Promise<BatchChannel | undefined> {
    const checkedChannelId = requireChannelId(channelId);
    const result = await this.client.batch_channel(checkedChannelId);
    const channel = result[0];
    if (channel === undefined) {
      return undefined;
    }
    return requireMatchingChannelId(fromIcChannel(channel), checkedChannelId);
  }

  async list(): Promise<BatchChannel[]> {
    let lastMismatch = "";
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const count = await this.client.batch_channel_count();
      if (count > BigInt(this.listLimit)) {
        throw new Error(`batch channel count ${count} exceeds listLimit ${this.listLimit}`);
      }
      const channels = await this.client.batch_channels([BigInt(this.listLimit)]);
      if (BigInt(channels.length) !== count) {
        lastMismatch = `batch channel list returned ${channels.length} records for count ${count}`;
        continue;
      }
      const decoded = channels.map(fromIcChannel);
      const channelIds = new Set(decoded.map((channel) => channel.channelId.toLowerCase()));
      if (channelIds.size !== decoded.length) {
        throw new Error("batch channel list returned duplicate channel ids");
      }
      return decoded;
    }

    throw new Error(lastMismatch || "batch channel list did not stabilize");
  }

  async updateChannel(
    channelId: string,
    update: (current: BatchChannel | undefined) => BatchChannel | undefined
  ): Promise<BatchChannelUpdateResult> {
    const checkedChannelId = requireChannelId(channelId);
    for (let attempt = 0; attempt <= this.maxRetries; attempt += 1) {
      const currentIc = (await this.client.batch_channel(checkedChannelId))[0];
      const current = currentIc === undefined ? undefined : requireMatchingChannelId(fromIcChannel(currentIc), checkedChannelId);
      const snapshot = current === undefined ? undefined : cloneChannel(current);
      const next = update(snapshot);

      if (next === snapshot && (current === undefined || channelsEqual(snapshot, current))) {
        return { channel: current, status: "unchanged" };
      }
      if (next === undefined) {
        requireNoLivePendingBeforeDelete(current);
      }

      const result = await this.client.batch_update_channel(
        checkedChannelId,
        currentIc === undefined ? [] : [currentIc.revision],
        {
          channel: next === undefined
            ? []
            : [toIcChannel(
              requireMonotonicChannelUpdate(current, requireMatchingChannelId(next, checkedChannelId)),
              currentIc?.revision ?? 0n
            )]
        }
      );

      if (result.status === "conflict") {
        continue;
      }
      if (result.status === "invalid") {
        throw new Error(optionalValue(result.message) ?? "invalid batch channel update");
      }
      if (result.status === "unchanged") {
        return { channel: current, status: "unchanged" };
      }
      if (result.status === "deleted") {
        return { channel: undefined, status: currentIc === undefined ? "unchanged" : "deleted" };
      }
      if (result.status !== "updated") {
        throw new Error(`unknown batch channel update status: ${result.status}`);
      }
      const updated = optionalValue(result.channel);
      if (updated === undefined) {
        throw new Error("batch channel update status updated without channel");
      }
      return {
        channel: requireMatchingChannelId(fromIcChannel(updated), checkedChannelId),
        status: "updated"
      };
    }

    throw new Error("batch channel update conflict");
  }
}

function fromIcChannel(channel: IcBatchChannel): BatchChannel {
  const chargedCumulativeAmount = requireUint128DecimalString(channel.charged_cumulative_amount, "chargedCumulativeAmount");
  const signedMaxClaimable = requireUint128DecimalString(channel.signed_max_claimable, "signedMaxClaimable");
  const totalClaimed = requireUint128DecimalString(channel.total_claimed, "totalClaimed");
  const balance = requireUint128DecimalString(channel.balance, "balance");
  requireChannelAmountBounds(chargedCumulativeAmount, signedMaxClaimable, totalClaimed, balance);
  const out: BatchChannel = {
    channelId: requireChannelId(channel.channel_id),
    channelConfig: {
      payer: requireNonZeroAddress(channel.channel_config.payer, "payer"),
      payerAuthorizer: requireNonZeroAddress(channel.channel_config.payer_authorizer, "payerAuthorizer"),
      receiver: requireNonZeroAddress(channel.channel_config.receiver, "receiver"),
      receiverAuthorizer: requireNonZeroAddress(channel.channel_config.receiver_authorizer, "receiverAuthorizer"),
      token: requireNonZeroAddress(channel.channel_config.token, "token"),
      withdrawDelay: requireBatchWithdrawDelay(safeNumber(channel.channel_config.withdraw_delay, "withdrawDelay")),
      salt: requireHexBytes(channel.channel_config.salt, "salt", 32)
    },
    chargedCumulativeAmount,
    signedMaxClaimable,
    signature: requireHexBytes(channel.signature, "signature", 65),
    balance,
    totalClaimed,
    withdrawRequestedAt: safeEpochMs(channel.withdraw_requested_at, "withdrawRequestedAt"),
    refundNonce: safeDecimalNumber(channel.refund_nonce, "refundNonce"),
    lastRequestTimestamp: safeEpochMs(channel.last_request_timestamp, "lastRequestTimestamp")
  };
  const onchainSyncedAt = optionalValue(channel.onchain_synced_at);
  if (onchainSyncedAt !== undefined) {
    out.onchainSyncedAt = safeEpochMs(onchainSyncedAt, "onchainSyncedAt");
  }
  const pendingRequest = optionalValue(channel.pending_request);
  if (pendingRequest !== undefined) {
    out.pendingRequest = {
      pendingId: requireLimitedNonEmptyString(pendingRequest.pending_id, "pendingRequest.pendingId"),
      signedMaxClaimable: requirePendingSignedMaxClaimable(pendingRequest.signed_max_claimable, chargedCumulativeAmount),
      expiresAt: safePositiveEpochMs(pendingRequest.expires_at, "pendingRequest.expiresAt")
    };
  }
  return out;
}

function toIcChannel(channel: BatchChannel, revision: bigint): IcBatchChannel {
  const chargedCumulativeAmount = requireUint128DecimalString(channel.chargedCumulativeAmount, "chargedCumulativeAmount");
  const signedMaxClaimable = requireUint128DecimalString(channel.signedMaxClaimable, "signedMaxClaimable");
  const totalClaimed = requireUint128DecimalString(channel.totalClaimed, "totalClaimed");
  const balance = requireUint128DecimalString(channel.balance, "balance");
  requireChannelAmountBounds(chargedCumulativeAmount, signedMaxClaimable, totalClaimed, balance);
  const out: IcBatchChannel = {
    channel_id: requireChannelId(channel.channelId),
    channel_config: {
      payer: requireNonZeroAddress(channel.channelConfig.payer, "payer"),
      payer_authorizer: requireNonZeroAddress(channel.channelConfig.payerAuthorizer, "payerAuthorizer"),
      receiver: requireNonZeroAddress(channel.channelConfig.receiver, "receiver"),
      receiver_authorizer: requireNonZeroAddress(channel.channelConfig.receiverAuthorizer, "receiverAuthorizer"),
      token: requireNonZeroAddress(channel.channelConfig.token, "token"),
      withdraw_delay: BigInt(requireBatchWithdrawDelay(nonNegativeSafeInteger(channel.channelConfig.withdrawDelay, "withdrawDelay"))),
      salt: requireHexBytes(channel.channelConfig.salt, "salt", 32)
    },
    charged_cumulative_amount: chargedCumulativeAmount,
    signed_max_claimable: signedMaxClaimable,
    signature: requireHexBytes(channel.signature, "signature", 65),
    balance,
    total_claimed: totalClaimed,
    withdraw_requested_at: BigInt(nonNegativeSafeInteger(channel.withdrawRequestedAt, "withdrawRequestedAtMs")),
    refund_nonce: String(nonNegativeSafeInteger(channel.refundNonce, "refundNonce")),
    onchain_synced_at: [],
    last_request_timestamp: BigInt(nonNegativeSafeInteger(channel.lastRequestTimestamp, "lastRequestTimestampMs")),
    pending_request: [],
    revision
  };
  if (channel.onchainSyncedAt !== undefined) {
    out.onchain_synced_at = [BigInt(nonNegativeSafeInteger(channel.onchainSyncedAt, "onchainSyncedAtMs"))];
  }
  if (channel.pendingRequest !== undefined) {
    out.pending_request = [{
      pending_id: requireLimitedNonEmptyString(channel.pendingRequest.pendingId, "pendingRequest.pendingId"),
      signed_max_claimable: requirePendingSignedMaxClaimable(channel.pendingRequest.signedMaxClaimable, chargedCumulativeAmount),
      expires_at: BigInt(positiveSafeInteger(channel.pendingRequest.expiresAt, "pendingRequest.expiresAtMs"))
    }];
  }
  return out;
}

function cloneChannel(channel: BatchChannel): BatchChannel {
  return fromIcChannel(toIcChannel(channel, 0n));
}

function channelsEqual(left: BatchChannel | undefined, right: BatchChannel | undefined): boolean {
  if (left === undefined || right === undefined) {
    return left === right;
  }
  return JSON.stringify(toJsonComparableChannel(left)) === JSON.stringify(toJsonComparableChannel(right));
}

function toJsonComparableChannel(channel: BatchChannel): Record<string, unknown> {
  return {
    balance: channel.balance,
    chargedCumulativeAmount: channel.chargedCumulativeAmount,
    channelConfig: {
      payer: channel.channelConfig.payer,
      payerAuthorizer: channel.channelConfig.payerAuthorizer,
      receiver: channel.channelConfig.receiver,
      receiverAuthorizer: channel.channelConfig.receiverAuthorizer,
      salt: channel.channelConfig.salt,
      token: channel.channelConfig.token,
      withdrawDelay: channel.channelConfig.withdrawDelay
    },
    channelId: channel.channelId,
    lastRequestTimestamp: channel.lastRequestTimestamp,
    onchainSyncedAt: channel.onchainSyncedAt,
    pendingRequest: channel.pendingRequest === undefined ? undefined : {
      expiresAt: channel.pendingRequest.expiresAt,
      pendingId: channel.pendingRequest.pendingId,
      signedMaxClaimable: channel.pendingRequest.signedMaxClaimable
    },
    refundNonce: channel.refundNonce,
    signature: channel.signature,
    signedMaxClaimable: channel.signedMaxClaimable,
    totalClaimed: channel.totalClaimed,
    withdrawRequestedAt: channel.withdrawRequestedAt
  };
}

function requireMatchingChannelId(channel: BatchChannel, expected: HexString): BatchChannel {
  if (channel.channelId.toLowerCase() !== expected.toLowerCase()) {
    throw new Error("channelId does not match requested channel id");
  }
  return channel;
}

function requireMonotonicChannelUpdate(current: BatchChannel | undefined, next: BatchChannel): BatchChannel {
  if (current === undefined) {
    requireInitialChannelCreate(next);
    return next;
  }
  requireStableChannelConfig(current, next);
  requirePendingChargeCommit(current, next);
  requireStablePendingRequest(current, next);
  requireMonotonicDecimal("chargedCumulativeAmount", current.chargedCumulativeAmount, next.chargedCumulativeAmount);
  requireMonotonicDecimal("signedMaxClaimable", current.signedMaxClaimable, next.signedMaxClaimable);
  requireMonotonicDecimal("totalClaimed", current.totalClaimed, next.totalClaimed);
  requireMonotonicDecimal("refundNonce", String(current.refundNonce), String(next.refundNonce));
  requireMonotonicNumber("lastRequestTimestampMs", current.lastRequestTimestamp, next.lastRequestTimestamp);
  return next;
}

function requireStableChannelConfig(current: BatchChannel, next: BatchChannel): void {
  if (
    !sameHexValue(current.channelConfig.payer, next.channelConfig.payer) ||
    !sameHexValue(current.channelConfig.payerAuthorizer, next.channelConfig.payerAuthorizer) ||
    !sameHexValue(current.channelConfig.receiver, next.channelConfig.receiver) ||
    !sameHexValue(current.channelConfig.receiverAuthorizer, next.channelConfig.receiverAuthorizer) ||
    !sameHexValue(current.channelConfig.token, next.channelConfig.token) ||
    !sameHexValue(current.channelConfig.salt, next.channelConfig.salt) ||
    current.channelConfig.withdrawDelay !== next.channelConfig.withdrawDelay
  ) {
    throw new Error("channelConfig must not change for an existing batch channel");
  }
}

function sameHexValue(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function requireInitialChannelCreate(next: BatchChannel): void {
  const pending = next.pendingRequest;
  if (pending === undefined) {
    throw new Error("batch channel create requires pendingRequest");
  }
  if (pending.expiresAt <= Date.now()) {
    throw new Error("batch channel create requires live pendingRequest");
  }
  if (next.signedMaxClaimable !== pending.signedMaxClaimable) {
    throw new Error("signedMaxClaimable must match pendingRequest.signedMaxClaimable when creating");
  }
  if (next.chargedCumulativeAmount !== "0") {
    throw new Error("batch channel create requires chargedCumulativeAmount 0");
  }
  if (next.balance !== "0") {
    throw new Error("batch channel create requires balance 0");
  }
  if (next.totalClaimed !== "0") {
    throw new Error("batch channel create requires totalClaimed 0");
  }
  if (next.refundNonce !== 0) {
    throw new Error("batch channel create requires refundNonce 0");
  }
  if (next.withdrawRequestedAt !== 0) {
    throw new Error("batch channel create requires withdrawRequestedAt 0");
  }
  if (next.onchainSyncedAt !== undefined) {
    throw new Error("batch channel create requires onchainSyncedAt empty");
  }
}

function requireStablePendingRequest(current: BatchChannel, next: BatchChannel): void {
  const currentPending = current.pendingRequest;
  const nextPending = next.pendingRequest;
  if (nextPending === undefined) {
    return;
  }
  if (currentPending === undefined || currentPending.pendingId !== nextPending.pendingId) {
    return;
  }
  if (
    currentPending.signedMaxClaimable !== nextPending.signedMaxClaimable ||
    currentPending.expiresAt !== nextPending.expiresAt ||
    current.signedMaxClaimable !== next.signedMaxClaimable
  ) {
    throw new Error("batch channel pendingRequest must not change for the same pendingId");
  }
}

function requirePendingChargeCommit(current: BatchChannel, next: BatchChannel): void {
  const currentCharged = BigInt(requireDecimalString(current.chargedCumulativeAmount, "chargedCumulativeAmount"));
  const nextCharged = BigInt(requireDecimalString(next.chargedCumulativeAmount, "chargedCumulativeAmount"));
  if (nextCharged <= currentCharged) {
    return;
  }
  const pending = current.pendingRequest;
  if (pending === undefined) {
    throw new Error("chargedCumulativeAmount increase requires pendingRequest");
  }
  if (pending.expiresAt <= Date.now()) {
    throw new Error("chargedCumulativeAmount increase requires live pendingRequest");
  }
  if (next.pendingRequest !== undefined) {
    throw new Error("chargedCumulativeAmount increase must consume pendingRequest");
  }
  if (next.signedMaxClaimable !== pending.signedMaxClaimable) {
    throw new Error("signedMaxClaimable must match pendingRequest.signedMaxClaimable when charge increases");
  }
  if (next.chargedCumulativeAmount !== pending.signedMaxClaimable) {
    throw new Error("chargedCumulativeAmount must match pendingRequest.signedMaxClaimable when charge increases");
  }
}

function requireNoLivePendingBeforeDelete(current: BatchChannel | undefined): void {
  if (
    current?.pendingRequest !== undefined &&
    current.pendingRequest.expiresAt > Date.now() &&
    !isPendingOnlyProvisionalChannel(current)
  ) {
    throw new Error("batch channel delete requires no live pendingRequest");
  }
}

function isPendingOnlyProvisionalChannel(channel: BatchChannel): boolean {
  return channel.pendingRequest !== undefined &&
    channel.pendingRequest.signedMaxClaimable === channel.signedMaxClaimable &&
    channel.chargedCumulativeAmount === "0" &&
    channel.balance === "0" &&
    channel.totalClaimed === "0" &&
    channel.refundNonce === 0 &&
    channel.withdrawRequestedAt === 0 &&
    channel.onchainSyncedAt === undefined;
}

function requireMonotonicDecimal(label: string, current: string, next: string): void {
  const currentValue = BigInt(requireDecimalString(current, label));
  const nextValue = BigInt(requireDecimalString(next, label));
  if (nextValue < currentValue) {
    throw new Error(`${label} must not decrease`);
  }
}

function requireMonotonicNumber(label: string, current: number, next: number): void {
  const currentValue = nonNegativeSafeInteger(current, label);
  const nextValue = nonNegativeSafeInteger(next, label);
  if (nextValue < currentValue) {
    throw new Error(`${label} must not decrease`);
  }
}

function requireChannelId(value: string): HexString {
  return requireHexBytes(value, "channelId", 32);
}

function requireAddress(value: string, label: string): HexString {
  return requireHexBytes(value, label, 20);
}

function requireNonZeroAddress(value: string, label: string): HexString {
  const address = requireAddress(value, label);
  if (/^0x0{40}$/i.test(address)) {
    throw new Error(`${label} must not be zero address`);
  }
  return address;
}

function requireHexBytes(value: string, label: string, bytes: number): HexString {
  if (!isHexString(value) || value.length !== 2 + bytes * 2) {
    throw new Error(`${label} must be a ${bytes}-byte 0x-prefixed hex string`);
  }
  return value;
}

function safeNumber(value: bigint, label: string): number {
  if (value < 0n) {
    throw new Error(`${label} must be non-negative`);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} exceeds MAX_SAFE_INTEGER`);
  }
  return Number(value);
}

function safePositiveNumber(value: bigint, label: string): number {
  const checked = safeNumber(value, label);
  if (checked <= 0) {
    throw new Error(`${label} must be positive`);
  }
  return checked;
}

function safeEpochMs(value: bigint, label: string): number {
  return safeNumber(value, `${label}Ms`);
}

function safePositiveEpochMs(value: bigint, label: string): number {
  return safePositiveNumber(value, `${label}Ms`);
}

function safeDecimalNumber(value: string, label: string): number {
  requireDecimalString(value, label);
  return safeNumber(BigInt(value), label);
}

function requireBatchWithdrawDelay(value: number): number {
  if (value < MIN_BATCH_WITHDRAW_DELAY_SECONDS || value > MAX_BATCH_WITHDRAW_DELAY_SECONDS) {
    throw new Error(`withdrawDelay must be between ${MIN_BATCH_WITHDRAW_DELAY_SECONDS} and ${MAX_BATCH_WITHDRAW_DELAY_SECONDS}`);
  }
  return value;
}

function requireDecimalString(value: string, label: string): string {
  if (utf8ByteLength(value) > MAX_BATCH_STRING_BYTES) {
    throw new Error(`${label} exceeds ${MAX_BATCH_STRING_BYTES} bytes`);
  }
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`${label} must be a decimal integer string`);
  }
  return value;
}

function requireUint128DecimalString(value: string, label: string): string {
  const checked = requireDecimalString(value, label);
  if (BigInt(checked) > UINT128_MAX) {
    throw new Error(`${label} exceeds uint128`);
  }
  return checked;
}

function requireLimitedNonEmptyString(value: string, label: string): string {
  if (utf8ByteLength(value) > MAX_BATCH_STRING_BYTES) {
    throw new Error(`${label} exceeds ${MAX_BATCH_STRING_BYTES} bytes`);
  }
  if (value.trim() === "") {
    throw new Error(`${label} must not be empty`);
  }
  return value;
}

function requirePendingSignedMaxClaimable(value: string, chargedCumulativeAmount: string): string {
  const checked = requireUint128DecimalString(value, "pendingRequest.signedMaxClaimable");
  if (BigInt(checked) < BigInt(chargedCumulativeAmount)) {
    throw new Error("pendingRequest.signedMaxClaimable must be at least chargedCumulativeAmount");
  }
  return checked;
}

function requireChannelAmountBounds(chargedCumulativeAmount: string, signedMaxClaimable: string, totalClaimed: string, balance: string): void {
  const signed = BigInt(signedMaxClaimable);
  if (BigInt(chargedCumulativeAmount) > signed) {
    throw new Error("chargedCumulativeAmount exceeds signedMaxClaimable");
  }
  if (BigInt(totalClaimed) > signed) {
    throw new Error("totalClaimed exceeds signedMaxClaimable");
  }
  if (BigInt(totalClaimed) > BigInt(balance)) {
    throw new Error("totalClaimed exceeds balance");
  }
}

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function boundedPositiveSafeInteger(value: number, label: string, max: number): number {
  const checked = positiveSafeInteger(value, label);
  if (checked > max) {
    throw new Error(`${label} must be less than or equal to ${max}`);
  }
  return checked;
}

function nonNegativeSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function optionalValue<T>(value: CandidOpt<T>): T | undefined {
  return value[0];
}

function isHexString(value: string): value is HexString {
  return /^0x[0-9a-fA-F]*$/.test(value);
}

function utf8ByteLength(value: string): number {
  return UTF8_ENCODER.encode(value).length;
}
