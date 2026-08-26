// scripts/batch_settlement_receipt.ts: x402 batch-settlement tx の receipt と post-state を確認する。
import { pathToFileURL } from "node:url";

import { BATCH_SETTLEMENT_ADDRESS } from "@x402/evm";
import { concatHex, createPublicClient, decodeEventLog, http, keccak256, parseAbi, toHex } from "viem";
import type { Address, Hex, TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";

import { loadDotenv } from "./env_file";
import { normalizePolygonRpcUrl } from "./rpc_url";

const DEFAULT_JPYC_POLYGON_ADDRESS: Address = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";

const BATCH_SETTLEMENT_ABI = parseAbi([
  "event Settled(address indexed receiver,address indexed token,address indexed sender,uint128 amount)",
  "function channels(bytes32 channelId) view returns (uint128 balance,uint128 totalClaimed)",
  "function claimWithSignature((((address,address,address,address,address,uint40,bytes32),uint128),bytes,uint128)[],bytes)",
  "function deposit((address,address,address,address,address,uint40,bytes32),uint128,address,bytes)",
  "function multicall(bytes[])",
  "function refundWithSignature((address,address,address,address,address,uint40,bytes32),uint128,uint256,bytes)",
  "function refundNonce(bytes32 channelId) view returns (uint256)",
  "function receivers(address receiver,address token) view returns (uint128 totalClaimed,uint128 totalSettled)",
  "function settle(address,address)"
]);

export type BatchSettlementAction = "claim" | "deposit" | "refund" | "settle";
export const BATCH_SETTLEMENT_ACTIONS: readonly BatchSettlementAction[] = ["deposit", "claim", "settle", "refund"];
const BATCH_FUNCTION_SELECTORS: Record<BatchSettlementAction | "multicall", Hex> = {
  claim: "0xe43ce1f2",
  deposit: "0x140f1e75",
  multicall: "0xac9650d8",
  refund: "0xb77433e9",
  settle: "0x9db32a8f"
};
const BATCH_DOMAIN_NAME = "x402 Batch Settlement";
const BATCH_DOMAIN_VERSION = "1";
const BATCH_CHAIN_ID = 137n;
const MIN_BATCH_WITHDRAW_DELAY_SECONDS = 900n;
const MAX_BATCH_WITHDRAW_DELAY_SECONDS = 2_592_000n;
const DEFAULT_MIN_CONFIRMATIONS = 3;
const EIP712_DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const CHANNEL_CONFIG_TYPE = "ChannelConfig(address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt)";

type DecodedBatchChannelConfig = {
  readonly payer: Address;
  readonly payerAuthorizer: Address;
  readonly receiver: Address;
  readonly receiverAuthorizer: Address;
  readonly salt: Hex;
  readonly token: Address;
  readonly withdrawDelay: bigint;
};

type DecodedBatchClaim = {
  readonly channelId: Hex;
  readonly config: DecodedBatchChannelConfig;
  readonly totalClaimed: bigint;
};

type BatchTransactionInputProof = {
  readonly calldataMinRefundNonce?: bigint;
  readonly calldataMinTotalClaimed?: bigint;
  readonly selector: Hex;
};

export type BatchSettlementReceiptReader = {
  readonly getBatchChannel: (contract: Address, channelId: Hex) => Promise<readonly [bigint, bigint]>;
  readonly getBatchReceiver: (contract: Address, receiver: Address, token: Address) => Promise<readonly [bigint, bigint]>;
  readonly getBatchRefundNonce: (contract: Address, channelId: Hex) => Promise<bigint>;
  readonly getBlockNumber: () => Promise<bigint>;
  readonly getTransaction: (args: { readonly hash: Hex }) => Promise<BatchSettlementTransaction>;
  readonly getTransactionReceipt: (args: { readonly hash: Hex }) => Promise<TransactionReceipt>;
};

export type BatchSettlementTransaction = {
  readonly from: Hex;
  readonly hash: Hex;
  readonly input: Hex;
  readonly to: Hex | null;
};

export type BatchSettlementReceiptOptions = {
  readonly action: BatchSettlementAction;
  readonly channelId?: Hex;
  readonly contract?: Address;
  readonly expectedDepositAmount?: string;
  readonly expectedMinBalance?: string;
  readonly expectedMinRefundNonce?: string;
  readonly expectedFrom?: Address;
  readonly expectedReceiverAuthorizer?: Address;
  readonly expectedSettledAmount?: string;
  readonly expectedTotalClaimed?: string;
  readonly expectedWithdrawDelay?: bigint;
  readonly hash: Hex;
  readonly minConfirmations?: number;
  readonly reader?: BatchSettlementReceiptReader;
  readonly receiver?: Address;
  readonly rpcUrl?: string;
  readonly token?: Address;
};

export type BatchSettlementReceiptsOptions = {
  readonly env: NodeJS.ProcessEnv;
  readonly reader?: BatchSettlementReceiptReader;
};

export type BatchSettlementReceiptResult = {
  readonly action: BatchSettlementAction;
  readonly blockNumber: string;
  readonly confirmations: string;
  readonly contract: Address;
  readonly from: Hex;
  readonly gasUsed: string;
  readonly hash: Hex;
  readonly inputSelector: Hex;
  readonly status: "success";
  readonly to: Hex;
  readonly channelState?: {
    readonly balance: string;
    readonly channelId: Hex;
    readonly refundNonce?: string;
    readonly totalClaimed: string;
  };
  readonly receiverState?: {
    readonly receiver: Address;
    readonly settledAmount: string;
    readonly token: Address;
    readonly totalClaimed: string;
    readonly totalSettled: string;
  };
};

type BatchChannelStateResult = NonNullable<BatchSettlementReceiptResult["channelState"]>;
type BatchReceiverStateResult = NonNullable<BatchSettlementReceiptResult["receiverState"]>;

function readEnv(name: string): string | undefined {
  return process.env[name];
}

function readEnvFrom(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name];
}

function requireEnv(name: string): string {
  const value = readEnv(name);
  if (!value || value.trim() === "") {
    throw new Error(`missing required env: ${name}`);
  }
  return value;
}

function requireEnvFrom(env: NodeJS.ProcessEnv, name: string): string {
  const value = readEnvFrom(env, name);
  if (!value || value.trim() === "") {
    throw new Error(`missing required env: ${name}`);
  }
  return value;
}

function requirePositiveIntegerEnvFrom(env: NodeJS.ProcessEnv, name: string): string {
  const value = requireEnvFrom(env, name);
  parsePositiveInteger(value, name);
  return value;
}

function isTxHash(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isBytes32(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isAddress(value: string): value is Address {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isPrivateKey(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function normalizeAddress(value: string, name: string): Address {
  if (!isAddress(value) || /^0x0{40}$/i.test(value)) {
    throw new Error(`${name} must be a non-zero 0x-prefixed EVM address`);
  }
  return value;
}

function normalizeBatchSettlementContract(value: string, name: string): Address {
  const contract = normalizeAddress(value, name);
  if (!sameHex(contract, BATCH_SETTLEMENT_ADDRESS)) {
    throw new Error(`${name} must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${BATCH_SETTLEMENT_ADDRESS}`);
  }
  return contract;
}

function normalizeBytes32(value: string, name: string): Hex {
  if (!isBytes32(value)) {
    throw new Error(`${name} must be a 32-byte 0x-prefixed hex string`);
  }
  return value;
}

function parseTxHash(value: string): Hex {
  if (!isTxHash(value)) {
    throw new Error("batch settlement tx must be a 32-byte 0x-prefixed transaction hash");
  }
  return value;
}

function parseAction(value: string): BatchSettlementAction {
  if (value === "deposit" || value === "claim" || value === "settle" || value === "refund") {
    return value;
  }
  throw new Error("BATCH_SETTLEMENT_ACTION must be deposit, claim, settle, or refund");
}

function parsePositiveInteger(value: string, name: string): bigint {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer string`);
  }
  return BigInt(value);
}

function parseOptionalNonNegativeInteger(value: string | undefined, name: string): bigint | undefined {
  if (value === undefined || value.trim() === "") {
    return undefined;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be a non-negative integer string`);
  }
  return BigInt(value);
}

function parseOptionalPositiveInteger(value: string | undefined, name: string): bigint | undefined {
  if (value === undefined || value.trim() === "") {
    return undefined;
  }
  return parsePositiveInteger(value, name);
}

function parseMinConfirmations(value: string | undefined): number {
  if (value === undefined || value.trim() === "") {
    return DEFAULT_MIN_CONFIRMATIONS;
  }
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("SETTLE_MIN_CONFIRMATIONS must be a non-negative integer string");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error("SETTLE_MIN_CONFIRMATIONS is too large");
  }
  return parsed;
}

function expectedBatchReceiverAuthorizerFromEnv(env: NodeJS.ProcessEnv): Address {
  const privateKey = requireEnvFrom(env, "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  if (!isPrivateKey(privateKey)) {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return privateKeyToAccount(privateKey).address;
}

function expectedBatchWithdrawDelayFromEnv(env: NodeJS.ProcessEnv): bigint {
  const value = requireEnvFrom(env, "BATCH_WITHDRAW_DELAY_SECONDS");
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error("BATCH_WITHDRAW_DELAY_SECONDS must be a positive integer string");
  }
  const seconds = BigInt(value);
  if (seconds < MIN_BATCH_WITHDRAW_DELAY_SECONDS || seconds > MAX_BATCH_WITHDRAW_DELAY_SECONDS) {
    throw new Error(`BATCH_WITHDRAW_DELAY_SECONDS must be between ${MIN_BATCH_WITHDRAW_DELAY_SECONDS.toString()} and ${MAX_BATCH_WITHDRAW_DELAY_SECONDS.toString()}`);
  }
  return seconds;
}

function expectedBatchSettlementSenderFromEnv(env: NodeJS.ProcessEnv): Address {
  const privateKey = requireEnvFrom(env, "FACILITATOR_EVM_PRIVATE_KEY");
  if (!isPrivateKey(privateKey)) {
    throw new Error("FACILITATOR_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return privateKeyToAccount(privateKey).address;
}

function createReader(rpcUrl: string): BatchSettlementReceiptReader {
  const normalizedRpcUrl = normalizePolygonRpcUrl(rpcUrl, "POLYGON_RPC_URL");
  const client = createPublicClient({
    chain: polygon,
    transport: http(normalizedRpcUrl)
  });

  return {
    async getBatchChannel(contract, channelId) {
      return client.readContract({ address: contract, abi: BATCH_SETTLEMENT_ABI, functionName: "channels", args: [channelId] });
    },
    async getBatchReceiver(contract, receiver, token) {
      return client.readContract({ address: contract, abi: BATCH_SETTLEMENT_ABI, functionName: "receivers", args: [receiver, token] });
    },
    async getBatchRefundNonce(contract, channelId) {
      return client.readContract({ address: contract, abi: BATCH_SETTLEMENT_ABI, functionName: "refundNonce", args: [channelId] });
    },
    async getBlockNumber() {
      return client.getBlockNumber();
    },
    async getTransaction(args) {
      return client.getTransaction(args);
    },
    async getTransactionReceipt(args) {
      return client.getTransactionReceipt(args);
    }
  };
}

function inputSelector(input: Hex): Hex {
  if (!/^0x[0-9a-fA-F]{8}/.test(input)) {
    throw new Error("batch settlement tx input is missing function selector");
  }
  return `0x${input.slice(2, 10)}`;
}

function hasSelector(input: Hex, selector: Hex): boolean {
  return inputSelector(input).toLowerCase() === selector.toLowerCase();
}

function hexByteLength(value: Hex): bigint {
  return BigInt((value.length - 2) / 2);
}

function readWordHex(input: Hex, byteOffset: bigint, label: string): Hex {
  if (byteOffset < 0n || byteOffset + 32n > hexByteLength(input)) {
    throw new Error(`${label} is truncated`);
  }
  const start = 2 + Number(byteOffset * 2n);
  const end = start + 64;
  const value = `0x${input.slice(start, end)}`;
  if (!isBytes32(value)) {
    throw new Error(`${label} has invalid word`);
  }
  return value;
}

function readWord(input: Hex, byteOffset: bigint, label = "batch multicall calldata"): bigint {
  return BigInt(readWordHex(input, byteOffset, label));
}

function readAddress(input: Hex, byteOffset: bigint, label: string): Address {
  const word = readWordHex(input, byteOffset, label);
  if (!/^0{24}$/i.test(word.slice(2, 26))) {
    throw new Error(`${label} has non-zero address padding`);
  }
  const value = `0x${word.slice(26)}`;
  if (!isAddress(value)) {
    throw new Error(`${label} has invalid address word`);
  }
  return value;
}

function uint256Word(value: bigint): Hex {
  if (value < 0n) {
    throw new Error("uint256 word cannot be negative");
  }
  const hex = `0x${value.toString(16).padStart(64, "0")}`;
  if (!isBytes32(hex)) {
    throw new Error("uint256 word is too large");
  }
  return hex;
}

function addressWord(value: Address): Hex {
  const hex = `0x${"0".repeat(24)}${value.slice(2)}`;
  if (!isBytes32(hex)) {
    throw new Error("address word is invalid");
  }
  return hex;
}

function readChannelConfig(input: Hex, byteOffset: bigint, label: string): DecodedBatchChannelConfig {
  return {
    payer: readAddress(input, byteOffset, label),
    payerAuthorizer: readAddress(input, byteOffset + 32n, label),
    receiver: readAddress(input, byteOffset + 64n, label),
    receiverAuthorizer: readAddress(input, byteOffset + 96n, label),
    token: readAddress(input, byteOffset + 128n, label),
    withdrawDelay: readWord(input, byteOffset + 160n, label),
    salt: readWordHex(input, byteOffset + 192n, label)
  };
}

function hashText(value: string): Hex {
  return keccak256(toHex(value));
}

function batchDomainSeparator(contract: Address): Hex {
  return keccak256(concatHex([
    hashText(EIP712_DOMAIN_TYPE),
    hashText(BATCH_DOMAIN_NAME),
    hashText(BATCH_DOMAIN_VERSION),
    uint256Word(BATCH_CHAIN_ID),
    addressWord(contract)
  ]));
}

function channelConfigHash(config: DecodedBatchChannelConfig): Hex {
  return keccak256(concatHex([
    hashText(CHANNEL_CONFIG_TYPE),
    addressWord(config.payer),
    addressWord(config.payerAuthorizer),
    addressWord(config.receiver),
    addressWord(config.receiverAuthorizer),
    addressWord(config.token),
    uint256Word(config.withdrawDelay),
    config.salt
  ]));
}

function computeChannelId(config: DecodedBatchChannelConfig, contract: Address): Hex {
  return keccak256(concatHex([
    "0x1901",
    batchDomainSeparator(contract),
    channelConfigHash(config)
  ]));
}

function ensureChannelIdMatches(actual: Hex, expected: Hex, label: string): void {
  if (!sameHex(actual, expected)) {
    throw new Error(`${label} channelId mismatch: ${actual} != ${expected}`);
  }
}

function verifyChannelConfigScope(config: DecodedBatchChannelConfig, options: BatchSettlementReceiptOptions, label: string): void {
  const expectedToken = options.token ?? DEFAULT_JPYC_POLYGON_ADDRESS;
  if (!sameHex(config.token, expectedToken)) {
    throw new Error(`${label} token mismatch: ${config.token} != ${expectedToken}`);
  }
  if (options.receiver && !sameHex(config.receiver, options.receiver)) {
    throw new Error(`${label} receiver mismatch: ${config.receiver} != ${options.receiver}`);
  }
  if (options.expectedReceiverAuthorizer && !sameHex(config.receiverAuthorizer, options.expectedReceiverAuthorizer)) {
    throw new Error(`${label} receiverAuthorizer mismatch: ${config.receiverAuthorizer} != ${options.expectedReceiverAuthorizer}`);
  }
  if (options.expectedWithdrawDelay !== undefined && config.withdrawDelay !== options.expectedWithdrawDelay) {
    throw new Error(`${label} withdrawDelay mismatch: ${config.withdrawDelay.toString()} != ${options.expectedWithdrawDelay.toString()}`);
  }
}

function readBytesArrayElement(input: Hex, arrayStart: bigint, elementOffset: bigint, minimumOffset: bigint): Hex {
  if (elementOffset < minimumOffset) {
    throw new Error("batch multicall bytes element offset overlaps array head");
  }
  const elementStart = arrayStart + 32n + elementOffset;
  const length = readWord(input, elementStart);
  const dataStart = elementStart + 32n;
  const dataEnd = dataStart + length;
  if (dataEnd > hexByteLength(input)) {
    throw new Error("batch multicall bytes element is truncated");
  }
  const start = 2 + Number(dataStart * 2n);
  const end = start + Number(length * 2n);
  return `0x${input.slice(start, end)}`;
}

function multicallElements(input: Hex): readonly Hex[] {
  const arrayOffset = readWord(input, 4n);
  const arrayStart = 4n + arrayOffset;
  const length = readWord(input, arrayStart);
  const elements: Hex[] = [];
  const minimumElementOffset = 32n * length;
  for (let index = 0n; index < length; index += 1n) {
    const elementOffset = readWord(input, arrayStart + 32n + index * 32n);
    const element = readBytesArrayElement(input, arrayStart, elementOffset, minimumElementOffset);
    elements.push(element);
  }
  return elements;
}

function calldataChannelConfig(input: Hex): DecodedBatchChannelConfig {
  return readChannelConfig(input, 4n, "batch calldata");
}

function calldataChannelId(input: Hex, contract: Address): Hex {
  return computeChannelId(calldataChannelConfig(input), contract);
}

function depositCalldataAmount(input: Hex): bigint {
  return readWord(input, 4n + 32n * 7n, "batch deposit calldata");
}

function refundCalldataNextNonce(input: Hex): bigint {
  return readWord(input, 4n + 32n * 8n, "batch refund calldata") + 1n;
}

function claimCalldataClaims(input: Hex, contract: Address): readonly DecodedBatchClaim[] {
  const claimsOffset = readWord(input, 4n, "batch claim calldata");
  const arrayStart = 4n + claimsOffset;
  const length = readWord(input, arrayStart, "batch claim calldata");
  const claims: DecodedBatchClaim[] = [];
  const minimumClaimOffset = 32n * length;
  for (let index = 0n; index < length; index += 1n) {
    const claimOffset = readWord(input, arrayStart + 32n + index * 32n, "batch claim calldata");
    if (claimOffset < minimumClaimOffset) {
      throw new Error("batch claim calldata offset overlaps array head");
    }
    const claimStart = arrayStart + 32n + claimOffset;
    const config = readChannelConfig(input, claimStart, "batch claim calldata");
    claims.push({
      channelId: computeChannelId(config, contract),
      config,
      totalClaimed: readWord(input, claimStart + 288n, "batch claim calldata")
    });
  }
  return claims;
}

function verifyClaimInputChannel(input: Hex, contract: Address, options: BatchSettlementReceiptOptions): bigint {
  const expectedChannelId = requireChannelId(options);
  const claims = claimCalldataClaims(input, contract);
  if (claims.length === 0) {
    throw new Error("batch claim calldata has no claims");
  }
  const first = claims[0];
  if (!first) {
    throw new Error("batch claim calldata has no claims");
  }
  for (const claim of claims) {
    if (!sameHex(claim.config.receiver, first.config.receiver)) {
      throw new Error("batch claim calldata mixes receivers");
    }
    if (!sameHex(claim.config.receiverAuthorizer, first.config.receiverAuthorizer)) {
      throw new Error("batch claim calldata mixes receiverAuthorizers");
    }
    if (!sameHex(claim.config.token, first.config.token)) {
      throw new Error("batch claim calldata mixes tokens");
    }
    if (claim.config.withdrawDelay !== first.config.withdrawDelay) {
      throw new Error("batch claim calldata mixes withdrawDelay values");
    }
    verifyChannelConfigScope(claim.config, options, "batch claim calldata");
  }
  const expectedClaim = claims.find((claim) => sameHex(claim.channelId, expectedChannelId));
  if (!expectedClaim) {
    const channelIds = claims.map((claim) => claim.channelId);
    throw new Error(`batch claim calldata channelId mismatch: ${channelIds.join(",")} does not include ${expectedChannelId}`);
  }
  const expectedTotalClaimed = parseOptionalNonNegativeInteger(options.expectedTotalClaimed, "BATCH_EXPECTED_TOTAL_CLAIMED");
  if (expectedTotalClaimed !== undefined && expectedClaim.totalClaimed < expectedTotalClaimed) {
    throw new Error(`batch claim calldata totalClaimed below expected: ${expectedClaim.totalClaimed.toString()} < ${expectedTotalClaimed.toString()}`);
  }
  return expectedClaim.totalClaimed;
}

function verifyRefundInputChannel(input: Hex, contract: Address, options: BatchSettlementReceiptOptions): Omit<BatchTransactionInputProof, "selector"> {
  const expectedChannelId = requireChannelId(options);
  if (hasSelector(input, BATCH_FUNCTION_SELECTORS.refund)) {
    const config = calldataChannelConfig(input);
    verifyChannelConfigScope(config, options, "batch refund calldata");
    ensureChannelIdMatches(computeChannelId(config, contract), expectedChannelId, "batch refund calldata");
    return { calldataMinRefundNonce: refundCalldataNextNonce(input) };
  }
  const calls = multicallElements(input);
  let calldataMinTotalClaimed: bigint | undefined;
  let calldataMinRefundNonce: bigint | undefined;
  for (const call of calls) {
    if (hasSelector(call, BATCH_FUNCTION_SELECTORS.claim)) {
      const totalClaimed = verifyClaimInputChannel(call, contract, options);
      calldataMinTotalClaimed = calldataMinTotalClaimed === undefined || totalClaimed > calldataMinTotalClaimed
        ? totalClaimed
        : calldataMinTotalClaimed;
    } else if (hasSelector(call, BATCH_FUNCTION_SELECTORS.refund)) {
      const config = calldataChannelConfig(call);
      const channelId = computeChannelId(config, contract);
      ensureChannelIdMatches(channelId, expectedChannelId, "batch refund calldata");
      verifyChannelConfigScope(config, options, "batch refund calldata");
      const nextNonce = refundCalldataNextNonce(call);
      calldataMinRefundNonce = calldataMinRefundNonce === undefined || nextNonce > calldataMinRefundNonce
        ? nextNonce
        : calldataMinRefundNonce;
    } else {
      throw new Error(`batch refund multicall contains unsupported call: ${inputSelector(call)}`);
    }
  }
  if (calldataMinRefundNonce === undefined) {
    throw new Error(`batch refund multicall channelId mismatch: no refundWithSignature call matches ${expectedChannelId}`);
  }
  return { calldataMinRefundNonce, ...(calldataMinTotalClaimed === undefined ? {} : { calldataMinTotalClaimed }) };
}

function verifySettleInputArgs(input: Hex, receiver: Address, token: Address): void {
  const inputReceiver = readAddress(input, 4n, "batch settle calldata");
  const inputToken = readAddress(input, 36n, "batch settle calldata");
  if (!sameHex(inputReceiver, receiver)) {
    throw new Error(`batch settle receiver mismatch: ${inputReceiver} != ${receiver}`);
  }
  if (!sameHex(inputToken, token)) {
    throw new Error(`batch settle token mismatch: ${inputToken} != ${token}`);
  }
}

function verifyTransactionInput(options: BatchSettlementReceiptOptions, input: Hex, contract: Address): BatchTransactionInputProof {
  const action = options.action;
  const selector = inputSelector(input);
  if (action === "refund" && hasSelector(input, BATCH_FUNCTION_SELECTORS.multicall)) {
    return { ...verifyRefundInputChannel(input, contract, options), selector };
  }
  const expected = BATCH_FUNCTION_SELECTORS[action];
  if (!hasSelector(input, expected)) {
    throw new Error(`batch ${action} tx selector mismatch: ${selector} != ${expected}`);
  }
  if (action === "deposit") {
    const config = calldataChannelConfig(input);
    verifyChannelConfigScope(config, options, "batch deposit calldata");
    ensureChannelIdMatches(computeChannelId(config, contract), requireChannelId(options), "batch deposit calldata");
    const expectedAmount = parseOptionalPositiveInteger(options.expectedDepositAmount, "BATCH_DEPOSIT_AMOUNT");
    if (expectedAmount !== undefined) {
      const actualAmount = depositCalldataAmount(input);
      if (actualAmount !== expectedAmount) {
        throw new Error(`batch deposit amount mismatch: ${actualAmount.toString()} != ${expectedAmount.toString()}`);
      }
    }
  } else if (action === "claim") {
    return { calldataMinTotalClaimed: verifyClaimInputChannel(input, contract, options), selector };
  } else if (action === "refund") {
    return { ...verifyRefundInputChannel(input, contract, options), selector };
  } else {
    if (!options.receiver) {
      throw new Error("BATCH_SETTLE_RECEIVER is required for settle receipt checks");
    }
    verifySettleInputArgs(input, options.receiver, requireSettleToken(options));
  }
  return { selector };
}

function requireChannelId(options: BatchSettlementReceiptOptions): Hex {
  if (!options.channelId) {
    throw new Error("BATCH_CHANNEL_ID is required for deposit, claim, and refund receipt checks");
  }
  return options.channelId;
}

function requireExpected(value: string | undefined, name: string): bigint {
  if (!value || value.trim() === "") {
    throw new Error(`${name} is required for this batch receipt check`);
  }
  return parsePositiveInteger(value, name);
}

function baseResult(
  options: BatchSettlementReceiptOptions,
  receipt: TransactionReceipt,
  contract: Address,
  confirmations: bigint,
  selector: Hex
): Omit<BatchSettlementReceiptResult, "channelState" | "receiverState"> {
  if (!receipt.to) {
    throw new Error("batch settlement tx recipient is missing");
  }
  return {
    action: options.action,
    blockNumber: receipt.blockNumber.toString(),
    confirmations: confirmations.toString(),
    contract,
    from: receipt.from,
    gasUsed: receipt.gasUsed.toString(),
    hash: options.hash,
    inputSelector: selector,
    status: "success",
    to: receipt.to
  };
}

function settledAmount(receipt: TransactionReceipt, contract: Address, receiver: Address, token: Address): string {
  let total = 0n;
  let matched = false;
  for (const log of receipt.logs) {
    if (log.removed) {
      continue;
    }
    if (!sameHex(log.transactionHash, receipt.transactionHash)) {
      throw new Error(`batch receipt log transaction hash mismatch: ${log.transactionHash} != ${receipt.transactionHash}`);
    }
    if (!sameHex(log.blockHash, receipt.blockHash)) {
      throw new Error(`batch receipt log block hash mismatch: ${log.blockHash} != ${receipt.blockHash}`);
    }
    if (log.blockNumber !== receipt.blockNumber) {
      throw new Error(`batch receipt log block number mismatch: ${log.blockNumber.toString()} != ${receipt.blockNumber.toString()}`);
    }
    if (!sameHex(log.address, contract)) {
      continue;
    }
    try {
      const decoded = decodeEventLog({
        abi: BATCH_SETTLEMENT_ABI,
        data: log.data,
        topics: log.topics
      });
      if (
        decoded.eventName === "Settled" &&
        sameHex(decoded.args.receiver, receiver) &&
        sameHex(decoded.args.token, token) &&
        sameHex(decoded.args.sender, receipt.from)
      ) {
        matched = true;
        total += decoded.args.amount;
      }
    } catch {
      continue;
    }
  }
  if (matched) {
    return total.toString();
  }
  throw new Error("expected batch Settled event not found");
}

function ensureAtLeast(actual: bigint, expected: bigint, label: string): void {
  if (actual < expected) {
    throw new Error(`${label} below expected: ${actual.toString()} < ${expected.toString()}`);
  }
}

async function verifyChannelPostState(
  options: BatchSettlementReceiptOptions,
  reader: BatchSettlementReceiptReader,
  contract: Address,
  calldataMinRefundNonce?: bigint,
  calldataMinTotalClaimed?: bigint
): Promise<BatchChannelStateResult> {
  const channelId = requireChannelId(options);
  const [balance, totalClaimed] = await reader.getBatchChannel(contract, channelId);
  const base = {
    balance: balance.toString(),
    channelId,
    totalClaimed: totalClaimed.toString()
  };

  if (options.action === "deposit") {
    ensureAtLeast(balance, requireExpected(options.expectedMinBalance, "BATCH_EXPECTED_MIN_BALANCE"), "batch channel balance");
    return base;
  }
  if (options.action === "claim") {
    ensureAtLeast(totalClaimed, requireExpected(options.expectedTotalClaimed, "BATCH_EXPECTED_TOTAL_CLAIMED"), "batch channel totalClaimed");
    if (calldataMinTotalClaimed !== undefined) {
      ensureAtLeast(totalClaimed, calldataMinTotalClaimed, "batch channel totalClaimed below calldata");
    }
    return base;
  }

  const refundNonce = await reader.getBatchRefundNonce(contract, channelId);
  ensureAtLeast(refundNonce, requireExpected(options.expectedMinRefundNonce, "BATCH_EXPECTED_MIN_REFUND_NONCE"), "batch refundNonce");
  if (calldataMinRefundNonce !== undefined) {
    ensureAtLeast(refundNonce, calldataMinRefundNonce, "batch refundNonce below calldata");
  }
  if (calldataMinTotalClaimed !== undefined) {
    ensureAtLeast(totalClaimed, calldataMinTotalClaimed, "batch channel totalClaimed below calldata");
  }
  const expectedClaimed = parseOptionalNonNegativeInteger(options.expectedTotalClaimed, "BATCH_EXPECTED_TOTAL_CLAIMED");
  if (expectedClaimed !== undefined) {
    ensureAtLeast(totalClaimed, expectedClaimed, "batch channel totalClaimed");
  }
  return { ...base, refundNonce: refundNonce.toString() };
}

async function verifyReceiverPostState(
  options: BatchSettlementReceiptOptions,
  reader: BatchSettlementReceiptReader,
  receipt: TransactionReceipt,
  contract: Address
): Promise<BatchReceiverStateResult> {
  if (!options.receiver) {
    throw new Error("BATCH_SETTLE_RECEIVER is required for settle receipt checks");
  }
  const receiver = options.receiver;
  const token = requireSettleToken(options);
  const amount = settledAmount(receipt, contract, receiver, token);
  const expected = parseOptionalNonNegativeInteger(options.expectedSettledAmount, "BATCH_SETTLE_AMOUNT");
  if (expected !== undefined && BigInt(amount) !== expected) {
    throw new Error(`batch settled amount mismatch: ${amount} != ${expected.toString()}`);
  }
  const [totalClaimed, totalSettled] = await reader.getBatchReceiver(contract, receiver, token);
  ensureAtLeast(totalSettled, BigInt(amount), "batch receiver totalSettled below event amount");
  ensureAtLeast(totalClaimed, totalSettled, "batch receiver totalClaimed below totalSettled");
  return {
    receiver,
    settledAmount: amount,
    token,
    totalClaimed: totalClaimed.toString(),
    totalSettled: totalSettled.toString()
  };
}

function requireSettleToken(options: BatchSettlementReceiptOptions): Address {
  if (!options.token) {
    throw new Error("BATCH_SETTLE_TOKEN is required for settle receipt checks");
  }
  return options.token;
}

export async function verifyBatchSettlementReceipt(
  options: BatchSettlementReceiptOptions
): Promise<BatchSettlementReceiptResult> {
  const contract = normalizeBatchSettlementContract(
    options.contract ?? requireEnv("BATCH_SETTLEMENT_CONTRACT"),
    options.contract === undefined ? "BATCH_SETTLEMENT_CONTRACT" : "contract"
  );
  validateReceiptOptionsBeforeRpc(options);
  const reader = options.reader ?? createReader(options.rpcUrl ?? requireEnv("POLYGON_RPC_URL"));
  const [receipt, transaction, latestBlock] = await Promise.all([
    reader.getTransactionReceipt({ hash: options.hash }),
    reader.getTransaction({ hash: options.hash }),
    reader.getBlockNumber()
  ]);

  if (!sameHex(receipt.transactionHash, options.hash)) {
    throw new Error(`batch receipt hash mismatch: ${receipt.transactionHash}`);
  }
  if (!sameHex(transaction.hash, options.hash)) {
    throw new Error(`batch transaction hash mismatch: ${transaction.hash}`);
  }
  if (receipt.status !== "success") {
    throw new Error(`batch settlement tx failed: ${receipt.status}`);
  }
  if (!receipt.to || !sameHex(receipt.to, contract)) {
    throw new Error(`batch settlement tx recipient mismatch: ${receipt.to}`);
  }
  if (!transaction.to || !sameHex(transaction.to, contract)) {
    throw new Error(`batch settlement transaction recipient mismatch: ${transaction.to}`);
  }
  if (options.expectedFrom) {
    if (!sameHex(receipt.from, options.expectedFrom)) {
      throw new Error(`batch settlement receipt sender mismatch: ${receipt.from} != ${options.expectedFrom}`);
    }
    if (!sameHex(transaction.from, options.expectedFrom)) {
      throw new Error(`batch settlement transaction sender mismatch: ${transaction.from} != ${options.expectedFrom}`);
    }
  }
  if (!sameHex(receipt.from, transaction.from)) {
    throw new Error(`batch settlement receipt/transaction sender mismatch: ${receipt.from} != ${transaction.from}`);
  }
  const inputProof = verifyTransactionInput(options, transaction.input, contract);
  const confirmations = latestBlock >= receipt.blockNumber ? latestBlock - receipt.blockNumber + 1n : 0n;
  const minConfirmations = BigInt(options.minConfirmations ?? DEFAULT_MIN_CONFIRMATIONS);
  if (confirmations < minConfirmations) {
    throw new Error(`batch settlement tx confirmations below minimum: ${confirmations.toString()} < ${minConfirmations.toString()}`);
  }

  const result = baseResult(options, receipt, contract, confirmations, inputProof.selector);
  if (options.action === "settle") {
    const receiverState = await verifyReceiverPostState(options, reader, receipt, contract);
    return { ...result, receiverState };
  }
  const channelState = await verifyChannelPostState(
    options,
    reader,
    contract,
    inputProof.calldataMinRefundNonce,
    inputProof.calldataMinTotalClaimed
  );
  return { ...result, channelState };
}

function validateReceiptOptionsBeforeRpc(options: BatchSettlementReceiptOptions): void {
  validateDirectMinConfirmations(options.minConfirmations);
  if (options.action === "settle") {
    if (!options.receiver) {
      throw new Error("BATCH_SETTLE_RECEIVER is required for settle receipt checks");
    }
    requireSettleToken(options);
    requireExpected(options.expectedSettledAmount, "BATCH_SETTLE_AMOUNT");
    return;
  }
  requireChannelId(options);
  if (options.action === "deposit") {
    requireExpected(options.expectedDepositAmount, "BATCH_DEPOSIT_AMOUNT");
    requireExpected(options.expectedMinBalance, "BATCH_EXPECTED_MIN_BALANCE");
    return;
  }
  if (options.action === "claim") {
    requireExpected(options.expectedTotalClaimed, "BATCH_EXPECTED_TOTAL_CLAIMED");
    return;
  }
  requireExpected(options.expectedMinRefundNonce, "BATCH_EXPECTED_MIN_REFUND_NONCE");
  parseOptionalNonNegativeInteger(options.expectedTotalClaimed, "BATCH_EXPECTED_TOTAL_CLAIMED");
}

function validateDirectMinConfirmations(value: number | undefined): void {
  if (value === undefined) {
    return;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("SETTLE_MIN_CONFIRMATIONS must be a non-negative safe integer");
  }
}

export async function verifyBatchSettlementReceiptsFromEnv(
  options: BatchSettlementReceiptsOptions
): Promise<readonly BatchSettlementReceiptResult[]> {
  const results: BatchSettlementReceiptResult[] = [];
  for (const action of BATCH_SETTLEMENT_ACTIONS) {
    results.push(await verifyBatchSettlementReceipt({
      ...batchSettlementReceiptOptionsForActionFromEnv(options.env, action),
      ...(options.reader ? { reader: options.reader } : {})
    }));
  }
  return results;
}

export function batchSettlementReceiptOptionsFromEnv(
  env: NodeJS.ProcessEnv,
  txArg?: string
): BatchSettlementReceiptOptions {
  const contract = normalizeBatchSettlementContract(requireEnvFrom(env, "BATCH_SETTLEMENT_CONTRACT"), "BATCH_SETTLEMENT_CONTRACT");
  const action = parseAction(requireEnvFrom(env, "BATCH_SETTLEMENT_ACTION"));
  const hash = parseTxHash(txArg ?? requireEnvFrom(env, "BATCH_SETTLEMENT_TX"));
  const channelId = action === "settle"
    ? readEnvFrom(env, "BATCH_CHANNEL_ID")
    : requireEnvFrom(env, "BATCH_CHANNEL_ID");
  const expectedMinBalance = action === "deposit" ? requirePositiveIntegerEnvFrom(env, "BATCH_EXPECTED_MIN_BALANCE") : readEnvFrom(env, "BATCH_EXPECTED_MIN_BALANCE");
  const expectedMinRefundNonce = action === "refund" ? requirePositiveIntegerEnvFrom(env, "BATCH_EXPECTED_MIN_REFUND_NONCE") : readEnvFrom(env, "BATCH_EXPECTED_MIN_REFUND_NONCE");
  const expectedDepositAmount = action === "deposit" ? requirePositiveIntegerEnvFrom(env, "BATCH_DEPOSIT_AMOUNT") : readEnvFrom(env, "BATCH_DEPOSIT_AMOUNT");
  const expectedSettledAmount = action === "settle" ? requirePositiveIntegerEnvFrom(env, "BATCH_SETTLE_AMOUNT") : readEnvFrom(env, "BATCH_SETTLE_AMOUNT");
  const expectedTotalClaimed = action === "claim" ? requirePositiveIntegerEnvFrom(env, "BATCH_EXPECTED_TOTAL_CLAIMED") : readEnvFrom(env, "BATCH_EXPECTED_TOTAL_CLAIMED");
  const rpcUrl = readEnvFrom(env, "POLYGON_RPC_URL");
  const token = action === "settle"
    ? requireEnvFrom(env, "BATCH_SETTLE_TOKEN")
    : readEnvFrom(env, "BATCH_SETTLE_TOKEN");
  const expectedFrom = expectedBatchSettlementSenderFromEnv(env);
  const receiver = normalizeAddress(requireEnvFrom(env, "BATCH_SETTLE_RECEIVER"), "BATCH_SETTLE_RECEIVER");
  const expectedReceiverAuthorizer = action === "settle" ? undefined : expectedBatchReceiverAuthorizerFromEnv(env);
  const expectedWithdrawDelay = action === "settle" ? undefined : expectedBatchWithdrawDelayFromEnv(env);
  return {
    action,
    contract,
    expectedFrom,
    hash,
    minConfirmations: parseMinConfirmations(readEnvFrom(env, "SETTLE_MIN_CONFIRMATIONS")),
    ...(channelId ? { channelId: normalizeBytes32(channelId, "BATCH_CHANNEL_ID") } : {}),
    ...(expectedDepositAmount ? { expectedDepositAmount } : {}),
    ...(expectedMinBalance ? { expectedMinBalance } : {}),
    ...(expectedMinRefundNonce ? { expectedMinRefundNonce } : {}),
    ...(expectedReceiverAuthorizer === undefined ? {} : { expectedReceiverAuthorizer }),
    ...(expectedSettledAmount ? { expectedSettledAmount } : {}),
    ...(expectedTotalClaimed ? { expectedTotalClaimed } : {}),
    ...(expectedWithdrawDelay === undefined ? {} : { expectedWithdrawDelay }),
    receiver,
    ...(rpcUrl ? { rpcUrl: normalizePolygonRpcUrl(rpcUrl, "POLYGON_RPC_URL") } : {}),
    ...(token ? { token: normalizeAddress(token, "BATCH_SETTLE_TOKEN") } : {})
  };
}

function commonReceiptOptionsFromEnv(
  env: NodeJS.ProcessEnv,
  action: BatchSettlementAction,
  txEnvName: string
): BatchSettlementReceiptOptions {
  const contract = normalizeBatchSettlementContract(requireEnvFrom(env, "BATCH_SETTLEMENT_CONTRACT"), "BATCH_SETTLEMENT_CONTRACT");
  const hash = parseTxHash(requireEnvFrom(env, txEnvName));
  const rpcUrl = readEnvFrom(env, "POLYGON_RPC_URL");
  const expectedFrom = expectedBatchSettlementSenderFromEnv(env);
  const receiver = normalizeAddress(requireEnvFrom(env, "BATCH_SETTLE_RECEIVER"), "BATCH_SETTLE_RECEIVER");
  const token = action === "settle"
    ? requireEnvFrom(env, "BATCH_SETTLE_TOKEN")
    : readEnvFrom(env, "BATCH_SETTLE_TOKEN");
  const expectedReceiverAuthorizer = action === "settle" ? undefined : expectedBatchReceiverAuthorizerFromEnv(env);
  const expectedWithdrawDelay = action === "settle" ? undefined : expectedBatchWithdrawDelayFromEnv(env);
  return {
    action,
    contract,
    expectedFrom,
    hash,
    minConfirmations: parseMinConfirmations(readEnvFrom(env, "SETTLE_MIN_CONFIRMATIONS")),
    ...(expectedReceiverAuthorizer === undefined ? {} : { expectedReceiverAuthorizer }),
    ...(expectedWithdrawDelay === undefined ? {} : { expectedWithdrawDelay }),
    receiver,
    ...(rpcUrl ? { rpcUrl: normalizePolygonRpcUrl(rpcUrl, "POLYGON_RPC_URL") } : {}),
    ...(token ? { token: normalizeAddress(token, "BATCH_SETTLE_TOKEN") } : {})
  };
}

export function batchSettlementReceiptOptionsForActionFromEnv(
  env: NodeJS.ProcessEnv,
  action: BatchSettlementAction
): BatchSettlementReceiptOptions {
  if (action === "deposit") {
    return {
      ...commonReceiptOptionsFromEnv(env, action, "BATCH_DEPOSIT_TX"),
      channelId: normalizeBytes32(requireEnvFrom(env, "BATCH_DEPOSIT_CHANNEL_ID"), "BATCH_DEPOSIT_CHANNEL_ID"),
      expectedDepositAmount: requirePositiveIntegerEnvFrom(env, "BATCH_DEPOSIT_AMOUNT"),
      expectedMinBalance: requirePositiveIntegerEnvFrom(env, "BATCH_DEPOSIT_EXPECTED_MIN_BALANCE")
    };
  }
  if (action === "claim") {
    return {
      ...commonReceiptOptionsFromEnv(env, action, "BATCH_CLAIM_TX"),
      channelId: normalizeBytes32(requireEnvFrom(env, "BATCH_CLAIM_CHANNEL_ID"), "BATCH_CLAIM_CHANNEL_ID"),
      expectedTotalClaimed: requirePositiveIntegerEnvFrom(env, "BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED")
    };
  }
  if (action === "refund") {
    const expectedTotalClaimed = readEnvFrom(env, "BATCH_REFUND_EXPECTED_TOTAL_CLAIMED");
    return {
      ...commonReceiptOptionsFromEnv(env, action, "BATCH_REFUND_TX"),
      channelId: normalizeBytes32(requireEnvFrom(env, "BATCH_REFUND_CHANNEL_ID"), "BATCH_REFUND_CHANNEL_ID"),
      expectedMinRefundNonce: requirePositiveIntegerEnvFrom(env, "BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE"),
      ...(expectedTotalClaimed ? { expectedTotalClaimed } : {})
    };
  }
  return {
    ...commonReceiptOptionsFromEnv(env, action, "BATCH_SETTLE_TX"),
    receiver: normalizeAddress(requireEnvFrom(env, "BATCH_SETTLE_RECEIVER"), "BATCH_SETTLE_RECEIVER"),
    expectedSettledAmount: requirePositiveIntegerEnvFrom(env, "BATCH_SETTLE_AMOUNT"),
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

async function runDirect(): Promise<BatchSettlementReceiptResult | readonly BatchSettlementReceiptResult[]> {
  if (process.argv.includes("--all")) {
    return verifyBatchSettlementReceiptsFromEnv({ env: process.env });
  }
  return verifyBatchSettlementReceipt(batchSettlementReceiptOptionsFromEnv(process.env, process.argv[2]));
}

if (isDirectRun()) {
  loadDotenv();
  runDirect().then((result) => {
    console.log(JSON.stringify(result, null, 2));
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
