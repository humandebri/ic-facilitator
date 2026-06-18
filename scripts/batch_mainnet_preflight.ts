// scripts/batch_mainnet_preflight.ts: x402 batch-settlement の Polygon mainnet 前提を read-only RPC で検査する。
import { pathToFileURL } from "node:url";

import { BATCH_SETTLEMENT_ADDRESS } from "@x402/evm";
import { createPublicClient, http, parseAbi } from "viem";
import type { Address, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";

import { loadDotenv } from "./env_file";

const DEFAULT_JPYC_POLYGON_ADDRESS: Address = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const EXPECTED_CHAIN_ID = 137;
const EXPECTED_JPYC_NAME = "JPY Coin";
const EXPECTED_JPYC_DECIMALS = 18;
const EXPECTED_JPYC_EIP712_VERSION = "1";
const EXPECTED_BATCH_SETTLEMENT_CONTRACT: Address = BATCH_SETTLEMENT_ADDRESS;
const MIN_BATCH_WITHDRAW_DELAY_SECONDS = 900;
const MAX_BATCH_WITHDRAW_DELAY_SECONDS = 2_592_000;
const ZERO_BYTES32: Hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
const PROBE_RECEIVER: Address = "0x0000000000000000000000000000000000000001";
const ANONYMOUS_PRINCIPAL = "2vxsx-fae";
const MANAGEMENT_PRINCIPAL = "aaaaa-aa";
const PRINCIPAL_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const UINT128_MAX = (1n << 128n) - 1n;

const JPYC_ABI = parseAbi([
  "function name() view returns (string)",
  "function decimals() view returns (uint8)",
  "function authorizationState(address authorizer,bytes32 nonce) view returns (bool)"
]);

const BATCH_ABI = parseAbi([
  "function channels(bytes32 channelId) view returns (uint128 balance,uint128 totalClaimed)",
  "function refundNonce(bytes32 channelId) view returns (uint256)",
  "function pendingWithdrawals(bytes32 channelId) view returns (uint128 amount,uint40 initiatedAt)",
  "function receivers(address receiver,address token) view returns (uint128 totalClaimed,uint128 totalSettled)"
]);

export type BatchMainnetPreflightCheck = {
  readonly detail: string;
  readonly name: string;
  readonly status: "fail" | "ok";
};

export type BatchMainnetPreflightReport = {
  readonly batchContract?: Address;
  readonly checks: readonly BatchMainnetPreflightCheck[];
  readonly jpyc: Address;
  readonly ready: boolean;
};

export type BatchMainnetPreflightReader = {
  readonly getBatchChannel: (contract: Address, channelId: Hex) => Promise<readonly [bigint, bigint]>;
  readonly getBatchPendingWithdrawal: (contract: Address, channelId: Hex) => Promise<readonly [bigint, number]>;
  readonly getBatchReceiver: (contract: Address, receiver: Address, token: Address) => Promise<readonly [bigint, bigint]>;
  readonly getBatchRefundNonce: (contract: Address, channelId: Hex) => Promise<bigint>;
  readonly getBytecode: (address: Address) => Promise<Hex | undefined>;
  readonly getChainId: () => Promise<number>;
  readonly getJpycAuthorizationState: (address: Address, authorizer: Address, nonce: Hex) => Promise<boolean>;
  readonly getJpycDecimals: (address: Address) => Promise<number>;
  readonly getJpycName: (address: Address) => Promise<string>;
};

export type BatchMainnetPreflightOptions = {
  readonly env: NodeJS.ProcessEnv;
  readonly reader?: BatchMainnetPreflightReader;
};

function ok(name: string, detail: string): BatchMainnetPreflightCheck {
  return { detail, name, status: "ok" };
}

function fail(name: string, detail: string): BatchMainnetPreflightCheck {
  return { detail, name, status: "fail" };
}

function isAddress(value: string): value is Address {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isHttpsRpcUrl(value: string): boolean {
  if (!value.startsWith("https://") || /\s/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.hostname !== "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}

function batchSettlementContractCheck(env: NodeJS.ProcessEnv): {
  readonly address?: Address;
  readonly check: BatchMainnetPreflightCheck;
} {
  const value = env.BATCH_SETTLEMENT_CONTRACT;
  if (!value || value.trim() === "") {
    return {
      check: fail("env:BATCH_SETTLEMENT_CONTRACT", "未設定")
    };
  }
  const address = value.trim();
  if (!isAddress(address) || /^0x0{40}$/i.test(address)) {
    return {
      check: fail("env:BATCH_SETTLEMENT_CONTRACT", "non-zero 0x-prefixed EVM address ではない")
    };
  }
  if (address.toLowerCase() !== EXPECTED_BATCH_SETTLEMENT_CONTRACT.toLowerCase()) {
    return {
      check: fail(
        "env:BATCH_SETTLEMENT_CONTRACT",
        `official @x402/evm BATCH_SETTLEMENT_ADDRESS ${EXPECTED_BATCH_SETTLEMENT_CONTRACT} と不一致`
      )
    };
  }
  return {
    address,
    check: ok("env:BATCH_SETTLEMENT_CONTRACT", address)
  };
}

function batchWithdrawDelayCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.BATCH_WITHDRAW_DELAY_SECONDS;
  if (!value || value.trim() === "") {
    return fail("env:BATCH_WITHDRAW_DELAY_SECONDS", "未設定");
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    return fail("env:BATCH_WITHDRAW_DELAY_SECONDS", "positive integer ではない");
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds < MIN_BATCH_WITHDRAW_DELAY_SECONDS || seconds > MAX_BATCH_WITHDRAW_DELAY_SECONDS) {
    return fail("env:BATCH_WITHDRAW_DELAY_SECONDS", `must be between ${MIN_BATCH_WITHDRAW_DELAY_SECONDS} and ${MAX_BATCH_WITHDRAW_DELAY_SECONDS}`);
  }
  return ok("env:BATCH_WITHDRAW_DELAY_SECONDS", `${seconds}`);
}

function batchReceiverAuthorizerKeyCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY;
  if (!value || value.trim() === "") {
    return fail("env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "未設定");
  }
  const key = value.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) {
    return fail("env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "0x-prefixed 32-byte private key ではない");
  }
  try {
    const address = privateKeyToAccount(key as Hex).address;
    if (/^0x0{40}$/i.test(address)) {
      return fail("env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "derived address is zero");
    }
    return ok("env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", `authorizer=${address}`);
  } catch {
    return fail("env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "secp256k1 private key として不正");
  }
}

function batchAuthorizerKeySeparationCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const receiverKey = env.BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY?.trim();
  const facilitatorKey = env.FACILITATOR_EVM_PRIVATE_KEY?.trim();
  if (!receiverKey || !facilitatorKey) {
    return ok("env:BATCH_KEY_SEPARATION", "FACILITATOR_EVM_PRIVATE_KEY 未設定のため readiness で検証");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(receiverKey) || !/^0x[0-9a-fA-F]{64}$/.test(facilitatorKey)) {
    return ok("env:BATCH_KEY_SEPARATION", "private key format は個別checkで検証");
  }
  try {
    const receiver = privateKeyToAccount(receiverKey as Hex).address.toLowerCase();
    const facilitator = privateKeyToAccount(facilitatorKey as Hex).address.toLowerCase();
    if (receiver === facilitator) {
      return fail(
        "env:BATCH_KEY_SEPARATION",
        "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address"
      );
    }
    return ok("env:BATCH_KEY_SEPARATION", `receiverAuthorizer=${receiver} facilitator=${facilitator}`);
  } catch {
    return ok("env:BATCH_KEY_SEPARATION", "private key validity は個別checkで検証");
  }
}

function batchSettlementFeeCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.BATCH_SETTLEMENT_FEE_AMOUNT;
  if (!value || value.trim() === "") {
    return fail("env:BATCH_SETTLEMENT_FEE_AMOUNT", "未設定");
  }
  const amount = value.trim();
  if (!/^[1-9][0-9]*$/.test(amount)) {
    return fail("env:BATCH_SETTLEMENT_FEE_AMOUNT", "positive integer ではない");
  }
  if (BigInt(amount) > UINT128_MAX) {
    return fail("env:BATCH_SETTLEMENT_FEE_AMOUNT", "uint128 に収まらない");
  }
  return ok("env:BATCH_SETTLEMENT_FEE_AMOUNT", amount);
}

function batchChannelStorageWriterCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL;
  if (!value || value.trim() === "") {
    return fail("env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "未設定");
  }
  const principal = value.trim();
  if (!isIcPrincipal(principal)) {
    return fail("env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "IC principal ではない");
  }
  if (principal === ANONYMOUS_PRINCIPAL || principal === MANAGEMENT_PRINCIPAL) {
    return fail("env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", "system principal は不可");
  }
  return ok("env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL", principal);
}

function isIcPrincipal(value: string): boolean {
  const bytes = decodePrincipalText(value);
  return bytes !== undefined && hasValidPrincipalChecksum(bytes);
}

function decodePrincipalText(value: string): number[] | undefined {
  if (value !== value.toLowerCase()) {
    return undefined;
  }
  const compact = value.replaceAll("-", "");
  if (compact.length === 0) {
    return undefined;
  }
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const char of compact) {
    const index = PRINCIPAL_BASE32_ALPHABET.indexOf(char);
    if (index < 0) {
      return undefined;
    }
    buffer = (buffer << 5) | index;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
      buffer &= (1 << bits) - 1;
    }
  }
  if (bytes.length < 4 || encodePrincipalText(bytes) !== value) {
    return undefined;
  }
  return bytes;
}

function encodePrincipalText(bytes: readonly number[]): string {
  let buffer = 0;
  let bits = 0;
  let compact = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      compact += PRINCIPAL_BASE32_ALPHABET.charAt((buffer >> bits) & 0x1f);
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0) {
    compact += PRINCIPAL_BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1f);
  }
  return groupPrincipalText(compact);
}

function groupPrincipalText(compact: string): string {
  const groups: string[] = [];
  for (let index = 0; index < compact.length; index += 5) {
    groups.push(compact.slice(index, index + 5));
  }
  return groups.join("-");
}

function hasValidPrincipalChecksum(bytes: readonly number[]): boolean {
  const first = bytes[0];
  const second = bytes[1];
  const third = bytes[2];
  const fourth = bytes[3];
  if (first === undefined || second === undefined || third === undefined || fourth === undefined) {
    return false;
  }
  const checksum = crc32(bytes.slice(4));
  return (
    first === ((checksum >>> 24) & 0xff) &&
    second === ((checksum >>> 16) & 0xff) &&
    third === ((checksum >>> 8) & 0xff) &&
    fourth === (checksum & 0xff)
  );
}

function crc32(bytes: readonly number[]): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      const mask = -(crc & 1);
      crc = (crc >>> 1) ^ (0xedb88320 & mask);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createReader(rpcUrl: string): BatchMainnetPreflightReader {
  const client = createPublicClient({
    chain: polygon,
    transport: http(rpcUrl)
  });

  return {
    async getBatchChannel(contract, channelId) {
      return client.readContract({ address: contract, abi: BATCH_ABI, functionName: "channels", args: [channelId] });
    },
    async getBatchPendingWithdrawal(contract, channelId) {
      return client.readContract({ address: contract, abi: BATCH_ABI, functionName: "pendingWithdrawals", args: [channelId] });
    },
    async getBatchReceiver(contract, receiver, token) {
      return client.readContract({ address: contract, abi: BATCH_ABI, functionName: "receivers", args: [receiver, token] });
    },
    async getBatchRefundNonce(contract, channelId) {
      return client.readContract({ address: contract, abi: BATCH_ABI, functionName: "refundNonce", args: [channelId] });
    },
    async getBytecode(address) {
      return client.getBytecode({ address });
    },
    async getChainId() {
      return client.getChainId();
    },
    async getJpycAuthorizationState(address, authorizer, nonce) {
      return client.readContract({ address, abi: JPYC_ABI, functionName: "authorizationState", args: [authorizer, nonce] });
    },
    async getJpycDecimals(address) {
      return client.readContract({ address, abi: JPYC_ABI, functionName: "decimals" });
    },
    async getJpycName(address) {
      return client.readContract({ address, abi: JPYC_ABI, functionName: "name" });
    }
  };
}

async function checked(name: string, run: () => Promise<string>): Promise<BatchMainnetPreflightCheck> {
  try {
    return ok(name, await run());
  } catch (error: unknown) {
    return fail(name, error instanceof Error ? error.message : String(error));
  }
}

function rpcUrlCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.POLYGON_RPC_URL;
  if (!value || value.trim() === "") {
    return fail("env:POLYGON_RPC_URL", "未設定");
  }
  if (!isHttpsRpcUrl(value)) {
    return fail("env:POLYGON_RPC_URL", "userinfo/fragment なしの HTTPS URL ではない");
  }
  return ok("env:POLYGON_RPC_URL", "設定済み");
}

function jpycEnvCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const configured = env.JPYC_POLYGON_ADDRESS;
  if (!configured || configured.trim() === "") {
    return ok("env:JPYC_POLYGON_ADDRESS", DEFAULT_JPYC_POLYGON_ADDRESS);
  }
  if (configured.toLowerCase() !== DEFAULT_JPYC_POLYGON_ADDRESS.toLowerCase()) {
    return fail("env:JPYC_POLYGON_ADDRESS", `canister fixed JPYC address と不一致: ${configured}`);
  }
  return ok("env:JPYC_POLYGON_ADDRESS", configured);
}

function jpycVersionCheck(env: NodeJS.ProcessEnv): BatchMainnetPreflightCheck {
  const value = env.JPYC_EIP712_VERSION;
  if (!value || value.trim() === "") {
    return fail("env:JPYC_EIP712_VERSION", "未設定");
  }
  if (value.trim() !== EXPECTED_JPYC_EIP712_VERSION) {
    return fail("env:JPYC_EIP712_VERSION", `must be ${EXPECTED_JPYC_EIP712_VERSION}`);
  }
  return ok("env:JPYC_EIP712_VERSION", EXPECTED_JPYC_EIP712_VERSION);
}

async function codeCheck(reader: BatchMainnetPreflightReader, name: string, address: Address): Promise<BatchMainnetPreflightCheck> {
  return checked(name, async () => {
    const code = await reader.getBytecode(address);
    if (!code || code === "0x") {
      throw new Error(`no contract code at ${address}`);
    }
    return `${address} codeBytes=${(code.length - 2) / 2}`;
  });
}

export async function checkBatchMainnetPreflight(
  options: BatchMainnetPreflightOptions
): Promise<BatchMainnetPreflightReport> {
  const batchContractCheck = batchSettlementContractCheck(options.env);
  const rpcCheck = rpcUrlCheck(options.env);
  const envChecks = [
    rpcCheck,
    jpycEnvCheck(options.env),
    jpycVersionCheck(options.env),
    batchContractCheck.check,
    batchWithdrawDelayCheck(options.env),
    batchReceiverAuthorizerKeyCheck(options.env),
    batchAuthorizerKeySeparationCheck(options.env),
    batchSettlementFeeCheck(options.env),
    batchChannelStorageWriterCheck(options.env)
  ];
  const batchContract = batchContractCheck.address;
  const jpyc = DEFAULT_JPYC_POLYGON_ADDRESS;
  const checks: BatchMainnetPreflightCheck[] = [...envChecks];

  if (!batchContract) {
    return { checks, jpyc, ready: false };
  }

  if (rpcCheck.status === "fail") {
    return { batchContract, checks, jpyc, ready: false };
  }

  const rpcUrl = options.env.POLYGON_RPC_URL;
  const reader = options.reader ?? (rpcUrl ? createReader(rpcUrl) : undefined);
  if (!reader) {
    checks.push(fail("rpc:reader", "POLYGON_RPC_URL が未設定"));
    return { batchContract, checks, jpyc, ready: false };
  }

  checks.push(
    await checked("polygon:chainId", async () => {
      const chainId = await reader.getChainId();
      if (chainId !== EXPECTED_CHAIN_ID) {
        throw new Error(`expected ${EXPECTED_CHAIN_ID}, got ${chainId}`);
      }
      return `${chainId}`;
    }),
    await codeCheck(reader, "polygon:batchContractCode", batchContract),
    await codeCheck(reader, "polygon:jpycCode", jpyc),
    await checked("jpyc:name", async () => {
      const name = await reader.getJpycName(jpyc);
      if (name !== EXPECTED_JPYC_NAME) {
        throw new Error(`expected ${EXPECTED_JPYC_NAME}, got ${name}`);
      }
      return name;
    }),
    await checked("jpyc:decimals", async () => {
      const decimals = await reader.getJpycDecimals(jpyc);
      if (decimals !== EXPECTED_JPYC_DECIMALS) {
        throw new Error(`expected ${EXPECTED_JPYC_DECIMALS}, got ${decimals}`);
      }
      return `${decimals}`;
    }),
    await checked("jpyc:authorizationStateSelector", async () => {
      const used = await reader.getJpycAuthorizationState(jpyc, PROBE_RECEIVER, ZERO_BYTES32);
      return `probeNonceUsed=${used}`;
    }),
    await checked("batch:channelsSelector", async () => {
      const [balance, totalClaimed] = await reader.getBatchChannel(batchContract, ZERO_BYTES32);
      return `balance=${balance.toString()} totalClaimed=${totalClaimed.toString()}`;
    }),
    await checked("batch:refundNonceSelector", async () => {
      return (await reader.getBatchRefundNonce(batchContract, ZERO_BYTES32)).toString();
    }),
    await checked("batch:pendingWithdrawalsSelector", async () => {
      const [amount, initiatedAt] = await reader.getBatchPendingWithdrawal(batchContract, ZERO_BYTES32);
      return `amount=${amount.toString()} initiatedAt=${initiatedAt}`;
    }),
    await checked("batch:receiversSelector", async () => {
      const [totalClaimed, totalSettled] = await reader.getBatchReceiver(batchContract, PROBE_RECEIVER, jpyc);
      return `totalClaimed=${totalClaimed.toString()} totalSettled=${totalSettled.toString()}`;
    })
  );

  return {
    batchContract,
    checks,
    jpyc,
    ready: checks.every((check) => check.status === "ok")
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  checkBatchMainnetPreflight({ env: process.env }).then((report) => {
    console.log(JSON.stringify(report, null, 2));
    if (!report.ready) {
      process.exitCode = 1;
    }
  }).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
