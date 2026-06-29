// scripts/batch_production_readiness.ts: batch settlement 本番投入前の証跡を副作用なしで集約する。
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { BATCH_SETTLEMENT_ADDRESS } from "@x402/evm";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { checkBatchMainnetPreflight } from "./batch_mainnet_preflight";
import type { BatchMainnetPreflightReader } from "./batch_mainnet_preflight";
import {
  BATCH_SETTLEMENT_ACTIONS,
  batchSettlementReceiptOptionsForActionFromEnv,
  verifyBatchSettlementReceipt
} from "./batch_settlement_receipt";
import type { BatchSettlementReceiptReader, BatchSettlementReceiptResult } from "./batch_settlement_receipt";
import { loadDotenv } from "./env_file";
import { checkCanisterSmoke } from "./smoke_canister";
import { REQUIRED_BATCH_ENV_NAMES, parseEnvNames } from "./smoke_canister_env";
import { normalizeDidServiceConstructor } from "./generate_did";

export type BatchProductionReadinessStatus = "fail" | "ok";

export type BatchProductionReadinessStage = {
  readonly detail: string;
  readonly name: string;
  readonly status: BatchProductionReadinessStatus;
};

export type BatchProductionReadinessReport = {
  readonly nextCommands: readonly string[];
  readonly ready: boolean;
  readonly stages: readonly BatchProductionReadinessStage[];
  readonly wasmSha256?: string;
};

export type BatchProductionReadinessOptions = {
  readonly batchPreflightReader?: BatchMainnetPreflightReader;
  readonly batchSettlementReceiptReader?: BatchSettlementReceiptReader;
  readonly commandRunner?: CommandRunner;
  readonly cwd?: string;
  readonly didPath?: string;
  readonly env: NodeJS.ProcessEnv;
  readonly fileReader?: FileReader;
  readonly fetchFn?: typeof fetch;
  readonly requireBatchReceipt?: boolean;
  readonly wasmPath?: string;
};

type CommandRunner = (command: string, args: readonly string[], cwd: string) => {
  readonly output: string;
  readonly status: number | null;
};

type FileReader = {
  readonly exists: (path: string) => boolean;
  readonly read: (path: string) => Buffer;
};

const DEFAULT_WASM_PATH = "target/wasm32-unknown-unknown/release/jpyc_x402_facilitator.wasm";
const DEFAULT_DID_PATH = "dist/facilitator.did";
const DEFAULT_ICP_CANISTER = "edge";
const DEFAULT_ICP_ENVIRONMENT = "ic";
const ANONYMOUS_PRINCIPAL = "2vxsx-fae";
const MANAGEMENT_PRINCIPAL = "aaaaa-aa";
const PRINCIPAL_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const MIN_BATCH_RECEIPT_CONFIRMATIONS = 3;
const READINESS_BATCH_CHANNEL_ID = `0x${"00".repeat(32)}`;
const DEFAULT_MIN_CANISTER_CYCLES = 1_000_000_000_000n;
const MIN_FREEZING_THRESHOLD_SECONDS = 7_776_000n;
const MAX_BATCH_CHANNELS_LIST = 1_000n;
const MAX_BATCH_STRING_BYTES = 512;
const MAX_SAFE_INTEGER_BIGINT = BigInt(Number.MAX_SAFE_INTEGER);
const UINT128_MAX = (1n << 128n) - 1n;
const REQUIRED_BATCH_DID_METHODS = [
  "batch_channel",
  "batch_channel_count",
  "batch_channels",
  "batch_create_payment_intent",
  "batch_deleted_channel",
  "batch_deleted_channel_count",
  "batch_deleted_channels",
  "batch_mark_payment_intent",
  "batch_payment_intent",
  "batch_receiver_authorizer",
  "batch_set_seller",
  "batch_set_writer_receiver_scope",
  "batch_settlement_contract",
  "batch_settlement_fee_amount",
  "batch_update_channel",
  "batch_writer_receiver_scope",
  "batch_writer_receiver_scope_count",
  "batch_writer_receiver_scopes"
];
const REQUIRED_BATCH_DID_SHAPES: readonly { readonly name: string; readonly pattern: RegExp }[] = [
  {
    name: "type BatchChannel",
    pattern: /\btype\s+BatchChannel\s*=\s*record\s*\{[\s\S]*\bchannel_id\s*:\s*text\s*;[\s\S]*\brevision\s*:\s*nat64\s*;[\s\S]*\}/
  },
  {
    name: "type BatchChannelUpdate",
    pattern: /\btype\s+BatchChannelUpdate\s*=\s*record\s*\{\s*channel\s*:\s*opt\s+BatchChannel\s*\}/
  },
  {
    name: "type BatchChannelUpdateResult",
    pattern: /\btype\s+BatchChannelUpdateResult\s*=\s*record\s*\{[\s\S]*\bstatus\s*:\s*text\s*;[\s\S]*\bcurrent_revision\s*:\s*opt\s+nat64\s*;[\s\S]*\bmessage\s*:\s*opt\s+text\s*;[\s\S]*\bchannel\s*:\s*opt\s+BatchChannel\s*;[\s\S]*\}/
  },
  {
    name: "type BatchDeletedChannel",
    pattern: /\btype\s+BatchDeletedChannel\s*=\s*record\s*\{[\s\S]*\bdeleted_at\s*:\s*nat64\s*;[\s\S]*\bdeleted_by\s*:\s*text\s*;[\s\S]*\bchannel\s*:\s*BatchChannel\s*;[\s\S]*\}/
  },
  {
    name: "type BatchPaymentIntent",
    pattern: /\btype\s+BatchPaymentIntent\s*=\s*record\s*\{[\s\S]*\bintent_id\s*:\s*text\s*;[\s\S]*\breceiver_address\s*:\s*text\s*;[\s\S]*\bstatus\s*:\s*text\s*;[\s\S]*\}/
  },
  {
    name: "type BatchSeller",
    pattern: /\btype\s+BatchSeller\s*=\s*record\s*\{[\s\S]*\breceiver_address\s*:\s*text\s*;[\s\S]*\bstatus\s*:\s*text\s*;[\s\S]*\}/
  },
  {
    name: "type BatchWriterReceiverScope",
    pattern: /\btype\s+BatchWriterReceiverScope\s*=\s*record\s*\{[\s\S]*\bwriter_principal\s*:\s*principal\s*;[\s\S]*\breceiver_address\s*:\s*text\s*;[\s\S]*\benabled\s*:\s*bool\s*;[\s\S]*\}/
  }
];
const REQUIRED_BATCH_CHANNEL_OUTPUT_FIELDS = [
  "balance",
  "channel_config",
  "channel_id",
  "charged_cumulative_amount",
  "last_request_timestamp",
  "onchain_synced_at",
  "pending_request",
  "refund_nonce",
  "revision",
  "signature",
  "signed_max_claimable",
  "total_claimed",
  "withdraw_requested_at"
];
const BATCH_RECEIPT_ENV_NEXT_COMMANDS: Readonly<Record<string, string>> = {
  BATCH_CLAIM_CHANNEL_ID: "set BATCH_CLAIM_CHANNEL_ID to the claimed channel id",
  BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED: "set BATCH_CLAIM_EXPECTED_TOTAL_CLAIMED to the expected post-claim totalClaimed",
  BATCH_CLAIM_TX: "set BATCH_CLAIM_TX to the claim transaction hash",
  BATCH_DEPOSIT_AMOUNT: "set BATCH_DEPOSIT_AMOUNT to the deposited amount",
  BATCH_DEPOSIT_CHANNEL_ID: "set BATCH_DEPOSIT_CHANNEL_ID to the deposited channel id",
  BATCH_DEPOSIT_EXPECTED_MIN_BALANCE: "set BATCH_DEPOSIT_EXPECTED_MIN_BALANCE to the expected post-deposit channel balance",
  BATCH_DEPOSIT_TX: "set BATCH_DEPOSIT_TX to the deposit transaction hash",
  BATCH_REFUND_CHANNEL_ID: "set BATCH_REFUND_CHANNEL_ID to the refunded channel id",
  BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE: "set BATCH_REFUND_EXPECTED_MIN_REFUND_NONCE to the expected post-refund nonce floor",
  BATCH_REFUND_TX: "set BATCH_REFUND_TX to the refund transaction hash",
  BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key",
  BATCH_SETTLE_AMOUNT: "set BATCH_SETTLE_AMOUNT to the positive settled amount from the settle event",
  BATCH_SETTLE_RECEIVER: "set BATCH_SETTLE_RECEIVER to the expected batch receiver address",
  BATCH_SETTLE_TOKEN: "set BATCH_SETTLE_TOKEN to the expected batch token address",
  BATCH_SETTLE_TX: "set BATCH_SETTLE_TX to the settle transaction hash",
  BATCH_SETTLEMENT_CONTRACT: `set BATCH_SETTLEMENT_CONTRACT=${BATCH_SETTLEMENT_ADDRESS}`,
  BATCH_WITHDRAW_DELAY_SECONDS: "set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds",
  FACILITATOR_EVM_PRIVATE_KEY: "set FACILITATOR_EVM_PRIVATE_KEY to the facilitator settlement private key",
  POLYGON_RPC_URL: "set POLYGON_RPC_URL to a Polygon HTTPS RPC URL"
};

function ok(name: string, detail: string): BatchProductionReadinessStage {
  return { detail, name, status: "ok" };
}

function fail(name: string, detail: string): BatchProductionReadinessStage {
  return { detail, name, status: "fail" };
}

function isHttpsOrigin(value: string): boolean {
  if (!/^https:\/\/[^/:@?#\s]+(:[0-9]+)?$/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.pathname === "/" &&
      url.search === "" &&
      url.hash === "" &&
      value === url.origin
    );
  } catch {
    return false;
  }
}

const defaultFileReader: FileReader = {
  exists(path) {
    return existsSync(path);
  },
  read(path) {
    return readFileSync(path);
  }
};

const defaultCommandRunner: CommandRunner = (command, args, cwd) => {
  const result = spawnSync(command, [...args], { cwd, encoding: "utf8" });
  return {
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim(),
    status: result.status
  };
};

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseCanisterModuleHash(output: string): string | undefined {
  const patterns = [
    /"?wasm_module_hash"?\s*[:=]\s*"?(?:0x)?([0-9a-fA-F]{64})"?/i,
    /"?module_hash"?\s*[:=]\s*"?(?:0x)?([0-9a-fA-F]{64})"?/i,
    /wasm\s+module\s+hash\s*[:=]\s*(?:0x)?([0-9a-fA-F]{64})/i,
    /module\s+hash\s*[:=]\s*(?:0x)?([0-9a-fA-F]{64})/i
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(output);
    const hash = match?.[1];
    if (hash !== undefined) {
      return hash.toLowerCase();
    }
  }
  return undefined;
}

function parseCanisterStatus(output: string): {
  readonly controllers: readonly string[];
  readonly cycles: bigint | undefined;
  readonly freezingThreshold: bigint | undefined;
  readonly moduleHash: string | undefined;
} {
  const json = parseJsonRecord(output);
  if (json !== undefined) {
    const settings = isRecord(json.settings) ? json.settings : undefined;
    return {
      controllers: parseJsonControllers(settings),
      cycles: findDirectBigIntField(json, ["cycles", "cycles_balance", "cyclesBalance", "balance"]),
      freezingThreshold: settings === undefined ? undefined : findDirectBigIntField(settings, ["freezing_threshold", "freezingThreshold"]),
      moduleHash: parseJsonModuleHash(json)
    };
  }
  return {
    controllers: collectPrincipalTextsFromText(output),
    cycles: parseLabeledBigInt(output, /cycles(?:\s+balance)?\s*[:=]\s*([0-9_]+)/i),
    freezingThreshold: parseLabeledBigInt(output, /freezing\s+threshold\s*[:=]\s*([0-9_]+)/i),
    moduleHash: parseCanisterModuleHash(output)
  };
}

function parseJsonRecord(output: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(output);
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collectPrincipalTextsFromText(output: string): readonly string[] {
  const principals = output.match(/[a-z2-7]{5}(?:-[a-z2-7]{5}){1,}/g) ?? [];
  return Array.from(new Set(principals.filter(isIcPrincipal)));
}

function parseJsonControllers(settings: Record<string, unknown> | undefined): readonly string[] {
  const controllers = settings?.controllers;
  if (!Array.isArray(controllers)) {
    return [];
  }
  const found: string[] = [];
  for (const item of controllers) {
    if (typeof item === "string" && isIcPrincipal(item)) {
      found.push(item);
    } else if (isRecord(item)) {
      const principal = item.principal;
      if (typeof principal === "string" && isIcPrincipal(principal)) {
        found.push(principal);
      }
    }
  }
  return Array.from(new Set(found));
}

function findDirectBigIntField(value: Record<string, unknown>, names: readonly string[]): bigint | undefined {
  for (const name of names) {
    const parsed = parseBigIntLike(value[name]);
    if (parsed !== undefined) {
      return parsed;
    }
  }
  return undefined;
}

function parseJsonModuleHash(value: Record<string, unknown>): string | undefined {
  for (const name of ["wasm_module_hash", "wasmModuleHash", "module_hash", "moduleHash"]) {
    const item = value[name];
    if (typeof item !== "string") {
      continue;
    }
    const match = /^(?:0x)?([0-9a-fA-F]{64})$/.exec(item.trim());
    if (match?.[1] !== undefined) {
      return match[1].toLowerCase();
    }
  }
  return undefined;
}

function parseBigIntLike(value: unknown): bigint | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return BigInt(value);
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const match = /([0-9][0-9_]*)/.exec(value);
  return match?.[1] === undefined ? undefined : BigInt(match[1].replaceAll("_", ""));
}

function parseLabeledBigInt(output: string, pattern: RegExp): bigint | undefined {
  const match = pattern.exec(output);
  return match?.[1] === undefined ? undefined : BigInt(match[1].replaceAll("_", ""));
}

function optionalPositiveBigIntEnv(env: NodeJS.ProcessEnv, name: string): bigint | undefined {
  const value = env[name]?.trim();
  if (value === undefined || value === "") {
    return undefined;
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive integer string`);
  }
  return BigInt(value);
}

function didHasMethod(did: string, method: string): boolean {
  const service = /\bservice\s*:\s*(?:\(\s*\)\s*->\s*)?\{([\s\S]*)\}\s*;?\s*$/.exec(did)?.[1];
  if (service === undefined) {
    return false;
  }
  const escaped = method.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[;\\n])\\s*${escaped}\\s*:\\s*\\(`).test(service);
}

function missingBatchDidStorageItems(did: string): readonly string[] {
  const missing: string[] = [];
  const service = /\bservice\s*:\s*(?:\(\s*\)\s*->\s*)?\{([\s\S]*)\}\s*;?\s*$/.exec(did)?.[1];
  for (const method of REQUIRED_BATCH_DID_METHODS) {
    if (!didHasMethod(did, method)) {
      missing.push(`method ${method}`);
    }
  }
  if (service !== undefined) {
    const serviceShapes: readonly { readonly name: string; readonly pattern: RegExp }[] = [
      { name: "method batch_channel signature", pattern: /\bbatch_channel\s*:\s*\(\s*text\s*\)\s*->\s*\(\s*opt\s+BatchChannel\s*\)\s*query\s*;/ },
      { name: "method batch_channel_count signature", pattern: /\bbatch_channel_count\s*:\s*\(\s*\)\s*->\s*\(\s*nat64\s*\)\s*query\s*;/ },
      { name: "method batch_channels signature", pattern: /\bbatch_channels\s*:\s*\(\s*opt\s+nat64\s*\)\s*->\s*\(\s*vec\s+BatchChannel\s*\)\s*query\s*;/ },
      { name: "method batch_create_payment_intent signature", pattern: /\bbatch_create_payment_intent\s*:\s*\(\s*text\s*,\s*text\s*,\s*text\s*,\s*text\s*,\s*text\s*,\s*text\s*\)\s*->\s*\(\s*Result\s*,?\s*\)\s*;/ },
      { name: "method batch_deleted_channel signature", pattern: /\bbatch_deleted_channel\s*:\s*\(\s*text\s*\)\s*->\s*\(\s*opt\s+BatchDeletedChannel\s*\)\s*query\s*;/ },
      { name: "method batch_deleted_channel_count signature", pattern: /\bbatch_deleted_channel_count\s*:\s*\(\s*\)\s*->\s*\(\s*nat64\s*\)\s*query\s*;/ },
      { name: "method batch_deleted_channels signature", pattern: /\bbatch_deleted_channels\s*:\s*\(\s*opt\s+nat64\s*\)\s*->\s*\(\s*vec\s+BatchDeletedChannel\s*\)\s*query\s*;/ },
      { name: "method batch_mark_payment_intent signature", pattern: /\bbatch_mark_payment_intent\s*:\s*\(\s*text\s*,\s*text\s*\)\s*->\s*\(\s*Result\s*,?\s*\)\s*;/ },
      { name: "method batch_payment_intent signature", pattern: /\bbatch_payment_intent\s*:\s*\(\s*text\s*\)\s*->\s*\(\s*opt\s+BatchPaymentIntent\s*\)\s*query\s*;/ },
      { name: "method batch_receiver_authorizer signature", pattern: /\bbatch_receiver_authorizer\s*:\s*\(\s*\)\s*->\s*\(\s*opt\s+text\s*\)\s*query\s*;/ },
      { name: "method batch_set_seller signature", pattern: /\bbatch_set_seller\s*:\s*\(\s*text\s*,\s*text\s*\)\s*->\s*\(\s*Result_1\s*,?\s*\)\s*;/ },
      { name: "method batch_set_writer_receiver_scope signature", pattern: /\bbatch_set_writer_receiver_scope\s*:\s*\(\s*principal\s*,\s*text\s*,\s*bool\s*\)\s*->\s*\(\s*Result_2\s*,?\s*\)\s*;/ },
      { name: "method batch_settlement_contract signature", pattern: /\bbatch_settlement_contract\s*:\s*\(\s*\)\s*->\s*\(\s*opt\s+text\s*\)\s*query\s*;/ },
      { name: "method batch_settlement_fee_amount signature", pattern: /\bbatch_settlement_fee_amount\s*:\s*\(\s*\)\s*->\s*\(\s*opt\s+text\s*\)\s*query\s*;/ },
      { name: "method batch_update_channel signature", pattern: /\bbatch_update_channel\s*:\s*\(\s*text\s*,\s*opt\s+nat64\s*,\s*BatchChannelUpdate\s*\)\s*->\s*\(\s*BatchChannelUpdateResult\s*,?\s*\)\s*;/ },
      { name: "method batch_writer_receiver_scope signature", pattern: /\bbatch_writer_receiver_scope\s*:\s*\(\s*principal\s*,\s*text\s*\)\s*->\s*\(\s*opt\s+BatchWriterReceiverScope\s*,?\s*\)\s*query\s*;/ },
      { name: "method batch_writer_receiver_scope_count signature", pattern: /\bbatch_writer_receiver_scope_count\s*:\s*\(\s*\)\s*->\s*\(\s*nat64\s*\)\s*query\s*;/ },
      { name: "method batch_writer_receiver_scopes signature", pattern: /\bbatch_writer_receiver_scopes\s*:\s*\(\s*opt\s+nat64\s*\)\s*->\s*\(\s*vec\s+BatchWriterReceiverScope\s*,?\s*\)\s*query\s*;/ },
      { name: "method settlement signature", pattern: /\bsettlement\s*:\s*\(\s*text\s*\)\s*->\s*\(\s*opt\s+SettlementRecord\s*\)\s*query\s*;/ }
    ];
    for (const shape of serviceShapes) {
      if (!shape.pattern.test(service)) {
        missing.push(shape.name);
      }
    }
  }
  for (const shape of REQUIRED_BATCH_DID_SHAPES) {
    if (!shape.pattern.test(did)) {
      missing.push(shape.name);
    }
  }
  return missing;
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

function batchSettlementFeeStage(env: NodeJS.ProcessEnv): BatchProductionReadinessStage {
  const value = env.BATCH_SETTLEMENT_FEE_AMOUNT;
  if (!value || value.trim() === "") {
    return fail("batch:settlement-fee", "BATCH_SETTLEMENT_FEE_AMOUNT is required");
  }
  const amount = value.trim();
  if (!/^[1-9][0-9]*$/.test(amount)) {
    return fail("batch:settlement-fee", "BATCH_SETTLEMENT_FEE_AMOUNT must be a positive integer string");
  }
  if (BigInt(amount) > UINT128_MAX) {
    return fail("batch:settlement-fee", "BATCH_SETTLEMENT_FEE_AMOUNT must fit uint128");
  }
  return ok("batch:settlement-fee", amount);
}

function batchReceiptConfirmationsStage(env: NodeJS.ProcessEnv): BatchProductionReadinessStage {
  const value = env.SETTLE_MIN_CONFIRMATIONS?.trim();
  if (value === undefined || value === "") {
    return ok("batch:receipt-confirmations", "SETTLE_MIN_CONFIRMATIONS defaults to 3");
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    return fail("batch:receipt-confirmations", "SETTLE_MIN_CONFIRMATIONS must be a positive integer for production batch receipts");
  }
  const confirmations = Number(value);
  if (!Number.isSafeInteger(confirmations)) {
    return fail("batch:receipt-confirmations", "SETTLE_MIN_CONFIRMATIONS is too large");
  }
  if (confirmations < MIN_BATCH_RECEIPT_CONFIRMATIONS) {
    return fail("batch:receipt-confirmations", "SETTLE_MIN_CONFIRMATIONS must be 3 or higher for production batch receipts");
  }
  return ok("batch:receipt-confirmations", `SETTLE_MIN_CONFIRMATIONS=${confirmations}`);
}

function normalizeEvmAddress(value: string, label: string): string {
  const address = value.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address) || /^0x0{40}$/i.test(address)) {
    throw new Error(`${label} must be a non-zero EVM address`);
  }
  return address.toLowerCase();
}

function isPrivateKey(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function receiverAuthorizerFromEnv(env: NodeJS.ProcessEnv): string {
  const key = env.BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY?.trim();
  if (!key) {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY is required");
  }
  if (!isPrivateKey(key)) {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a 0x-prefixed 32-byte private key");
  }
  try {
    return normalizeEvmAddress(privateKeyToAccount(key).address, "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  } catch {
    throw new Error("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must be a valid secp256k1 private key");
  }
}

function facilitatorAddressFromEnv(env: NodeJS.ProcessEnv): string {
  const key = env.FACILITATOR_EVM_PRIVATE_KEY?.trim();
  if (!key) {
    throw new Error("FACILITATOR_EVM_PRIVATE_KEY is required");
  }
  if (!isPrivateKey(key)) {
    throw new Error("FACILITATOR_EVM_PRIVATE_KEY must be a 0x-prefixed 32-byte private key");
  }
  try {
    return normalizeEvmAddress(privateKeyToAccount(key).address, "FACILITATOR_EVM_PRIVATE_KEY");
  } catch {
    throw new Error("FACILITATOR_EVM_PRIVATE_KEY must be a valid secp256k1 private key");
  }
}

function batchKeySeparationStage(env: NodeJS.ProcessEnv): BatchProductionReadinessStage {
  let receiverAuthorizer: string;
  let facilitator: string;
  try {
    receiverAuthorizer = receiverAuthorizerFromEnv(env);
    facilitator = facilitatorAddressFromEnv(env);
  } catch (error: unknown) {
    return fail("batch:key-separation", error instanceof Error ? error.message : String(error));
  }
  if (receiverAuthorizer === facilitator) {
    return fail(
      "batch:key-separation",
      "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address"
    );
  }
  return ok("batch:key-separation", `receiverAuthorizer=${receiverAuthorizer} facilitator=${facilitator}`);
}

function parseOptionalText(output: string): string | undefined {
  const match = /^\s*\(\s*opt\s+"([^"]+)"\s*,?\s*\)\s*$/.exec(output);
  return match?.[1];
}

function parseNat64Output(output: string): bigint | undefined {
  const match = /^\s*\(\s*([0-9][0-9_]*)\s*:\s*nat64\s*,?\s*\)\s*$/.exec(output);
  return match?.[1] === undefined ? undefined : BigInt(match[1].replaceAll("_", ""));
}

function canisterWriterScopeStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "call", canister, "batch_writer_receiver_scope_count", "()", "--environment", environment], cwd);
  if (result.status !== 0) {
    return fail("canister:batch-writer-scope", result.output || "failed to query batch_writer_receiver_scope_count");
  }
  const count = parseNat64Output(result.output);
  if (count === undefined) {
    return fail("canister:batch-writer-scope", `unexpected batch_writer_receiver_scope_count output: ${result.output}`);
  }
  if (count === 0n) {
    return fail("canister:batch-writer-scope", "active seller writer receiver scope count must be greater than 0");
  }
  return ok("canister:batch-writer-scope", `${canister}@${environment} active seller enabled scopes=${count.toString()}`);
}

function canisterReceiverAuthorizerStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  let expected: string;
  try {
    expected = receiverAuthorizerFromEnv(env);
  } catch (error: unknown) {
    return fail("canister:batch-receiver-authorizer", error instanceof Error ? error.message : String(error));
  }
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "call", canister, "batch_receiver_authorizer", "()", "--environment", environment], cwd);
  if (result.status !== 0) {
    return fail("canister:batch-receiver-authorizer", result.output || "failed to query batch_receiver_authorizer");
  }
  const actualText = parseOptionalText(result.output);
  if (!actualText) {
    return fail("canister:batch-receiver-authorizer", "batch receiver authorizer is not configured on canister");
  }
  let actual: string;
  try {
    actual = normalizeEvmAddress(actualText, "batch_receiver_authorizer");
  } catch (error: unknown) {
    return fail("canister:batch-receiver-authorizer", error instanceof Error ? error.message : String(error));
  }
  if (actual !== expected) {
    return fail("canister:batch-receiver-authorizer", `expected ${expected}, got ${actual}`);
  }
  return ok("canister:batch-receiver-authorizer", `${canister}@${environment} receiver authorizer ${actual}`);
}

function canisterSettlementContractStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const value = env.BATCH_SETTLEMENT_CONTRACT?.trim();
  if (!value) {
    return fail("canister:batch-settlement-contract", "BATCH_SETTLEMENT_CONTRACT is required");
  }
  let expected: string;
  try {
    expected = normalizeEvmAddress(value, "BATCH_SETTLEMENT_CONTRACT");
  } catch (error: unknown) {
    return fail("canister:batch-settlement-contract", error instanceof Error ? error.message : String(error));
  }
  if (expected !== BATCH_SETTLEMENT_ADDRESS.toLowerCase()) {
    return fail(
      "canister:batch-settlement-contract",
      `BATCH_SETTLEMENT_CONTRACT must equal official @x402/evm BATCH_SETTLEMENT_ADDRESS ${BATCH_SETTLEMENT_ADDRESS}`
    );
  }
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "call", canister, "batch_settlement_contract", "()", "--environment", environment], cwd);
  if (result.status !== 0) {
    return fail("canister:batch-settlement-contract", result.output || "failed to query batch_settlement_contract");
  }
  const actualText = parseOptionalText(result.output);
  if (!actualText) {
    return fail("canister:batch-settlement-contract", "batch settlement contract is not configured on canister");
  }
  let actual: string;
  try {
    actual = normalizeEvmAddress(actualText, "batch_settlement_contract");
  } catch (error: unknown) {
    return fail("canister:batch-settlement-contract", error instanceof Error ? error.message : String(error));
  }
  if (actual !== expected) {
    return fail("canister:batch-settlement-contract", `expected ${expected}, got ${actual}`);
  }
  return ok("canister:batch-settlement-contract", `${canister}@${environment} contract ${actual}`);
}

function canisterSettlementFeeStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const expected = env.BATCH_SETTLEMENT_FEE_AMOUNT?.trim();
  if (!expected) {
    return fail("canister:batch-settlement-fee", "BATCH_SETTLEMENT_FEE_AMOUNT is required");
  }
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "call", canister, "batch_settlement_fee_amount", "()", "--environment", environment], cwd);
  if (result.status !== 0) {
    return fail("canister:batch-settlement-fee", result.output || "failed to query batch_settlement_fee_amount");
  }
  const actual = parseOptionalText(result.output);
  if (!actual) {
    return fail("canister:batch-settlement-fee", "batch settlement fee amount is not configured on canister");
  }
  if (actual !== expected) {
    return fail("canister:batch-settlement-fee", `expected ${expected}, got ${actual}`);
  }
  return ok("canister:batch-settlement-fee", `${canister}@${environment} fee ${actual}`);
}

function canisterEnvStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "call", canister, "env_names", "()", "--environment", environment], cwd);
  if (result.status !== 0) {
    return fail("canister:batch-env", result.output || "failed to query canister env_names");
  }
  let names: string[];
  try {
    names = parseEnvNames(result.output);
  } catch (error: unknown) {
    return fail("canister:batch-env", error instanceof Error ? error.message : String(error));
  }
  const missing = REQUIRED_BATCH_ENV_NAMES.filter((name) => !names.includes(name));
  if (missing.length > 0) {
    return fail("canister:batch-env", `missing canister batch env names: ${missing.join(", ")}`);
  }
  return ok("canister:batch-env", `${canister}@${environment} batch env names present`);
}

function canisterStorageApiStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const count = runner("icp", ["canister", "call", canister, "batch_channel_count", "()", "--environment", environment], cwd);
  if (count.status !== 0) {
    return fail("canister:batch-storage-api", count.output || "failed to query batch_channel_count");
  }
  const channelCount = parseNat64Output(count.output);
  if (channelCount === undefined) {
    return fail("canister:batch-storage-api", `unexpected batch_channel_count output: ${count.output}`);
  }
  if (channelCount > MAX_BATCH_CHANNELS_LIST) {
    return fail("canister:batch-storage-api", `batch channel count ${channelCount} exceeds list limit ${MAX_BATCH_CHANNELS_LIST}`);
  }
  const channel = runner(
    "icp",
    ["canister", "call", canister, "batch_channel", `("${READINESS_BATCH_CHANNEL_ID}")`, "--environment", environment],
    cwd
  );
  if (channel.status !== 0) {
    return fail("canister:batch-storage-api", channel.output || "failed to query batch_channel");
  }
  if (!isOptionalBatchChannelOutput(channel.output)) {
    return fail("canister:batch-storage-api", `unexpected batch_channel output: ${channel.output}`);
  }
  const listLimit = channelCount === 0n ? 1n : channelCount;
  const list = runner(
    "icp",
    ["canister", "call", canister, "batch_channels", `(opt (${listLimit.toString()} : nat64))`, "--environment", environment],
    cwd
  );
  if (list.status !== 0) {
    return fail("canister:batch-storage-api", list.output || "failed to query batch_channels");
  }
  if (!isBatchChannelsListOutput(list.output)) {
    return fail("canister:batch-storage-api", `unexpected batch_channels output: ${list.output}`);
  }
  const listedChannels = countBatchChannelRecords(list.output);
  if (channelCount === 0n && !isEmptyBatchChannelsListOutput(list.output)) {
    return fail("canister:batch-storage-api", `batch_channel_count is 0 but batch_channels returned non-empty output`);
  }
  if (channelCount > 0n && listedChannels === 0n) {
    return fail(
      "canister:batch-storage-api",
      `batch_channel_count is ${channelCount.toString()} but batch_channels returned no channel records`
    );
  }
  if (listedChannels !== channelCount) {
    return fail(
      "canister:batch-storage-api",
      `batch_channel_count is ${channelCount.toString()} but batch_channels returned ${listedChannels.toString()} channel records`
    );
  }
  const deletedCount = runner("icp", ["canister", "call", canister, "batch_deleted_channel_count", "()", "--environment", environment], cwd);
  if (deletedCount.status !== 0) {
    return fail("canister:batch-storage-api", deletedCount.output || "failed to query batch_deleted_channel_count");
  }
  const deletedChannelCount = parseNat64Output(deletedCount.output);
  if (deletedChannelCount === undefined) {
    return fail("canister:batch-storage-api", `unexpected batch_deleted_channel_count output: ${deletedCount.output}`);
  }
  if (deletedChannelCount > MAX_BATCH_CHANNELS_LIST) {
    return fail("canister:batch-storage-api", `batch deleted channel count ${deletedChannelCount} exceeds list limit ${MAX_BATCH_CHANNELS_LIST}`);
  }
  const deletedChannel = runner(
    "icp",
    ["canister", "call", canister, "batch_deleted_channel", `("${READINESS_BATCH_CHANNEL_ID}")`, "--environment", environment],
    cwd
  );
  if (deletedChannel.status !== 0) {
    return fail("canister:batch-storage-api", deletedChannel.output || "failed to query batch_deleted_channel");
  }
  if (!isOptionalBatchDeletedChannelOutput(deletedChannel.output)) {
    return fail("canister:batch-storage-api", `unexpected batch_deleted_channel output: ${deletedChannel.output}`);
  }
  const deletedListLimit = deletedChannelCount === 0n ? 1n : deletedChannelCount;
  const deletedList = runner(
    "icp",
    ["canister", "call", canister, "batch_deleted_channels", `(opt (${deletedListLimit.toString()} : nat64))`, "--environment", environment],
    cwd
  );
  if (deletedList.status !== 0) {
    return fail("canister:batch-storage-api", deletedList.output || "failed to query batch_deleted_channels");
  }
  if (!isBatchDeletedChannelsListOutput(deletedList.output)) {
    return fail("canister:batch-storage-api", `unexpected batch_deleted_channels output: ${deletedList.output}`);
  }
  const listedDeletedChannels = countBatchDeletedChannelRecords(deletedList.output);
  if (deletedChannelCount === 0n && !isEmptyBatchChannelsListOutput(deletedList.output)) {
    return fail("canister:batch-storage-api", "batch_deleted_channel_count is 0 but batch_deleted_channels returned non-empty output");
  }
  if (deletedChannelCount > 0n && listedDeletedChannels === 0n) {
    return fail(
      "canister:batch-storage-api",
      `batch_deleted_channel_count is ${deletedChannelCount.toString()} but batch_deleted_channels returned no channel records`
    );
  }
  if (listedDeletedChannels !== deletedChannelCount) {
    return fail(
      "canister:batch-storage-api",
      `batch_deleted_channel_count is ${deletedChannelCount.toString()} but batch_deleted_channels returned ${listedDeletedChannels.toString()} channel records`
    );
  }
  return ok("canister:batch-storage-api", `${canister}@${environment} batch channel storage APIs ok count=${channelCount.toString()} deleted=${deletedChannelCount.toString()}`);
}

function isOptionalBatchChannelOutput(output: string): boolean {
  const value = output.trim();
  return /^\(\s*null\s*\)$/.test(value) ||
    (/^\(\s*opt\s+record\b[\s\S]*\)\s*$/.test(value) && hasBatchChannelOutputFields(value));
}

function isOptionalBatchDeletedChannelOutput(output: string): boolean {
  const value = output.trim();
  return /^\(\s*null\s*\)$/.test(value) ||
    (/^\(\s*opt\s+record\b[\s\S]*\)\s*$/.test(value) && hasBatchDeletedChannelOutputFields(value));
}

function countBatchChannelRecords(output: string): bigint {
  return BigInt(output.match(/\brecord\s*\{[\s\S]*?\bchannel_id\s*=/g)?.length ?? 0);
}

function countBatchDeletedChannelRecords(output: string): bigint {
  return BigInt(output.match(/\brecord\s*\{[\s\S]*?\bdeleted_at\s*=/g)?.length ?? 0);
}

function isBatchChannelsListOutput(output: string): boolean {
  const inner = batchChannelsListInner(output);
  if (inner === undefined) {
    return false;
  }
  const trimmed = inner.trim();
  return trimmed === "" ||
    (/^record\b[\s\S]*\bchannel_id\s*=[\s\S]*\}\s*;?\s*(?:record\b[\s\S]*\bchannel_id\s*=[\s\S]*\}\s*;?\s*)*$/.test(trimmed) &&
      hasBatchChannelOutputFields(trimmed));
}

function isBatchDeletedChannelsListOutput(output: string): boolean {
  const inner = batchChannelsListInner(output);
  if (inner === undefined) {
    return false;
  }
  const trimmed = inner.trim();
  return trimmed === "" ||
    (/^record\b[\s\S]*\bdeleted_at\s*=[\s\S]*\}\s*;?\s*(?:record\b[\s\S]*\bdeleted_at\s*=[\s\S]*\}\s*;?\s*)*$/.test(trimmed) &&
      hasBatchDeletedChannelOutputFields(trimmed));
}

function isEmptyBatchChannelsListOutput(output: string): boolean {
  return /^\s*\(\s*vec\s*\{\s*\}\s*,?\s*\)\s*$/.test(output);
}

function batchChannelsListInner(output: string): string | undefined {
  return /^\s*\(\s*vec\s*\{([\s\S]*)\}\s*,?\s*\)\s*$/.exec(output)?.[1];
}

function hasBatchChannelOutputFields(output: string): boolean {
  return REQUIRED_BATCH_CHANNEL_OUTPUT_FIELDS.every((field) =>
    new RegExp(`\\b${field}\\s*=`).test(output)
  ) && batchChannelOutputValidationError(output) === undefined;
}

function hasBatchDeletedChannelOutputFields(output: string): boolean {
  return /\bdeleted_at\s*=/.test(output) &&
    /\bdeleted_by\s*=/.test(output) &&
    /\bchannel\s*=\s*record\b/.test(output) &&
    hasBatchChannelOutputFields(output);
}

function batchChannelOutputValidationError(output: string): string | undefined {
  const channelIds = quotedFieldValues(output, "channel_id");
  if (channelIds.length === 0) {
    return "channel_id must be a quoted text field";
  }
  for (const value of channelIds) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(value)) {
      return "channel_id must be a 32-byte 0x-prefixed hex string";
    }
  }
  const signatures = quotedFieldValues(output, "signature");
  if (signatures.length === 0) {
    return "signature must be a quoted text field";
  }
  for (const value of signatures) {
    if (!/^0x[0-9a-fA-F]{130}$/.test(value)) {
      return "signature must be a 65-byte 0x-prefixed hex string";
    }
  }
  for (const field of ["payer", "payer_authorizer", "receiver", "receiver_authorizer", "token"]) {
    const values = quotedFieldValues(output, field);
    if (values.length === 0) {
      return `${field} must be a quoted text field`;
    }
    for (const value of values) {
      if (!/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
        return `${field} must be a non-zero EVM address`;
      }
    }
  }
  for (const field of ["balance", "charged_cumulative_amount", "signed_max_claimable", "total_claimed"]) {
    const values = quotedFieldValues(output, field);
    if (values.length === 0) {
      return `${field} must be a quoted text field`;
    }
    for (const value of values) {
      if (!isBoundedDecimal(value, UINT128_MAX)) {
        return `${field} must be a uint128 decimal string`;
      }
    }
  }
  const refundNonces = quotedFieldValues(output, "refund_nonce");
  if (refundNonces.length === 0) {
    return "refund_nonce must be a quoted text field";
  }
  for (const value of refundNonces) {
    if (!isBoundedDecimal(value, MAX_SAFE_INTEGER_BIGINT)) {
      return "refund_nonce must be a safe decimal integer string";
    }
  }
  const withdrawDelays = nat64FieldValues(output, "withdraw_delay");
  if (withdrawDelays.length === 0) {
    return "withdraw_delay must be a nat64 field";
  }
  for (const value of withdrawDelays) {
    if (value < 900n || value > 2_592_000n) {
      return "withdraw_delay must be between 900 and 2592000";
    }
  }
  return undefined;
}

function quotedFieldValues(output: string, field: string): readonly string[] {
  const pattern = new RegExp(`\\b${field}\\s*=\\s*"([^"]*)"`, "g");
  return Array.from(output.matchAll(pattern), (match) => match[1] ?? "");
}

function nat64FieldValues(output: string, field: string): readonly bigint[] {
  const pattern = new RegExp(`\\b${field}\\s*=\\s*([0-9]+)\\s*:\\s*nat64\\b`, "g");
  return Array.from(output.matchAll(pattern), (match) => BigInt(match[1] ?? "0"));
}

function isBoundedDecimal(value: string, max: bigint): boolean {
  if (value.length === 0 || value.length > MAX_BATCH_STRING_BYTES || !/^[0-9]+$/.test(value)) {
    return false;
  }
  return BigInt(value) <= max;
}

function canisterWasmHashStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string,
  wasmSha256?: string
): BatchProductionReadinessStage {
  if (!wasmSha256) {
    return fail("canister:wasm-hash", "local wasm SHA-256 is unavailable");
  }
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "status", canister, "--environment", environment, "--json"], cwd);
  if (result.status !== 0) {
    return fail("canister:wasm-hash", result.output || "failed to query canister status");
  }
  const deployedHash = parseCanisterStatus(result.output).moduleHash;
  if (!deployedHash) {
    return fail("canister:wasm-hash", `canister status did not include module hash: ${result.output}`);
  }
  if (deployedHash !== wasmSha256) {
    return fail("canister:wasm-hash", `expected ${wasmSha256}, got ${deployedHash}`);
  }
  return ok("canister:wasm-hash", `${canister}@${environment} module hash matches local wasm`);
}

function canisterOperationalSafetyStage(
  env: NodeJS.ProcessEnv,
  runner: CommandRunner,
  cwd: string
): BatchProductionReadinessStage {
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const result = runner("icp", ["canister", "status", canister, "--environment", environment, "--json"], cwd);
  if (result.status !== 0) {
    return fail("canister:operational-safety", result.output || "failed to query canister status");
  }
  const status = parseCanisterStatus(result.output);
  const controllers = status.controllers.filter((principal) => principal !== ANONYMOUS_PRINCIPAL && principal !== MANAGEMENT_PRINCIPAL);
  if (controllers.length < 2) {
    return fail("canister:operational-safety", "canister must have at least two non-system controllers");
  }
  if (status.freezingThreshold === undefined) {
    return fail("canister:operational-safety", "canister status did not include freezing threshold");
  }
  if (status.freezingThreshold < MIN_FREEZING_THRESHOLD_SECONDS) {
    return fail("canister:operational-safety", `freezing threshold below ${MIN_FREEZING_THRESHOLD_SECONDS.toString()} seconds`);
  }
  if (status.cycles === undefined) {
    return fail("canister:operational-safety", "canister status did not include cycles balance");
  }
  let minCycles: bigint;
  try {
    minCycles = optionalPositiveBigIntEnv(env, "BATCH_MIN_CANISTER_CYCLES") ?? DEFAULT_MIN_CANISTER_CYCLES;
  } catch (error: unknown) {
    return fail("canister:operational-safety", error instanceof Error ? error.message : String(error));
  }
  if (status.cycles < minCycles) {
    return fail("canister:operational-safety", `cycles below ${minCycles.toString()}`);
  }
  return ok("canister:operational-safety", `${canister}@${environment} controllers=${controllers.length} cycles=${status.cycles.toString()}`);
}

function commandStage(
  runner: CommandRunner,
  cwd: string,
  name: string,
  command: string,
  args: readonly string[],
  okDetail: string,
  failDetail: string
): BatchProductionReadinessStage {
  const result = runner(command, args, cwd);
  if (result.status === 0) {
    return ok(name, okDetail);
  }
  return fail(name, result.output || failDetail);
}

function artifactStages(
  options: Required<Pick<BatchProductionReadinessOptions, "commandRunner" | "cwd" | "didPath" | "fileReader" | "wasmPath">>
): { readonly stages: readonly BatchProductionReadinessStage[]; readonly wasmSha256?: string } {
  const wasmPath = resolve(options.cwd, options.wasmPath);
  const didPath = resolve(options.cwd, options.didPath);
  const stages: BatchProductionReadinessStage[] = [];
  let wasmHash: string | undefined;

  if (!options.fileReader.exists(wasmPath)) {
    stages.push(fail("wasm:exists", `${options.wasmPath} not found`));
  } else {
    const bytes = options.fileReader.read(wasmPath);
    wasmHash = sha256(bytes);
    stages.push(ok("wasm:sha256", wasmHash));
  }

  if (!options.fileReader.exists(didPath)) {
    stages.push(fail("did:exists", `${options.didPath} not found`));
  } else {
    const did = options.fileReader.read(didPath).toString("utf8");
    stages.push(ok("did:exists", options.didPath));
    const missingItems = missingBatchDidStorageItems(did);
    if (missingItems.length > 0) {
      stages.push(fail("did:batch-storage-api", `missing or mismatched DID batch storage API: ${missingItems.join(", ")}`));
    } else {
      stages.push(ok("did:batch-storage-api", "batch channel storage API shape present"));
    }
    if (options.fileReader.exists(wasmPath)) {
      const generated = options.commandRunner("candid-extractor", [options.wasmPath], options.cwd);
      if (generated.status !== 0) {
        stages.push(fail("did:generated", generated.output || "failed to extract DID from local wasm"));
      } else if (
        normalizeDidServiceConstructor(generated.output).trim() !==
        normalizeDidServiceConstructor(did).trim()
      ) {
        stages.push(fail("did:generated", "dist/facilitator.did does not match local wasm candid-extractor output"));
      } else {
        stages.push(ok("did:generated", "dist/facilitator.did matches local wasm"));
      }
    }
  }
  stages.push(commandStage(
    options.commandRunner,
    options.cwd,
    "did:tracked",
    "git",
    ["ls-files", "--error-unmatch", options.didPath],
    `${options.didPath} tracked`,
    `${options.didPath} is not tracked`
  ));
  stages.push(commandStage(
    options.commandRunner,
    options.cwd,
    "did:clean",
    "git",
    ["diff", "--exit-code", "--", options.didPath],
    `${options.didPath} clean`,
    `${options.didPath} differs from HEAD`
  ));

  return wasmHash ? { stages, wasmSha256: wasmHash } : { stages };
}

async function preflightStages(options: BatchProductionReadinessOptions): Promise<readonly BatchProductionReadinessStage[]> {
  try {
    const report = await checkBatchMainnetPreflight({
      env: options.env,
      ...(options.batchPreflightReader ? { reader: options.batchPreflightReader } : {})
    });
    if (report.ready) {
      return [ok("batch:preflight", "Polygon/JPYC/batch contract read-only checks passed")];
    }
    return report.checks
      .filter((check) => check.status === "fail")
      .map((check) => fail(`batch:preflight:${check.name}`, check.detail));
  } catch (error: unknown) {
    return [fail("batch:preflight", error instanceof Error ? error.message : String(error))];
  }
}

async function receiptStages(options: BatchProductionReadinessOptions): Promise<readonly BatchProductionReadinessStage[]> {
  const stages: BatchProductionReadinessStage[] = [];
  for (const action of BATCH_SETTLEMENT_ACTIONS) {
    try {
      const result = await verifyBatchSettlementReceipt({
        ...batchSettlementReceiptOptionsForActionFromEnv(options.env, action),
        ...(options.batchSettlementReceiptReader ? { reader: options.batchSettlementReceiptReader } : {})
      });
      stages.push(ok(`batch:receipt:${action}`, batchReceiptStageDetail(result)));
    } catch (error: unknown) {
      stages.push(fail(`batch:receipt:${action}`, error instanceof Error ? error.message : String(error)));
    }
  }
  return stages;
}

function batchReceiptStageDetail(result: BatchSettlementReceiptResult): string {
  const base = `${result.action} tx=${result.hash} block=${result.blockNumber} confirmations=${result.confirmations}`;
  if (result.receiverState) {
    return `${base} receiver=${result.receiverState.receiver} token=${result.receiverState.token} settledAmount=${result.receiverState.settledAmount} totalClaimed=${result.receiverState.totalClaimed} totalSettled=${result.receiverState.totalSettled}`;
  }
  if (result.channelState) {
    const refundNonce = result.channelState.refundNonce === undefined ? "" : ` refundNonce=${result.channelState.refundNonce}`;
    return `${base} channel=${result.channelState.channelId} balance=${result.channelState.balance} totalClaimed=${result.channelState.totalClaimed}${refundNonce}`;
  }
  return base;
}

async function batchSupportedStage(options: BatchProductionReadinessOptions): Promise<BatchProductionReadinessStage> {
  try {
    const environment = options.env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
    const baseUrl = options.env.X402_BASE_URL;
    if (environment === "ic") {
      if (!baseUrl || baseUrl.trim() === "") {
        return fail("canister:batch-supported", "X402_BASE_URL is required for mainnet batch readiness");
      }
      if (!isHttpsOrigin(baseUrl)) {
        return fail("canister:batch-supported", "X402_BASE_URL must be a https://host[:port] origin for mainnet batch readiness");
      }
    }
    const result = await checkCanisterSmoke({
      env: options.env,
      ...(options.fetchFn ? { fetchFn: options.fetchFn } : {}),
      requireBatch: true
    });
    const expectedFacilitator = facilitatorAddressFromEnv(options.env);
    const actualFacilitator = normalizeEvmAddress(result.facilitatorAddress, "health.facilitatorAddress");
    if (actualFacilitator !== expectedFacilitator) {
      return fail("canister:batch-supported", `health.facilitatorAddress mismatch: expected ${expectedFacilitator}, got ${actualFacilitator}`);
    }
    return ok("canister:batch-supported", `${result.baseUrl} advertises batch-settlement`);
  } catch (error: unknown) {
    return fail("canister:batch-supported", error instanceof Error ? error.message : String(error));
  }
}

function nextCommands(
  stages: readonly BatchProductionReadinessStage[],
  requireBatchReceipt: boolean,
  env: NodeJS.ProcessEnv
): readonly string[] {
  const commands: string[] = [];
  const canister = env.ICP_CANISTER ?? DEFAULT_ICP_CANISTER;
  const environment = env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT;
  for (const stage of stages) {
    if (stage.status !== "fail" || !stage.name.startsWith("batch:preflight")) {
      continue;
    }
    for (const command of preflightNextCommands(stage.name)) {
      commands.push(command);
    }
  }
  if (requireBatchReceipt && stages.some((stage) => stage.name.startsWith("batch:receipt:") && stage.status === "fail")) {
    commands.push(...batchReceiptEnvNextCommands(stages));
    commands.push("npm run receipt:batch:all");
  }
  if (stages.some((stage) => stage.name === "batch:receipt-confirmations" && stage.status === "fail")) {
    commands.push("set SETTLE_MIN_CONFIRMATIONS to 3 or higher for production batch receipt verification");
  }
  if (stages.some((stage) => stage.name === "batch:settlement-fee" && stage.status === "fail")) {
    commands.push("set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer");
  }
  if (stages.some((stage) => stage.name === "batch:key-separation" && stage.status === "fail")) {
    commands.push("use different private keys for FACILITATOR_EVM_PRIVATE_KEY and BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY");
  }
  if (stages.some((stage) => stage.name === "canister:batch-env" && stage.status === "fail")) {
    commands.push(canisterEnvCommand(environment, canister));
    commands.push(canisterEnvSmokeCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-writer-scope" && stage.status === "fail")) {
    commands.push(`icp canister call ${canister} batch_set_seller '("<receiver-address>", "active")' -e ${environment}`);
    commands.push(`icp canister call ${canister} batch_set_writer_receiver_scope '(principal "<writer-principal>", "<receiver-address>", true)' -e ${environment}`);
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-receiver-authorizer" && stage.status === "fail")) {
    commands.push(canisterEnvCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-settlement-contract" && stage.status === "fail")) {
    commands.push(canisterEnvCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-settlement-fee" && stage.status === "fail")) {
    commands.push(canisterEnvCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-supported" && stage.status === "fail")) {
    if (!env.X402_BASE_URL || env.X402_BASE_URL.trim() === "") {
      commands.push("set X402_BASE_URL to the deployed canister HTTPS origin");
    } else if ((env.ICP_ENVIRONMENT ?? DEFAULT_ICP_ENVIRONMENT) === "ic" && !isHttpsOrigin(env.X402_BASE_URL)) {
      commands.push("set X402_BASE_URL to a https://host[:port] origin");
    }
    commands.push(smokeCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:batch-storage-api" && stage.status === "fail")) {
    commands.push("npm run build");
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:wasm-hash" && stage.status === "fail")) {
    commands.push("npm run build");
    commands.push(deployCommand(environment, canister));
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name === "canister:operational-safety" && stage.status === "fail")) {
    commands.push(`icp canister settings update ${canister} --freezing-threshold 7776000 -e ${environment}`);
    commands.push(`icp canister settings update ${canister} --add-controller <backup-principal> -e ${environment}`);
    commands.push(readinessCommand(environment, canister, requireBatchReceipt));
  }
  if (stages.some((stage) => stage.name.startsWith("wasm:") && stage.status === "fail")) {
    commands.push("npm run build");
  }
  if (stages.some((stage) => stage.name.startsWith("did:") && stage.status === "fail")) {
    commands.push("npm run did:generate");
    commands.push("npm run did:check");
  }
  return uniqueCommands(commands);
}

function batchReceiptEnvNextCommands(stages: readonly BatchProductionReadinessStage[]): readonly string[] {
  const commands: string[] = [];
  for (const stage of stages) {
    if (!stage.name.startsWith("batch:receipt:") || stage.status !== "fail") {
      continue;
    }
    const envName = receiptEnvNameFromDetail(stage.detail);
    const command = envName === undefined ? undefined : BATCH_RECEIPT_ENV_NEXT_COMMANDS[envName];
    if (command !== undefined) {
      commands.push(command);
    }
  }
  return uniqueCommands(commands);
}

function receiptEnvNameFromDetail(detail: string): string | undefined {
  return /^missing required env: ([A-Z0-9_]+)$/.exec(detail)?.[1] ??
    /^([A-Z0-9_]+) (?:must|is required)\b/.exec(detail)?.[1];
}

function preflightNextCommands(stageName: string): readonly string[] {
  switch (stageName) {
    case "batch:preflight:env:POLYGON_RPC_URL":
      return ["set POLYGON_RPC_URL to a Polygon HTTPS RPC URL"];
    case "batch:preflight:env:JPYC_POLYGON_ADDRESS":
      return ["unset JPYC_POLYGON_ADDRESS or set it to the fixed JPYC Polygon address"];
    case "batch:preflight:env:JPYC_EIP712_VERSION":
      return ["set JPYC_EIP712_VERSION=1"];
    case "batch:preflight:env:BATCH_SETTLEMENT_CONTRACT":
      return [`set BATCH_SETTLEMENT_CONTRACT=${BATCH_SETTLEMENT_ADDRESS}`];
    case "batch:preflight:env:BATCH_WITHDRAW_DELAY_SECONDS":
      return ["set BATCH_WITHDRAW_DELAY_SECONDS to the deployed batch withdraw delay in seconds"];
    case "batch:preflight:env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY":
      return ["set BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY to the receiver authorizer private key"];
    case "batch:preflight:env:BATCH_SETTLEMENT_FEE_AMOUNT":
      return ["set BATCH_SETTLEMENT_FEE_AMOUNT to a positive JPYC atomic-unit integer"];
    default:
      return ["npm run preflight:batch"];
  }
}

function uniqueCommands(commands: readonly string[]): readonly string[] {
  return Array.from(new Set(commands));
}

function canisterEnvCommand(environment: string, canister: string): string {
  if (environment === "ic" && canister === DEFAULT_ICP_CANISTER) {
    return "ICP_ENVIRONMENT=ic npm run ic:env:mainnet";
  }
  if (environment === "local" && canister === DEFAULT_ICP_CANISTER) {
    return "ICP_ENVIRONMENT=local npm run ic:env:local";
  }
  return `scripts/set_canister_env.sh ${environment} ${canister}`;
}

function deployCommand(environment: string, canister: string): string {
  if (environment === "ic" && canister === DEFAULT_ICP_CANISTER) {
    return "ICP_ENVIRONMENT=ic npm run ic:deploy:mainnet";
  }
  if (environment === "local" && canister === DEFAULT_ICP_CANISTER) {
    return "ICP_ENVIRONMENT=local npm run ic:deploy:local";
  }
  return `icp deploy -e ${environment} ${canister} --yes`;
}

function readinessCommand(environment: string, canister: string, requireBatchReceipt: boolean): string {
  const script = requireBatchReceipt ? "verify:batch" : "verify:batch:preflight";
  return `ICP_ENVIRONMENT=${environment} ICP_CANISTER=${canister} npm run ${script}`;
}

function canisterEnvSmokeCommand(environment: string, canister: string): string {
  return `ICP_ENVIRONMENT=${environment} ICP_CANISTER=${canister} npm run smoke:canister:env -- --with-batch`;
}

function smokeCommand(environment: string, canister: string): string {
  return `ICP_ENVIRONMENT=${environment} ICP_CANISTER=${canister} npm run smoke:canister -- --with-batch`;
}

export async function buildBatchProductionReadinessReport(
  options: BatchProductionReadinessOptions
): Promise<BatchProductionReadinessReport> {
  const cwd = options.cwd ?? process.cwd();
  const requireBatchReceipt = options.requireBatchReceipt ?? true;
  const commandRunner = options.commandRunner ?? defaultCommandRunner;
  const artifact = artifactStages({
    commandRunner,
    cwd,
    didPath: options.didPath ?? DEFAULT_DID_PATH,
    fileReader: options.fileReader ?? defaultFileReader,
    wasmPath: options.wasmPath ?? DEFAULT_WASM_PATH
  });
  let stages = [
    ...await preflightStages(options),
    batchSettlementFeeStage(options.env),
    batchKeySeparationStage(options.env),
    canisterEnvStage(options.env, commandRunner, cwd),
    canisterWriterScopeStage(options.env, commandRunner, cwd),
    canisterReceiverAuthorizerStage(options.env, commandRunner, cwd),
    canisterSettlementContractStage(options.env, commandRunner, cwd),
    canisterSettlementFeeStage(options.env, commandRunner, cwd),
    canisterStorageApiStage(options.env, commandRunner, cwd),
    canisterWasmHashStage(options.env, commandRunner, cwd, artifact.wasmSha256),
    canisterOperationalSafetyStage(options.env, commandRunner, cwd),
    await batchSupportedStage(options),
    ...artifact.stages
  ];
  if (requireBatchReceipt) {
    stages = [...stages, batchReceiptConfirmationsStage(options.env), ...await receiptStages(options)];
  }

  return {
    nextCommands: nextCommands(stages, requireBatchReceipt, options.env),
    ready: stages.every((stage) => stage.status === "ok"),
    stages,
    ...(artifact.wasmSha256 ? { wasmSha256: artifact.wasmSha256 } : {})
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  buildBatchProductionReadinessReport({
    env: process.env,
    requireBatchReceipt: !process.argv.includes("--preflight-only")
  }).then((report) => {
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
