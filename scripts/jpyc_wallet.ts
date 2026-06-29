// scripts/jpyc_wallet.ts: buyer wallet の JPYC 残高を確認し、EIP-3009 決済前提を集約する。
import { pathToFileURL } from "node:url";

import { createPublicClient, formatEther, formatUnits, http, parseAbi } from "viem";
import type { Address, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";

import { positiveDecimalToAtomicUnits } from "../src/amount";
import { loadDotenv } from "./env_file";
import { normalizePolygonRpcUrl } from "./rpc_url";

const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const DEFAULT_JPYC_PRICE = "1";
const JPYC_DECIMALS = 18;
const ERC20_ABI = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)"
]);

function readEnv(name: string): string | undefined {
  return process.env[name];
}

function requireEnv(name: string): string {
  const value = readEnv(name);
  if (!value || value.trim() === "") {
    throw new Error(`missing required env: ${name}`);
  }
  return value;
}

function isHex(value: string): value is Hex {
  return /^0x[0-9a-fA-F]+$/.test(value);
}

function isAddress(value: string): value is Address {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function requirePrivateKey(): Hex {
  const value = requireEnv("BUYER_EVM_PRIVATE_KEY");
  if (!isHex(value) || value.length !== 66) {
    throw new Error("BUYER_EVM_PRIVATE_KEY must be a 32-byte 0x-prefixed hex private key");
  }
  return value;
}

function readAddress(name: string, defaultValue: Address): Address {
  const value = readEnv(name) ?? defaultValue;
  if (!isAddress(value) || /^0x0{40}$/i.test(value)) {
    throw new Error(`${name} must be a non-zero 0x-prefixed EVM address`);
  }
  return value;
}

function readAmount(name: string, defaultValue: string): bigint {
  return BigInt(positiveDecimalToAtomicUnits(readEnv(name) ?? defaultValue, JPYC_DECIMALS, name));
}

export function hasRequiredAmount(value: bigint, requiredAmount: bigint): boolean {
  return value >= requiredAmount;
}

export function walletRequirementFailure(hasRequiredBalance: boolean): string | null {
  return hasRequiredBalance ? null : "buyer wallet is missing required JPYC balance";
}

export function fundingNextActions(
  buyer: Address,
  hasRequiredBalance: boolean,
  requiredAmountHuman: string
): readonly string[] {
  return hasRequiredBalance ? [] : [`send at least ${requiredAmountHuman} JPYC on Polygon to ${buyer}`];
}

export function walletRequirementSummary(balance: bigint, nativeBalance: bigint, requiredAmount: bigint): {
  readonly hasNativeGasBalance: boolean;
  readonly hasRequiredBalance: boolean;
  readonly nativeGasRequired: false;
  readonly requirementFailure: string | null;
} {
  const hasRequiredBalance = hasRequiredAmount(balance, requiredAmount);
  return {
    hasNativeGasBalance: nativeBalance > 0n,
    hasRequiredBalance,
    nativeGasRequired: false,
    requirementFailure: walletRequirementFailure(hasRequiredBalance)
  };
}

type WalletState = {
  readonly account: ReturnType<typeof privateKeyToAccount>;
  readonly balance: bigint;
  readonly decimals: number;
  readonly jpyc: Address;
  readonly nativeBalance: bigint;
  readonly requiredAmount: bigint;
};

async function loadWalletState(privateKey: Hex): Promise<WalletState> {
  const rpcUrl = normalizePolygonRpcUrl(requireEnv("POLYGON_RPC_URL"));
  const account = privateKeyToAccount(privateKey);
  const jpyc = readAddress("JPYC_POLYGON_ADDRESS", DEFAULT_JPYC_POLYGON_ADDRESS);
  const requiredAmount = readAmount("JPYC_PRICE", DEFAULT_JPYC_PRICE);
  const publicClient = createPublicClient({
    chain: polygon,
    transport: http(rpcUrl)
  });
  const decimals = await publicClient.readContract({
    address: jpyc,
    abi: ERC20_ABI,
    functionName: "decimals"
  });
  if (decimals !== JPYC_DECIMALS) {
    throw new Error(`unexpected JPYC decimals: ${decimals}`);
  }
  const balance = await publicClient.readContract({
    address: jpyc,
    abi: ERC20_ABI,
    functionName: "balanceOf",
    args: [account.address]
  });
  const nativeBalance = await publicClient.getBalance({ address: account.address });
  return { account, balance, decimals, jpyc, nativeBalance, requiredAmount };
}

export async function checkWallet(privateKey: Hex = requirePrivateKey()): Promise<Record<string, unknown>> {
  const { account, balance, decimals, jpyc, nativeBalance, requiredAmount } = await loadWalletState(privateKey);
  const requirement = walletRequirementSummary(balance, nativeBalance, requiredAmount);
  const requiredAmountHuman = formatUnits(requiredAmount, JPYC_DECIMALS);
  if (requirement.requirementFailure) {
    throw new Error(
      [
        requirement.requirementFailure,
        `nextActions: ${fundingNextActions(account.address, requirement.hasRequiredBalance, requiredAmountHuman).join("; ")}`
      ].join("; ")
    );
  }
  return {
    address: account.address,
    balance: balance.toString(),
    balanceHuman: formatUnits(balance, JPYC_DECIMALS),
    decimals,
    jpyc,
    nativeBalance: nativeBalance.toString(),
    nativeBalanceHuman: formatEther(nativeBalance),
    nativeGasRequired: false,
    requiredAmount: requiredAmount.toString(),
    requiredAmountHuman
  };
}

async function main(): Promise<void> {
  const { account, balance, decimals, jpyc, nativeBalance, requiredAmount } = await loadWalletState(requirePrivateKey());
  const requirement = walletRequirementSummary(balance, nativeBalance, requiredAmount);
  const requiredAmountHuman = formatUnits(requiredAmount, JPYC_DECIMALS);
  const result = {
    buyer: account.address,
    jpyc,
    decimals,
    requiredAmount: requiredAmount.toString(),
    requiredAmountHuman,
    balance: balance.toString(),
    balanceHuman: formatUnits(balance, JPYC_DECIMALS),
    nativeBalance: nativeBalance.toString(),
    nativeBalanceHuman: formatEther(nativeBalance),
    nativeGasRequired: false,
    hasRequiredBalance: requirement.hasRequiredBalance,
    requirementFailure: requirement.requirementFailure,
    hasNativeGasBalance: requirement.hasNativeGasBalance,
    nextActions: fundingNextActions(account.address, requirement.hasRequiredBalance, requiredAmountHuman)
  };

  console.log(JSON.stringify(result, null, 2));

  if (result.requirementFailure) {
    process.exitCode = 1;
  }
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  main().catch((error: unknown) => {
    if (typeof error === "object" && error !== null && "shortMessage" in error && typeof error.shortMessage === "string") {
      console.error(error.shortMessage);
    } else {
      const message = error instanceof Error ? error.message : String(error);
      console.error(message);
    }
    process.exitCode = 1;
  });
}
