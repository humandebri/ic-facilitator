// scripts/jpyc_wallet.ts: buyer wallet の JPYC 残高と Permit2 allowance を確認し、必要なら approve を送信する。
import { pathToFileURL } from "node:url";

import { createPermit2ApprovalTx, PERMIT2_ADDRESS } from "@x402/evm";
import { createPublicClient, createWalletClient, formatEther, formatUnits, http, maxUint256, parseAbi } from "viem";
import type { Address, Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";

import { positiveDecimalToAtomicUnits } from "../src/amount";
import { loadDotenv } from "./env_file";

const DEFAULT_JPYC_POLYGON_ADDRESS = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const DEFAULT_JPYC_PRICE = "1";
const JPYC_DECIMALS = 18;
const ERC20_ABI = parseAbi([
  "function allowance(address owner, address spender) view returns (uint256)",
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

export function walletRequirementFailure(hasRequiredBalance: boolean, hasPermit2Allowance: boolean): string | null {
  if (hasRequiredBalance && hasPermit2Allowance) { return null; }
  const missing = [
    ...(hasRequiredBalance ? [] : ["JPYC balance"]),
    ...(hasPermit2Allowance ? [] : ["Permit2 allowance"])
  ];
  return `buyer wallet is missing required ${missing.join(" and ")}`;
}

export function approveRequirementFailure(hasPermit2Allowance: boolean, hasNativeGasBalance: boolean): string | null {
  return !hasPermit2Allowance && !hasNativeGasBalance ? "buyer wallet needs native Polygon gas to approve Permit2 allowance" : null;
}

export function approveRequirementWarning(hasRequiredBalance: boolean, hasPermit2Allowance: boolean): string | null {
  return !hasRequiredBalance && !hasPermit2Allowance ? "Permit2 approve does not add JPYC balance" : null;
}

export function shouldSendPermit2Approve(hasPermit2Allowance: boolean): boolean {
  return !hasPermit2Allowance;
}

export function fundingNextActions(
  buyer: Address,
  hasRequiredBalance: boolean,
  hasPermit2Allowance: boolean,
  hasNativeGasBalance: boolean,
  requiredAmountHuman: string
): readonly string[] {
  return [
    ...(hasRequiredBalance ? [] : [`send at least ${requiredAmountHuman} JPYC on Polygon to ${buyer}`]),
    ...(hasNativeGasBalance ? [] : [`send Polygon native gas to ${buyer}`]),
    ...(hasPermit2Allowance ? [] : ["run JPYC_APPROVE=1 npm run wallet:jpyc after gas is funded"])
  ];
}

export function walletRequirementSummary(balance: bigint, allowance: bigint, nativeBalance: bigint, requiredAmount: bigint): {
  readonly approveFailure: string | null;
  readonly approveWarning: string | null;
  readonly hasPermit2Allowance: boolean;
  readonly hasNativeGasBalance: boolean;
  readonly hasRequiredBalance: boolean;
  readonly requirementFailure: string | null;
} {
  const hasRequiredBalance = hasRequiredAmount(balance, requiredAmount);
  const hasPermit2Allowance = hasRequiredAmount(allowance, requiredAmount);
  const hasNativeGasBalance = nativeBalance > 0n;
  return {
    approveFailure: approveRequirementFailure(hasPermit2Allowance, hasNativeGasBalance),
    approveWarning: approveRequirementWarning(hasRequiredBalance, hasPermit2Allowance),
    hasPermit2Allowance,
    hasNativeGasBalance,
    hasRequiredBalance,
    requirementFailure: walletRequirementFailure(hasRequiredBalance, hasPermit2Allowance)
  };
}

type WalletState = {
  readonly account: ReturnType<typeof privateKeyToAccount>;
  readonly allowance: bigint;
  readonly balance: bigint;
  readonly decimals: number;
  readonly jpyc: Address;
  readonly nativeBalance: bigint;
  readonly publicClient: ReturnType<typeof createPublicClient>;
  readonly requiredAmount: bigint;
  readonly rpcUrl: string;
};

async function loadWalletState(privateKey: Hex): Promise<WalletState> {
  const rpcUrl = requireEnv("POLYGON_RPC_URL");
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
  const allowance = await publicClient.readContract({
    address: jpyc,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [account.address, PERMIT2_ADDRESS]
  });
  const nativeBalance = await publicClient.getBalance({ address: account.address });
  return { account, allowance, balance, decimals, jpyc, nativeBalance, publicClient, requiredAmount, rpcUrl };
}

export async function checkWallet(privateKey: Hex = requirePrivateKey()): Promise<Record<string, unknown>> {
  const { account, allowance, balance, decimals, jpyc, nativeBalance, requiredAmount } = await loadWalletState(privateKey);
  const requirement = walletRequirementSummary(balance, allowance, nativeBalance, requiredAmount);
  const requiredAmountHuman = formatUnits(requiredAmount, JPYC_DECIMALS);
  const failure = requirement.requirementFailure
    ? [
        requirement.requirementFailure,
        ...(requirement.approveFailure ? [requirement.approveFailure] : []),
        `nextActions: ${fundingNextActions(account.address, requirement.hasRequiredBalance, requirement.hasPermit2Allowance, requirement.hasNativeGasBalance, requiredAmountHuman).join("; ")}`
      ].join("; ")
    : null;
  if (failure) {
    throw new Error(failure);
  }
  return {
    address: account.address,
    allowance: allowance.toString(),
    allowanceHuman: formatUnits(allowance, JPYC_DECIMALS),
    balance: balance.toString(),
    balanceHuman: formatUnits(balance, JPYC_DECIMALS),
    decimals,
    jpyc,
    nativeBalance: nativeBalance.toString(),
    nativeBalanceHuman: formatEther(nativeBalance),
    permit2: PERMIT2_ADDRESS,
    requiredAmount: requiredAmount.toString(),
    requiredAmountHuman
  };
}

async function main(): Promise<void> {
  const { account, allowance, balance, decimals, jpyc, nativeBalance, publicClient, requiredAmount, rpcUrl } = await loadWalletState(requirePrivateKey());
  const approveTx = createPermit2ApprovalTx(jpyc);
  const requirement = walletRequirementSummary(balance, allowance, nativeBalance, requiredAmount);
  const requiredAmountHuman = formatUnits(requiredAmount, JPYC_DECIMALS);
  const result = {
    buyer: account.address,
    jpyc,
    decimals,
    permit2: PERMIT2_ADDRESS,
    requiredAmount: requiredAmount.toString(),
    requiredAmountHuman,
    balance: balance.toString(),
    balanceHuman: formatUnits(balance, JPYC_DECIMALS),
    allowance: allowance.toString(),
    allowanceHuman: formatUnits(allowance, JPYC_DECIMALS),
    nativeBalance: nativeBalance.toString(),
    nativeBalanceHuman: formatEther(nativeBalance),
    hasRequiredBalance: requirement.hasRequiredBalance,
    hasPermit2Allowance: requirement.hasPermit2Allowance,
    requirementFailure: requirement.requirementFailure,
    hasNativeGasBalance: requirement.hasNativeGasBalance,
    approveFailure: requirement.approveFailure,
    approveWarning: requirement.approveWarning,
    nextActions: fundingNextActions(account.address, requirement.hasRequiredBalance, requirement.hasPermit2Allowance, requirement.hasNativeGasBalance, requiredAmountHuman),
    approveTx
  };

  if (readEnv("JPYC_APPROVE") !== "1") {
    console.log(JSON.stringify(result, null, 2));
    if (result.requirementFailure) {
      process.exitCode = 1;
    }
    return;
  }

  if (!shouldSendPermit2Approve(result.hasPermit2Allowance)) {
    console.log(JSON.stringify({ ...result, approveSkipped: true }, null, 2));
    if (result.requirementFailure) { process.exitCode = 1; }
    return;
  }

  if (nativeBalance === 0n) {
    throw new Error("buyer wallet needs native Polygon gas to send JPYC approve");
  }

  const walletClient = createWalletClient({
    account,
    chain: polygon,
    transport: http(rpcUrl)
  });
  const hash = await walletClient.writeContract({
    address: jpyc,
    abi: parseAbi(["function approve(address spender, uint256 amount) returns (bool)"]),
    functionName: "approve",
    args: [PERMIT2_ADDRESS, maxUint256]
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const postApproveAllowance = await publicClient.readContract({
    address: jpyc,
    abi: ERC20_ABI,
    functionName: "allowance",
    args: [account.address, PERMIT2_ADDRESS]
  });
  const hasPostApprovePermit2Allowance = hasRequiredAmount(postApproveAllowance, requiredAmount);

  console.log(
    JSON.stringify(
      {
        ...result,
        approveHash: hash,
        approveStatus: receipt.status,
        postApproveAllowance: postApproveAllowance.toString(),
        postApproveAllowanceHuman: formatUnits(postApproveAllowance, JPYC_DECIMALS),
        hasPostApprovePermit2Allowance
      },
      null,
      2
    )
  );

  if (receipt.status !== "success" || !hasPostApprovePermit2Allowance) {
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
