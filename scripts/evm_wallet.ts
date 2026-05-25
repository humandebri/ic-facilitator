// scripts/evm_wallet.ts: JPYC 実決済 smoke 用の seller / buyer EVM wallet を生成する。
import { pathToFileURL } from "node:url";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

export type RoleWallet = {
  readonly address: Hex;
  readonly privateKey: Hex;
  readonly role: "buyer" | "seller";
};

export type WalletPair = {
  readonly buyer: RoleWallet;
  readonly shellExports: readonly string[];
  readonly seller: RoleWallet;
};

export type BuyerWalletForSeller = {
  readonly buyer: RoleWallet;
  readonly seller: {
    readonly address: Hex;
    readonly role: "seller";
  };
  readonly shellExports: readonly string[];
};

const SAMPLE_SELLER_ADDRESS = "0x0000000000000000000000000000000000000402";

function isPrivateKey(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isEvmAddress(value: string): value is Hex {
  return /^0x[0-9a-fA-F]{40}$/.test(value);
}

export function normalizeSellerAddress(value: string): Hex {
  if (!isEvmAddress(value) || /^0x0{40}$/i.test(value)) {
    throw new Error("seller address must be a non-zero 0x-prefixed 20-byte EVM address");
  }
  if (value.toLowerCase() === SAMPLE_SELLER_ADDRESS.toLowerCase()) {
    throw new Error("seller address must not be the sample address");
  }
  return value;
}

export function walletFromPrivateKey(role: RoleWallet["role"], privateKey: Hex): RoleWallet {
  if (!isPrivateKey(privateKey)) {
    throw new Error("private key must be a 32-byte 0x-prefixed hex string");
  }
  return {
    address: privateKeyToAccount(privateKey).address,
    privateKey,
    role
  };
}

export function createWalletPair(generate: () => Hex = generatePrivateKey): WalletPair {
  const seller = walletFromPrivateKey("seller", generate());
  const buyer = walletFromPrivateKey("buyer", generate());
  if (seller.address.toLowerCase() === buyer.address.toLowerCase()) {
    throw new Error("generated seller and buyer addresses must differ");
  }
  return {
    buyer,
    seller,
    shellExports: [
      `export SELLER_EVM_ADDRESS=${seller.address}`,
      `export BUYER_EVM_ADDRESS=${buyer.address}`,
      `export BUYER_EVM_PRIVATE_KEY=${buyer.privateKey}`
    ]
  };
}

export function createBuyerWalletForSeller(
  sellerAddress: string,
  generate: () => Hex = generatePrivateKey
): BuyerWalletForSeller {
  const seller: BuyerWalletForSeller["seller"] = {
    address: normalizeSellerAddress(sellerAddress),
    role: "seller"
  };
  const buyer = walletFromPrivateKey("buyer", generate());
  if (seller.address.toLowerCase() === buyer.address.toLowerCase()) {
    throw new Error("seller and buyer addresses must differ");
  }
  return {
    buyer,
    seller,
    shellExports: [
      `export SELLER_EVM_ADDRESS=${seller.address}`,
      `export BUYER_EVM_ADDRESS=${buyer.address}`,
      `export BUYER_EVM_PRIVATE_KEY=${buyer.privateKey}`
    ]
  };
}

function sellerArg(args: readonly string[]): string | undefined {
  const inline = args.find((arg) => arg.startsWith("--seller="));
  if (inline) {
    return inline.slice("--seller=".length);
  }
  const index = args.findIndex((arg) => arg === "--seller");
  return index >= 0 ? args[index + 1] : undefined;
}

function outputEnv(args: readonly string[]): boolean {
  return args.includes("--env");
}

export function shellExportText(pair: Pick<WalletPair, "shellExports">): string {
  return `${pair.shellExports.join("\n")}\n`;
}

export function shouldRequireSellerForEnv(args: readonly string[]): boolean {
  return outputEnv(args) && !sellerArg(args);
}

function main(): void {
  const args = process.argv.slice(2);
  if (shouldRequireSellerForEnv(args)) {
    throw new Error("wallet:env requires --seller; use wallet:new to create and inspect a seller key");
  }
  const seller = sellerArg(args);
  const pair = seller ? createBuyerWalletForSeller(seller) : createWalletPair();
  if (outputEnv(args)) {
    process.stdout.write(shellExportText(pair));
  } else {
    console.log(JSON.stringify(pair, null, 2));
  }
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  try {
    main();
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  }
}
