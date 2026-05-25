// test/evmWallet.test.ts: 実決済 smoke 用 wallet 生成 helper を検証する。
import { describe, expect, it } from "vitest";
import type { Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { createBuyerWalletForSeller, createWalletPair, normalizeSellerAddress, shellExportText, shouldRequireSellerForEnv, walletFromPrivateKey } from "../scripts/evm_wallet";

const sellerKey: Hex = `0x${"1".repeat(64)}`;
const buyerKey: Hex = `0x${"2".repeat(64)}`;
const seller = "0x1000000000000000000000000000000000000402";
const sampleSeller = "0x0000000000000000000000000000000000000402";

describe("evm wallet helper", () => {
  it("derives an address from a private key", () => {
    const wallet = walletFromPrivateKey("buyer", buyerKey);

    expect(wallet.address).toBe(privateKeyToAccount(buyerKey).address);
    expect(wallet.privateKey).toBe(buyerKey);
    expect(wallet.role).toBe("buyer");
  });

  it("creates seller and buyer shell exports", () => {
    const keys = [sellerKey, buyerKey];
    let index = 0;
    const pair = createWalletPair(() => {
      const key = keys[index];
      if (!key) { throw new Error("missing test key"); }
      index += 1;
      return key;
    });

    expect(pair.seller.address).toBe(privateKeyToAccount(sellerKey).address);
    expect(pair.buyer.address).toBe(privateKeyToAccount(buyerKey).address);
    expect(pair.shellExports).toEqual([
      `export SELLER_EVM_ADDRESS=${pair.seller.address}`,
      `export BUYER_EVM_ADDRESS=${pair.buyer.address}`,
      `export BUYER_EVM_PRIVATE_KEY=${pair.buyer.privateKey}`
    ]);
  });

  it("creates a buyer wallet for an existing seller address", () => {
    const pair = createBuyerWalletForSeller(seller, () => buyerKey);

    expect(pair.seller).toEqual({ address: seller, role: "seller" });
    expect(pair.buyer.address).toBe(privateKeyToAccount(buyerKey).address);
    expect(pair.shellExports).toEqual([
      `export SELLER_EVM_ADDRESS=${seller}`,
      `export BUYER_EVM_ADDRESS=${pair.buyer.address}`,
      `export BUYER_EVM_PRIVATE_KEY=${buyerKey}`
    ]);
  });

  it("rejects invalid seller addresses", () => {
    expect(() => normalizeSellerAddress("0x0")).toThrow("seller address must be a non-zero");
    expect(() => normalizeSellerAddress(sampleSeller)).toThrow("seller address must not be the sample address");
  });

  it("prints shell exports without JSON wrapper", () => {
    const pair = createBuyerWalletForSeller(seller, () => buyerKey);

    expect(shellExportText(pair)).toBe(`export SELLER_EVM_ADDRESS=${seller}\nexport BUYER_EVM_ADDRESS=${pair.buyer.address}\nexport BUYER_EVM_PRIVATE_KEY=${buyerKey}\n`);
  });

  it("requires an existing seller for env-only output", () => {
    expect(shouldRequireSellerForEnv(["--env"])).toBe(true);
    expect(shouldRequireSellerForEnv(["--env", "--seller", seller])).toBe(false);
  });
});
