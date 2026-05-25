// test/payJpycSampleSeller.test.ts: buyer script が sample seller への署名を拒否することを確認する。
import { afterEach, describe, expect, it, vi } from "vitest";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import type { Hex } from "viem";

import { payJpyc } from "../scripts/pay_jpyc";

const privateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
const sampleSeller = "0x0000000000000000000000000000000000000402";
const targetUrl = "https://example.test/jpyc/report";
const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: { url: targetUrl, description: "JPYC protected report", mimeType: "application/json" },
  accepts: [{
    scheme: "exact",
    network: "eip155:137",
    amount: "1000000000000000000",
    asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
    payTo: sampleSeller,
    maxTimeoutSeconds: 60,
    extra: { assetTransferMethod: "permit2" }
  }]
};

function sampleSellerFetch(calls: { value: number }): typeof fetch {
  return async () => {
    calls.value += 1;
    return new Response(JSON.stringify({ error: "payment_required" }), {
      status: 402,
      headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
    });
  };
}

describe("payJpyc sample seller guard", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("rejects sample seller env before signing", async () => {
    vi.stubEnv("SELLER_EVM_ADDRESS", sampleSeller);
    const calls = { value: 0 };

    await expect(payJpyc({ fetchFn: sampleSellerFetch(calls), privateKey, targetUrl })).rejects.toThrow(
      "SELLER_EVM_ADDRESS must be a real seller address"
    );
    expect(calls.value).toBe(1);
  });

  it("rejects sample seller options before signing", async () => {
    const calls = { value: 0 };

    await expect(payJpyc({
      expectedPayTo: sampleSeller,
      fetchFn: sampleSellerFetch(calls),
      privateKey,
      targetUrl
    })).rejects.toThrow("SELLER_EVM_ADDRESS must be a real seller address");
    expect(calls.value).toBe(1);
  });
});
