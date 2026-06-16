// test/payJpycReceiver.test.ts: buyer payment client が送金先未確認の署名を拒否する。
import { afterEach, describe, expect, it, vi } from "vitest";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import type { Hex } from "viem";

import { payJpyc } from "../scripts/pay_jpyc";

const privateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
const targetUrl = "https://example.test/jpyc/report";

const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: { url: targetUrl, description: "JPYC protected report", mimeType: "application/json" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:137",
      amount: "1000000000000000000",
      asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      payTo: "0x0000000000000000000000000000000000000402",
      maxTimeoutSeconds: 60,
      extra: { assetTransferMethod: "eip3009", name: "JPY Coin", version: "1" }
    }
  ]
};

describe("payJpyc receiver verification", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("requires expected receiver before signing", async () => {
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": encodePaymentRequiredHeader(paymentRequired)
        }
      });

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        fetchFn,
        privateKey,
        targetUrl
      })
    ).rejects.toThrow("missing required env: SELLER_EVM_ADDRESS");
  });
});
