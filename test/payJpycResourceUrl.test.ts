// test/payJpycResourceUrl.test.ts: local HTTP target で resource URL 未設定の署名を拒否する。
import { describe, expect, it } from "vitest";
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import type { Hex } from "viem";

import { payJpyc } from "../scripts/pay_jpyc";

const privateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
const targetUrl = "http://edge.local.localhost:8000/jpyc/report";
const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: { url: "https://ic-edge.local/jpyc/report", description: "JPYC protected report", mimeType: "application/json" },
  accepts: [{
    scheme: "exact",
    network: "eip155:137",
    amount: "1000000000000000000",
    asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
    payTo: "0x1000000000000000000000000000000000000402",
    maxTimeoutSeconds: 60,
    extra: { assetTransferMethod: "permit2" }
  }]
};

describe("payJpyc resource URL guard", () => {
  function fetchPaymentRequired(): typeof fetch {
    let calls = 0;
    return async () => {
      calls += 1;
      return new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
      });
    };
  }

  it("requires explicit resource URL for HTTP targets before signing", async () => {
    const fetchFn = fetchPaymentRequired();
    await expect(payJpyc({
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn,
      privateKey,
      targetUrl
    })).rejects.toThrow("missing required env: X402_RESOURCE_URL");
  });

  it("rejects non-HTTPS expected resource URLs before signing", async () => {
    await expect(payJpyc({
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      expectedResourceUrl: "http://edge.local.localhost:8000/jpyc/report",
      fetchFn: fetchPaymentRequired(),
      privateKey,
      targetUrl
    })).rejects.toThrow("X402_RESOURCE_URL must be an https URL");
  });
});
