// test/payJpycSettlement.test.ts: paid response の settlement 証跡を必須検証する。
import { describe, expect, it } from "vitest";
import { encodePaymentRequiredHeader, encodePaymentResponseHeader } from "@x402/core/http";
import type { PaymentRequired, SettleResponse } from "@x402/core/types";
import type { Hex } from "viem";

import { payJpyc } from "../scripts/pay_jpyc";

const privateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
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
    payTo: "0x1000000000000000000000000000000000000402",
    maxTimeoutSeconds: 60,
    extra: { assetTransferMethod: "permit2" }
  }]
};

function fetchWithSettlement(settlement: SettleResponse | null): typeof fetch {
  let callCount = 0;
  return async () => {
    callCount += 1;
    if (callCount === 1) {
      return new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
      });
    }
    return new Response(JSON.stringify({
      asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      network: "eip155:137",
      report: "paid JPYC access granted"
    }), {
      status: 200,
      headers: settlement ? { "payment-response": encodePaymentResponseHeader(settlement) } : {}
    });
  };
}

describe("payJpyc settlement validation", () => {
  it("rejects missing settlement responses", async () => {
    await expect(payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn: fetchWithSettlement(null),
      privateKey,
      targetUrl
    })).rejects.toThrow("payment did not settle successfully");
  });

  it("rejects settlements from unexpected payers", async () => {
    await expect(payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn: fetchWithSettlement({
        success: true,
        transaction: "0x0000000000000000000000000000000000000000000000000000000000000402",
        network: "eip155:137",
        payer: "0x0000000000000000000000000000000000000001"
      }),
      privateKey,
      targetUrl
    })).rejects.toThrow("unexpected settlement payer");
  });

  it("rejects settlements with unexpected amounts", async () => {
    await expect(payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn: fetchWithSettlement({
        success: true,
        transaction: "0x0000000000000000000000000000000000000000000000000000000000000402",
        network: "eip155:137",
        payer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
        amount: "1"
      }),
      privateKey,
      targetUrl
    })).rejects.toThrow("unexpected settlement amount");
  });

  it("rejects successful settlements that still carry error fields", async () => {
    await expect(payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn: fetchWithSettlement({
        success: true,
        transaction: "0x0000000000000000000000000000000000000000000000000000000000000402",
        network: "eip155:137",
        payer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
        errorReason: "conflicting_error"
      }),
      privateKey,
      targetUrl
    })).rejects.toThrow("successful settlement must not include error fields");
  });
});
