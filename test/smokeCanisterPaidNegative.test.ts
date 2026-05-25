// test/smokeCanisterPaidNegative.test.ts: 不正 payment-signature で canister が paid body を返さないことを固定する。
import { encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import { describe, expect, it } from "vitest";

import { checkPaidNegativeSmoke } from "../scripts/smoke_canister_paid_negative";

const baseUrl = "https://canister.example.test";
const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: {
    url: `${baseUrl}/jpyc/report`,
    description: "JPYC protected report",
    mimeType: "application/json"
  },
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

describe("paid negative canister smoke", () => {
  it("keeps malformed payments at 402 without settlement response", async () => {
    let calls = 0;
    const fetchFn: typeof fetch = async (_input, init) => {
      calls += 1;
      const headers = new Headers(init?.headers);
      if (calls === 1) {
        expect(headers.has("payment-signature")).toBe(false);
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
        });
      }
      expect(headers.get("payment-signature")).toBe("not-a-valid-x402-payment");
      return new Response(JSON.stringify({ error: "payment_required" }), { status: 402 });
    };

    await expect(checkPaidNegativeSmoke({ X402_BASE_URL: baseUrl }, fetchFn)).resolves.toEqual({
      baseUrl,
      body: { error: "payment_required" },
      fakePaidStatus: 402,
      initialStatus: 402
    });
  });

  it("rejects fake 402 responses that include settlement proof", async () => {
    const fetchFn: typeof fetch = async (_input, init) => {
      const headers = new Headers(init?.headers);
      if (!headers.has("payment-signature")) {
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: { "payment-required": encodePaymentRequiredHeader(paymentRequired) }
        });
      }
      return new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: { "payment-response": "fake" }
      });
    };

    await expect(checkPaidNegativeSmoke({ X402_BASE_URL: baseUrl }, fetchFn)).rejects.toThrow(
      "fake paid request returned payment-response"
    );
  });
});
