// test/payJpyc.test.ts: buyer payment client が 402 取得、署名、paid retry、settlement 解釈まで行うことを確認する。
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader
} from "@x402/core/http";
import type { PaymentRequired, SettleResponse } from "@x402/core/types";
import type { Hex } from "viem";

import { hasExpectedPaidJpycReportBody, hasPaidJpycReportBody, payJpyc } from "../scripts/pay_jpyc";

const buyerPrivateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
const targetUrl = "https://example.test/jpyc/report";
const sellerAddress = "0x1000000000000000000000000000000000000402";
const buyerAddress = "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993";
const atomicAmount = "1000000000000000000";
const jpycAsset = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const sellerAuthorization = {
  version: 1,
  scheme: "eip191",
  seller: sellerAddress,
  payer: buyerAddress,
  amount: atomicAmount,
  asset: jpycAsset,
  network: "eip155:137",
  resource: targetUrl,
  validAfter: "0",
  validBefore: "9999999999",
  authorizationNonce: `0x${"22".repeat(32)}`,
  expiresAt: "9999999999",
  signature: `0x${"11".repeat(65)}`
};
const paymentRequired: PaymentRequired = {
  x402Version: 2,
  error: "Payment required",
  resource: {
    url: targetUrl,
    description: "JPYC protected report",
    mimeType: "application/json"
  },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:137",
      amount: atomicAmount,
      asset: jpycAsset,
      payTo: sellerAddress,
      maxTimeoutSeconds: 60,
      extra: {
        assetTransferMethod: "eip3009",
        name: "JPY Coin",
        version: "1",
        sellerAuthorization
      }
    }
  ]
};
const settlement: SettleResponse = {
  success: true,
  transaction: "0x0000000000000000000000000000000000000000000000000000000000000402",
  network: "eip155:137",
  payer: buyerAddress
};

describe("payJpyc", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("recognizes the paid JPYC report body", () => {
    const body = {
      asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      network: "eip155:137",
      report: "paid JPYC access granted"
    };
    expect(hasPaidJpycReportBody(body)).toBe(true);
    expect(hasExpectedPaidJpycReportBody({ ...body, asset: "0x0000000000000000000000000000000000000001" }, body.asset)).toBe(false);
    expect(hasPaidJpycReportBody({ ...body, report: "other" })).toBe(false);
  });

  it("creates a payment signature and reads settlement response", async () => {
    let callCount = 0;
    const fetchFn: typeof fetch = async (input, init) => {
      callCount += 1;
      expect(String(input)).toBe(targetUrl);

      if (callCount === 1) {
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "payment-required": encodePaymentRequiredHeader(paymentRequired)
          }
        });
      }

      const headers = new Headers(init?.headers);
      const paymentSignature = headers.get("payment-signature");
      expect(paymentSignature).toBeTruthy();
      if (!paymentSignature) {
        throw new Error("missing payment-signature");
      }

      const payload = decodePaymentSignatureHeader(paymentSignature);
      expect(payload.accepted).toEqual(paymentRequired.accepts[0]);
      expect(payload.accepted.extra?.sellerAuthorization).toEqual(sellerAuthorization);
      expect(payload.payload).toHaveProperty("authorization");
      expect(payload.payload).not.toHaveProperty("permit2Authorization");

      return new Response(JSON.stringify({
        asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        network: "eip155:137",
        report: "paid JPYC access granted"
      }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "payment-response": encodePaymentResponseHeader(settlement)
        }
      });
    };

    const result = await payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedEip712Version: "1",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn,
      privateKey: buyerPrivateKey,
      targetUrl
    });

    expect(callCount).toBe(2);
    expect(result).toEqual({
      buyer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
      targetUrl,
      unpaidStatus: 402,
      paidStatus: 200,
      body: {
        asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        network: "eip155:137",
        report: "paid JPYC access granted"
      },
      settlement,
      settlementTxExport: `export SETTLEMENT_TX=${settlement.transaction}`,
      verifyCommand: `SETTLEMENT_TX=${settlement.transaction} npm run verify:jpyc`
    });
  });

  it("can retry a paid request with the same payment signature", async () => {
    let callCount = 0;
    let firstPaymentSignature = "";
    const retrySettlement: SettleResponse = {
      ...settlement,
      amount: "1000000000000000000",
      transaction: "0x0000000000000000000000000000000000000000000000000000000000000500"
    };
    const fetchFn: typeof fetch = async (input, init) => {
      callCount += 1;
      expect(String(input)).toBe(targetUrl);

      if (callCount === 1) {
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "payment-required": encodePaymentRequiredHeader(paymentRequired)
          }
        });
      }

      const paymentSignature = new Headers(init?.headers).get("payment-signature");
      expect(paymentSignature).toBeTruthy();
      if (!paymentSignature) {
        throw new Error("missing payment-signature");
      }
      if (callCount === 2) {
        firstPaymentSignature = paymentSignature;
      } else {
        expect(paymentSignature).toBe(firstPaymentSignature);
      }

      return new Response(JSON.stringify({
        asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        network: "eip155:137",
        report: "paid JPYC access granted"
      }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "payment-response": encodePaymentResponseHeader(callCount === 2 ? settlement : retrySettlement)
        }
      });
    };

    const result = await payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedEip712Version: "1",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn,
      privateKey: buyerPrivateKey,
      targetUrl,
      withPaidRetry: true
    });

    expect(callCount).toBe(3);
    expect(result.paidStatus).toBe(200);
    expect(result.paidRetryStatus).toBe(200);
    expect(result.retrySettlement).toEqual(retrySettlement);
  });

  it("can enable paid retry from the environment", async () => {
    vi.stubEnv("X402_PAID_RETRY", "1");
    let callCount = 0;
    const fetchFn: typeof fetch = async () => {
      callCount += 1;
      if (callCount === 1) {
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "payment-required": encodePaymentRequiredHeader(paymentRequired)
          }
        });
      }
      return new Response(JSON.stringify({
        asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        network: "eip155:137",
        report: "paid JPYC access granted"
      }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "payment-response": encodePaymentResponseHeader(settlement)
        }
      });
    };

    const result = await payJpyc({
      expectedAmount: "1000000000000000000",
      expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
      expectedEip712Version: "1",
      expectedPayTo: "0x1000000000000000000000000000000000000402",
      fetchFn,
      privateKey: buyerPrivateKey,
      targetUrl
    });

    expect(callCount).toBe(3);
    expect(result.paidRetryStatus).toBe(200);
  });

  it("rejects unexpected payment requirements before signing", async () => {
    let callCount = 0;
    const baseRequirement = paymentRequired.accepts[0];
    if (!baseRequirement) {
      throw new Error("missing base payment requirement");
    }
    const badPaymentRequired: PaymentRequired = {
      ...paymentRequired,
      accepts: [
        {
          ...baseRequirement,
          asset: "0x0000000000000000000000000000000000000001"
        }
      ]
    };
    const fetchFn: typeof fetch = async () => {
      callCount += 1;
      return new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": encodePaymentRequiredHeader(badPaymentRequired)
        }
      });
    };

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        expectedEip712Version: "1",
        expectedPayTo: "0x1000000000000000000000000000000000000402",
        fetchFn,
        privateKey: buyerPrivateKey,
        targetUrl
      })
    ).rejects.toThrow("unexpected payment asset");
    expect(callCount).toBe(1);
  });

  it("rejects unexpected resource URLs before signing", async () => {
    vi.stubEnv("SELLER_EVM_ADDRESS", "0x1000000000000000000000000000000000000402");
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": encodePaymentRequiredHeader({
            ...paymentRequired,
            resource: {
              ...paymentRequired.resource,
              url: "https://example.test/other"
            }
          })
        }
      });

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        expectedEip712Version: "1",
        expectedMaxTimeoutSeconds: 60,
        expectedPayTo: "0x1000000000000000000000000000000000000402",
        fetchFn,
        privateKey: buyerPrivateKey,
        targetUrl
      })
    ).rejects.toThrow("unexpected payment resource");
  });

  it("rejects unexpected timeouts before signing", async () => {
    vi.stubEnv("SELLER_EVM_ADDRESS", "0x1000000000000000000000000000000000000402");
    const baseRequirement = paymentRequired.accepts[0];
    if (!baseRequirement) {
      throw new Error("missing base payment requirement");
    }
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": encodePaymentRequiredHeader({
            ...paymentRequired,
            accepts: [{ ...baseRequirement, maxTimeoutSeconds: 3600 }]
          })
        }
      });

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        expectedEip712Version: "1",
        expectedMaxTimeoutSeconds: 60,
        expectedPayTo: "0x1000000000000000000000000000000000000402",
        fetchFn,
        privateKey: buyerPrivateKey,
        targetUrl
      })
    ).rejects.toThrow("unexpected payment timeout");
  });

  it("rejects missing EIP-3009 transfer methods before signing", async () => {
    vi.stubEnv("SELLER_EVM_ADDRESS", "0x1000000000000000000000000000000000000402");
    const baseRequirement = paymentRequired.accepts[0];
    if (!baseRequirement) {
      throw new Error("missing base payment requirement");
    }
    const fetchFn: typeof fetch = async () =>
      new Response(JSON.stringify({ error: "payment_required" }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": encodePaymentRequiredHeader({
            ...paymentRequired,
            accepts: [{ ...baseRequirement, extra: {} }]
          })
        }
      });

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        expectedEip712Version: "1",
        expectedMaxTimeoutSeconds: 60,
        expectedPayTo: "0x1000000000000000000000000000000000000402",
        fetchFn,
        privateKey: buyerPrivateKey,
        targetUrl
      })
    ).rejects.toThrow("unexpected payment transfer method");
  });

  it("rejects paid responses with unexpected bodies", async () => {
    let callCount = 0;
    const fetchFn: typeof fetch = async () => {
      callCount += 1;
      if (callCount === 1) {
        return new Response(JSON.stringify({ error: "payment_required" }), {
          status: 402,
          headers: {
            "content-type": "application/json",
            "payment-required": encodePaymentRequiredHeader(paymentRequired)
          }
        });
      }
      return new Response(JSON.stringify({ report: "other" }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "payment-response": encodePaymentResponseHeader(settlement)
        }
      });
    };

    await expect(
      payJpyc({
        expectedAmount: "1000000000000000000",
        expectedAsset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
        expectedEip712Version: "1",
        expectedPayTo: "0x1000000000000000000000000000000000000402",
        fetchFn,
        privateKey: buyerPrivateKey,
        targetUrl
      })
    ).rejects.toThrow("unexpected paid response body");
  });

});
