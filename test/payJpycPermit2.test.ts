// test/payJpycPermit2.test.ts: JPYC exact 支払いで生成される Permit2 payload の重要フィールドを固定する。
import { describe, expect, it } from "vitest";
import {
  decodePaymentSignatureHeader,
  encodePaymentRequiredHeader,
  encodePaymentResponseHeader
} from "@x402/core/http";
import type { PaymentRequired, SettleResponse } from "@x402/core/types";
import { x402ExactPermit2ProxyAddress } from "@x402/evm";
import type { Hex } from "viem";

import { payJpyc } from "../scripts/pay_jpyc";

const buyerPrivateKey: Hex = "0x59c6995e998f97a5a0044966f094538db1f78e001b7e6f2480d4ef9f4a3a9a8e";
const buyerAddress = "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993";
const targetUrl = "https://example.test/jpyc/report";
const jpycAsset = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const sellerAddress = "0x1000000000000000000000000000000000000402";
const atomicAmount = "1000000000000000000";

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
        assetTransferMethod: "permit2"
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

function property(value: unknown, name: string): unknown {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  return Object.getOwnPropertyDescriptor(value, name)?.value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`missing string field: ${label}`);
  }
  return value;
}

function lower(value: unknown, label: string): string {
  return requireString(value, label).toLowerCase();
}

describe("payJpyc Permit2 payload", () => {
  it("pins exact Polygon JPYC Permit2 authorization fields", async () => {
    let paymentSignature = "";
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

      paymentSignature = requireString(new Headers(init?.headers).get("payment-signature"), "payment-signature");
      return new Response(JSON.stringify({
        asset: jpycAsset,
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

    await payJpyc({
      expectedAmount: atomicAmount,
      expectedAsset: jpycAsset,
      expectedPayTo: sellerAddress,
      fetchFn,
      privateKey: buyerPrivateKey,
      targetUrl
    });

    const decoded = decodePaymentSignatureHeader(paymentSignature);
    const permit2Authorization = property(decoded.payload, "permit2Authorization");
    const permitted = property(permit2Authorization, "permitted");
    const witness = property(permit2Authorization, "witness");

    expect(callCount).toBe(2);
    expect(decoded.accepted).toEqual(paymentRequired.accepts[0]);
    expect(lower(property(permit2Authorization, "from"), "from")).toBe(buyerAddress.toLowerCase());
    expect(lower(property(permitted, "token"), "permitted.token")).toBe(jpycAsset.toLowerCase());
    expect(requireString(property(permitted, "amount"), "permitted.amount")).toBe(atomicAmount);
    expect(lower(property(permit2Authorization, "spender"), "spender")).toBe(x402ExactPermit2ProxyAddress.toLowerCase());
    expect(lower(property(witness, "to"), "witness.to")).toBe(sellerAddress.toLowerCase());
    expect(requireString(property(permit2Authorization, "nonce"), "nonce")).toMatch(/^\d+$/);
    expect(requireString(property(permit2Authorization, "deadline"), "deadline")).toMatch(/^\d+$/);
    expect(requireString(property(decoded.payload, "signature"), "signature")).toMatch(/^0x[0-9a-fA-F]+$/);
  });
});
