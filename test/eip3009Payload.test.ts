// test/eip3009Payload.test.ts: 実決済前の exact EIP-3009 payload 検証を確認する。
import { describe, expect, it } from "vitest";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";

import { validateExactEip3009PaymentPayload } from "../scripts/eip3009_payload";

const requirement: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:137",
  amount: "1000000000000000000",
  asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
  payTo: "0x0000000000000000000000000000000000000402",
  maxTimeoutSeconds: 60,
  extra: {
    assetTransferMethod: "eip3009",
    name: "JPY Coin",
    version: "1"
  }
};

const expected = {
  amount: requirement.amount,
  asset: requirement.asset,
  buyer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
  eip712Version: "1",
  maxTimeoutSeconds: requirement.maxTimeoutSeconds,
  payTo: requirement.payTo,
  resourceUrl: "https://example.test/jpyc/report"
};

function paymentPayload(nonce: string): PaymentPayload {
  return {
    x402Version: 2,
    accepted: requirement,
    resource: {
      url: expected.resourceUrl,
      description: "JPYC protected report",
      mimeType: "application/json"
    },
    payload: {
      signature: "0x01",
      authorization: {
        from: expected.buyer,
        to: requirement.payTo,
        value: requirement.amount,
        validAfter: "0",
        validBefore: "9999999999",
        nonce
      }
    }
  };
}

describe("exact EIP-3009 payment payload validation", () => {
  it("accepts the expected JPYC exact EIP-3009 payload", () => {
    expect(() => validateExactEip3009PaymentPayload(paymentPayload(`0x${"11".repeat(32)}`), expected)).not.toThrow();
  });

  it("rejects unexpected EIP-3009 nonces before paid retry", () => {
    expect(() =>
      validateExactEip3009PaymentPayload(paymentPayload("0x01"), expected)
    ).toThrow("invalid payment payload bytes32");
  });

  it("rejects unexpected payload resource URLs before paid retry", () => {
    const payload = paymentPayload(`0x${"11".repeat(32)}`);
    expect(() =>
      validateExactEip3009PaymentPayload(payload, { ...expected, resourceUrl: "https://example.test/other" })
    ).toThrow("unexpected payment payload resource");
  });

  it("rejects unexpected payload x402 versions before paid retry", () => {
    const payload = {
      ...paymentPayload(`0x${"11".repeat(32)}`),
      x402Version: 1
    };
    expect(() => validateExactEip3009PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload x402 version"
    );
  });

  it("rejects unexpected accepted transfer methods before paid retry", () => {
    const payload = {
      ...paymentPayload(`0x${"11".repeat(32)}`),
      accepted: {
        ...requirement,
        extra: {
          assetTransferMethod: "permit2",
          name: "JPY Coin",
          version: "1"
        }
      }
    };
    expect(() => validateExactEip3009PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload accepted transfer method"
    );
  });

  it("rejects Permit2 payloads before paid retry", () => {
    const payload = {
      ...paymentPayload(`0x${"11".repeat(32)}`),
      payload: {
        signature: "0x01",
        permit2Authorization: {}
      }
    };
    expect(() => validateExactEip3009PaymentPayload(payload, expected)).toThrow(
      "unexpected Permit2 payment payload"
    );
  });

  it("rejects unexpected accepted EIP-712 domains before paid retry", () => {
    const payload = {
      ...paymentPayload(`0x${"11".repeat(32)}`),
      accepted: {
        ...requirement,
        extra: {
          assetTransferMethod: "eip3009",
          name: "JPY Coin",
          version: "2"
        }
      }
    };
    expect(() => validateExactEip3009PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload EIP-712 domain"
    );
  });
});
