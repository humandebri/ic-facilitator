// test/permit2Payload.test.ts: 実決済前の exact Permit2 payload 検証を確認する。
import { describe, expect, it } from "vitest";
import type { PaymentPayload, PaymentRequirements } from "@x402/core/types";
import { x402ExactPermit2ProxyAddress } from "@x402/evm";

import { validateExactPermit2PaymentPayload } from "../scripts/permit2_payload";

const requirement: PaymentRequirements = {
  scheme: "exact",
  network: "eip155:137",
  amount: "1000000000000000000",
  asset: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
  payTo: "0x0000000000000000000000000000000000000402",
  maxTimeoutSeconds: 60,
  extra: {
    assetTransferMethod: "permit2"
  }
};

const expected = {
  amount: requirement.amount,
  asset: requirement.asset,
  buyer: "0xb51aFB2CbA39fB1e3e2B3d1dF337579896FBA993",
  maxTimeoutSeconds: requirement.maxTimeoutSeconds,
  payTo: requirement.payTo,
  resourceUrl: "https://example.test/jpyc/report"
};

function paymentPayload(spender: string): PaymentPayload {
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
      permit2Authorization: {
        from: expected.buyer,
        permitted: {
          token: requirement.asset,
          amount: requirement.amount
        },
        spender,
        nonce: "1",
        deadline: "9999999999",
        witness: {
          to: requirement.payTo,
          validAfter: "0"
        }
      }
    }
  };
}

describe("exact Permit2 payment payload validation", () => {
  it("accepts the expected JPYC exact Permit2 payload", () => {
    expect(() => validateExactPermit2PaymentPayload(paymentPayload(x402ExactPermit2ProxyAddress), expected)).not.toThrow();
  });

  it("rejects unexpected Permit2 spenders before paid retry", () => {
    expect(() =>
      validateExactPermit2PaymentPayload(paymentPayload("0x0000000000000000000000000000000000000001"), expected)
    ).toThrow("unexpected payment payload spender");
  });

  it("rejects unexpected payload resource URLs before paid retry", () => {
    const payload = paymentPayload(x402ExactPermit2ProxyAddress);
    expect(() =>
      validateExactPermit2PaymentPayload(payload, { ...expected, resourceUrl: "https://example.test/other" })
    ).toThrow("unexpected payment payload resource");
  });

  it("rejects unexpected payload x402 versions before paid retry", () => {
    const payload = {
      ...paymentPayload(x402ExactPermit2ProxyAddress),
      x402Version: 1
    };
    expect(() => validateExactPermit2PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload x402 version"
    );
  });

  it("rejects unexpected accepted transfer methods before paid retry", () => {
    const payload = {
      ...paymentPayload(x402ExactPermit2ProxyAddress),
      accepted: {
        ...requirement,
        extra: {
          assetTransferMethod: "eip3009"
        }
      }
    };
    expect(() => validateExactPermit2PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload accepted transfer method"
    );
  });

  it("rejects unexpected accepted timeouts before paid retry", () => {
    const payload = {
      ...paymentPayload(x402ExactPermit2ProxyAddress),
      accepted: {
        ...requirement,
        maxTimeoutSeconds: 3600
      }
    };
    expect(() => validateExactPermit2PaymentPayload(payload, expected)).toThrow(
      "unexpected payment payload accepted timeout"
    );
  });
});
