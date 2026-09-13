import { describe, expect, it } from "vitest";

import {
  creditPaymentOutcome,
} from "../web/src/credit_payment";

describe("Credit payment state", () => {
  it("keeps a 202 payment pending with the same authorization retry path", () => {
    expect(creditPaymentOutcome(202, { settlement: { transaction: "0xabc" } })).toEqual({
      kind: "pending",
      transaction: "0xabc",
    });
  });

  it("uses the paid response creditAtoms as the terminal balance", () => {
    expect(creditPaymentOutcome(200, { creditAtoms: "123" })).toEqual({
      kind: "success",
      creditAtoms: "123",
    });
  });

  it("rejects non-success terminal responses", () => {
    expect(() => creditPaymentOutcome(502, { message: "upstream failed" }))
      .toThrow("upstream failed");
  });
});
