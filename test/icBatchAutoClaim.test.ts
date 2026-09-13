import { describe, it, expect, vi } from "vitest";
import { IcBatchAutoClaim, type IcBatchAutoClaimClient } from "../src/icBatchAutoClaim";

function client(): IcBatchAutoClaimClient {
  return {
    batch_auto_claim_set_enabled: vi.fn(async () => ({ Ok: null })),
    batch_auto_claim_request: vi.fn(async () => ({ Ok: null })),
    batch_auto_claim_status: vi.fn(async () => ({ Ok: [] as [] }))
  };
}

describe("IcBatchAutoClaim", () => {
  it("normalizes identifiers and exposes absent status", async () => {
    const actor = client();
    const api = new IcBatchAutoClaim(actor);
    await api.setEnabled(`0x${"AB".repeat(20)}`, true);
    expect(actor.batch_auto_claim_set_enabled).toHaveBeenCalledWith(`0x${"ab".repeat(20)}`, true);
    expect(await api.status(`0x${"ab".repeat(32)}`)).toBeUndefined();
  });
  it("propagates drain and authorization failures", async () => {
    const actor = client();
    actor.batch_auto_claim_request = vi.fn(async () => ({ Err: "caller is not authorized for receiver" }));
    await expect(new IcBatchAutoClaim(actor).requestClaim(`0x${"ab".repeat(32)}`)).rejects.toThrow("not authorized");
  });
  it("rejects malformed identifiers before calling the actor", async () => {
    const actor = client();
    await expect(new IcBatchAutoClaim(actor).requestClaim("0x12")).rejects.toThrow("32-byte");
    expect(actor.batch_auto_claim_request).not.toHaveBeenCalled();
  });
});
