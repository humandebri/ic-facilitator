import { describe, expect, it } from "vitest";
import { requireEvmAddress, requireFacilitatorUrl } from "./buildEnv";

describe("requireFacilitatorUrl", () => {
  it("accepts the non-routable CI preview URL", () => {
    expect(requireFacilitatorUrl("https://preview.invalid")).toBe("https://preview.invalid");
  });

  it.each([
    [undefined, "is required"],
    ["http://preview.invalid", "must be an HTTPS URL"],
    ["https://user:secret@preview.invalid", "must be an HTTPS URL"],
  ])("rejects unsafe build URL %s", (value, message) => {
    expect(() => requireFacilitatorUrl(value)).toThrow(message);
  });
});

describe("requireEvmAddress", () => {
  it("accepts a non-zero EVM address", () => {
    expect(requireEvmAddress("VITE_TOKEN_ADDRESS", "0x1000000000000000000000000000000000000001"))
      .toBe("0x1000000000000000000000000000000000000001");
  });

  it.each([
    [undefined, "is required"],
    ["", "is required"],
    ["0x0000000000000000000000000000000000000000", "must be a non-zero EVM address"],
    ["0x1234", "must be a non-zero EVM address"],
  ])("rejects an invalid build address %s", (value, message) => {
    expect(() => requireEvmAddress("VITE_TOKEN_ADDRESS", value)).toThrow(message);
  });
});
