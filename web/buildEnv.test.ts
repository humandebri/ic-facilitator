import { describe, expect, it } from "vitest";
import { requireFacilitatorUrl } from "./buildEnv";

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
