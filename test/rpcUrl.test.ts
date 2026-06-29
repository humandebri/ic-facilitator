// test/rpcUrl.test.ts: Polygon RPC URL validator の共有契約を確認する。
import { describe, expect, it } from "vitest";

import { isPolygonRpcUrl, normalizePolygonRpcUrl } from "../scripts/rpc_url";

describe("Polygon RPC URL validator", () => {
  it("rejects HTTP, userinfo, fragment, whitespace, and invalid URLs", () => {
    for (const value of [
      "http://polygon.example",
      "https://trusted.example@evil.example",
      "https://polygon.example/#x",
      "https://polygon.example/v2/key#x",
      "https://polygon.example/with space",
      "not a url"
    ]) {
      expect(isPolygonRpcUrl(value)).toBe(false);
      expect(() => normalizePolygonRpcUrl(value)).toThrow(
        "POLYGON_RPC_URL must be a HTTPS RPC URL without userinfo or fragment"
      );
    }
  });

  it("accepts HTTPS RPC URLs with optional path and query", () => {
    for (const value of [
      "https://polygon.example",
      "https://polygon.example:443",
      "https://polygon-mainnet.example/v2/api-key",
      "https://polygon-mainnet.example/rpc?apikey=abc"
    ]) {
      expect(isPolygonRpcUrl(value)).toBe(true);
      expect(normalizePolygonRpcUrl(value)).toBe(value);
    }
  });
});
