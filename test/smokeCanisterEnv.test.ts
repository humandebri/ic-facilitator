// test/smokeCanisterEnv.test.ts: canister env name smoke が secret 値なしで不足名を検出することを確認する。
import { describe, expect, it } from "vitest";

import { checkCanisterEnvNames, parseEnvNames } from "../scripts/smoke_canister_env";

function envName(parts: readonly string[]): string {
  return parts.join("_");
}

const facilitatorKeyEnv = envName(["FACILITATOR", "EVM", "PRIVATE", "KEY"]);

const envNamesOutput = `(
  vec { "${facilitatorKeyEnv}"; "FACILITATOR_MAX_GAS"; "FACILITATOR_MAX_SETTLEMENT_FEE_WEI"; "JPYC_EIP712_VERSION"; "POLYGON_RPC_SERVICES"; "SELLER_CREDIT_PAY_TO"; "SELLER_CREDIT_TOPUP_AMOUNT"; "SELLER_SETTLEMENT_FEE_AMOUNT"; "SETTLE_CONFIRMATION_TIMEOUT_SECONDS"; "SETTLEMENT_CACHE_TTL_SECONDS";},
)`;

describe("canister env smoke", () => {
  it("parses env_names output", () => {
    expect(parseEnvNames(envNamesOutput)).toContain(facilitatorKeyEnv);
  });

  it("accepts the required JPYC x402 env name set", () => {
    expect(checkCanisterEnvNames(envNamesOutput)).toMatchObject({
      canister: "edge",
      environment: "local",
      names: expect.arrayContaining([facilitatorKeyEnv, "JPYC_EIP712_VERSION", "POLYGON_RPC_SERVICES"])
    });
  });

  it("rejects missing required env names", () => {
    expect(() => checkCanisterEnvNames(`(vec { "${facilitatorKeyEnv}"; })`)).toThrow(
      "missing canister env names"
    );
  });
});
