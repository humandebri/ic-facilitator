// test/smokeCanisterEnv.test.ts: canister env name smoke が secret 値なしで不足名を検出することを確認する。
import { describe, expect, it } from "vitest";

import { checkCanisterEnvNames, parseEnvNames } from "../scripts/smoke_canister_env";

const envNamesOutput = `(
  vec { "FACILITATOR_EVM_PRIVATE_KEY"; "FACILITATOR_MAX_GAS"; "JPYC_POLYGON_ADDRESS"; "POLYGON_RPC_SERVICES"; "SETTLE_CONFIRMATION_TIMEOUT_SECONDS"; "SETTLEMENT_CACHE_TTL_SECONDS";},
)`;

describe("canister env smoke", () => {
  it("parses env_names output", () => {
    expect(parseEnvNames(envNamesOutput)).toContain("FACILITATOR_EVM_PRIVATE_KEY");
  });

  it("accepts the required JPYC x402 env name set", () => {
    expect(checkCanisterEnvNames(envNamesOutput)).toMatchObject({
      canister: "edge",
      environment: "local",
      names: expect.arrayContaining(["FACILITATOR_EVM_PRIVATE_KEY", "POLYGON_RPC_SERVICES"])
    });
  });

  it("rejects missing required env names", () => {
    expect(() => checkCanisterEnvNames(`(vec { "FACILITATOR_EVM_PRIVATE_KEY"; })`)).toThrow(
      "missing canister env names"
    );
  });
});
