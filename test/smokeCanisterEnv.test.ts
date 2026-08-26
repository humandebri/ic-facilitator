// test/smokeCanisterEnv.test.ts: canister env name smoke が secret 値なしで不足名を検出することを確認する。
import { describe, expect, it } from "vitest";

import { canisterEnvSmokeOptionsFromArgs, checkCanisterEnvNames, parseEnvNames } from "../scripts/smoke_canister_env";

function envName(parts: readonly string[]): string {
  return parts.join("_");
}

const facilitatorKeyEnv = envName(["FACILITATOR", "EVM", "PRIVATE", "KEY"]);

const envNamesOutput = `(
  vec { "${facilitatorKeyEnv}"; "FACILITATOR_MAX_GAS"; "FACILITATOR_MAX_SETTLEMENT_FEE_WEI"; "FACILITATOR_PUBLIC_ORIGIN"; "JPYC_EIP712_VERSION"; "POLYGON_RPC_URL"; "SELLER_CREDIT_PAY_TO"; "SELLER_SETTLEMENT_FEE_AMOUNT"; "SETTLE_CONFIRMATION_TIMEOUT_SECONDS"; "SETTLE_MIN_CONFIRMATIONS"; "SETTLEMENT_CACHE_TTL_SECONDS";},
)`;
const batchEnvNamesOutput = `(
  vec { "${facilitatorKeyEnv}"; "FACILITATOR_MAX_GAS"; "FACILITATOR_MAX_SETTLEMENT_FEE_WEI"; "FACILITATOR_PUBLIC_ORIGIN"; "JPYC_EIP712_VERSION"; "POLYGON_RPC_URL"; "SELLER_CREDIT_PAY_TO"; "SELLER_SETTLEMENT_FEE_AMOUNT"; "SETTLE_CONFIRMATION_TIMEOUT_SECONDS"; "SETTLE_MIN_CONFIRMATIONS"; "SETTLEMENT_CACHE_TTL_SECONDS"; "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"; "BATCH_SETTLEMENT_CONTRACT"; "BATCH_SETTLEMENT_FEE_AMOUNT"; "BATCH_WITHDRAW_DELAY_SECONDS";},
)`;
const partialBatchActionEnvNamesOutput = batchEnvNamesOutput.replace(
  '"BATCH_SETTLEMENT_FEE_AMOUNT";',
  '"BATCH_SETTLEMENT_FEE_AMOUNT"; "BATCH_CLAIM_FEE_AMOUNT";'
);

describe("canister env smoke", () => {
  it("parses env_names output", () => {
    expect(parseEnvNames(envNamesOutput)).toContain(facilitatorKeyEnv);
  });

  it("rejects env_names output with extra text outside the Candid vector", () => {
    expect(() => parseEnvNames(`warning "BATCH_SETTLEMENT_CONTRACT" ${envNamesOutput}`)).toThrow(
      "unexpected env_names output"
    );
  });

  it("accepts the required JPYC x402 env name set", () => {
    expect(checkCanisterEnvNames(envNamesOutput)).toMatchObject({
      canister: "edge",
      environment: "local",
      names: expect.arrayContaining([facilitatorKeyEnv, "JPYC_EIP712_VERSION", "POLYGON_RPC_URL"])
    });
  });

  it("rejects missing required env names", () => {
    expect(() => checkCanisterEnvNames(`(vec { "${facilitatorKeyEnv}"; })`)).toThrow(
      "missing canister env names"
    );
  });

  it("can require batch env names", () => {
    expect(checkCanisterEnvNames(batchEnvNamesOutput, "ic", "edge", { requireBatch: true })).toMatchObject({
      canister: "edge",
      environment: "ic",
      names: expect.arrayContaining(["BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", "BATCH_SETTLEMENT_CONTRACT"])
    });

    expect(() => checkCanisterEnvNames(envNamesOutput, "ic", "edge", { requireBatch: true })).toThrow(
      "missing canister env names: BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
    );
    expect(() => checkCanisterEnvNames(partialBatchActionEnvNamesOutput, "ic", "edge", { requireBatch: true })).toThrow(
      "partial batch action fee env names: BATCH_DEPOSIT_FEE_AMOUNT"
    );
  });

  it("enables batch env checks from the CLI flag", () => {
    expect(canisterEnvSmokeOptionsFromArgs(["node", "scripts/smoke_canister_env.ts"])).toEqual({
      requireBatch: false
    });
    const options = canisterEnvSmokeOptionsFromArgs(["node", "scripts/smoke_canister_env.ts", "--with-batch"]);
    expect(options).toEqual({ requireBatch: true });
    expect(() => checkCanisterEnvNames(envNamesOutput, "ic", "edge", options)).toThrow(
      "missing canister env names: BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY"
    );
  });
});
