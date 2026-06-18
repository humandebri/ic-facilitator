// test/batchMainnetPreflight.test.ts: batch mainnet preflight のread-only検証条件を確認する。
import { describe, expect, it } from "vitest";
import type { Address, Hex } from "viem";

import { checkBatchMainnetPreflight } from "../scripts/batch_mainnet_preflight";
import type { BatchMainnetPreflightReader } from "../scripts/batch_mainnet_preflight";

const jpyc: Address = "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB";
const batchContract: Address = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003";
const contractCode: Hex = "0x60016000";

type FakeReaderOptions = {
  readonly batchCode?: Hex;
  readonly chainId?: number;
  readonly rejectAuthorizationState?: boolean;
  readonly jpycCode?: Hex;
  readonly jpycDecimals?: number;
  readonly jpycName?: string;
  readonly rejectBatchChannel?: boolean;
};

class FakeReader implements BatchMainnetPreflightReader {
  private readonly options: FakeReaderOptions;

  constructor(options: FakeReaderOptions = {}) {
    this.options = options;
  }

  async getBatchChannel(): Promise<readonly [bigint, bigint]> {
    if (this.options.rejectBatchChannel) {
      throw new Error("channels selector reverted");
    }
    return [0n, 0n];
  }

  async getBatchPendingWithdrawal(): Promise<readonly [bigint, number]> {
    return [0n, 0];
  }

  async getBatchReceiver(): Promise<readonly [bigint, bigint]> {
    return [0n, 0n];
  }

  async getBatchRefundNonce(): Promise<bigint> {
    return 0n;
  }

  async getBytecode(address: Address): Promise<Hex | undefined> {
    if (address.toLowerCase() === batchContract.toLowerCase()) {
      return this.options.batchCode;
    }
    if (address.toLowerCase() === jpyc.toLowerCase()) {
      return this.options.jpycCode ?? contractCode;
    }
    return undefined;
  }

  async getChainId(): Promise<number> {
    return this.options.chainId ?? 137;
  }

  async getJpycAuthorizationState(): Promise<boolean> {
    if (this.options.rejectAuthorizationState) {
      throw new Error("authorizationState selector reverted");
    }
    return false;
  }

  async getJpycDecimals(): Promise<number> {
    return this.options.jpycDecimals ?? 18;
  }

  async getJpycName(): Promise<string> {
    return this.options.jpycName ?? "JPY Coin";
  }
}

class CountingReader extends FakeReader {
  calls = 0;

  override async getChainId(): Promise<number> {
    this.calls += 1;
    return super.getChainId();
  }
}

function baseEnv(): NodeJS.ProcessEnv {
  return {
    BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "ryjl3-tyaaa-aaaaa-aaaba-cai",
    BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "0x2222222222222222222222222222222222222222222222222222222222222222",
    BATCH_SETTLEMENT_CONTRACT: batchContract,
    BATCH_SETTLEMENT_FEE_AMOUNT: "100",
    BATCH_WITHDRAW_DELAY_SECONDS: "900",
    JPYC_EIP712_VERSION: "1",
    POLYGON_RPC_URL: "https://polygon.example"
  };
}

describe("batch mainnet preflight", () => {
  it("accepts Polygon JPYC and batch contract read-only prerequisites", async () => {
    const report = await checkBatchMainnetPreflight({
      env: baseEnv(),
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(true);
    expect(report.batchContract).toBe(batchContract);
    expect(report.jpyc).toBe(jpyc);
    expect(report.checks.map((check) => check.status)).not.toContain("fail");
  });

  it("rejects a non-Polygon RPC endpoint", async () => {
    const report = await checkBatchMainnetPreflight({
      env: baseEnv(),
      reader: new FakeReader({ batchCode: contractCode, chainId: 80002 })
    });

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({
      detail: "expected 137, got 80002",
      name: "polygon:chainId",
      status: "fail"
    });
  });

  it("rejects missing batch contract code", async () => {
    const report = await checkBatchMainnetPreflight({
      env: baseEnv(),
      reader: new FakeReader()
    });

    expect(report.ready).toBe(false);
    expect(report.checks.find((check) => check.name === "polygon:batchContractCode")?.detail)
      .toContain("no contract code");
  });

  it("rejects JPYC mismatch and unusable batch selectors", async () => {
    const report = await checkBatchMainnetPreflight({
      env: { ...baseEnv(), JPYC_POLYGON_ADDRESS: "0x0000000000000000000000000000000000000002" },
      reader: new FakeReader({
        batchCode: contractCode,
        jpycDecimals: 6,
        jpycName: "Other Token",
        rejectAuthorizationState: true,
        rejectBatchChannel: true
      })
    });

    expect(report.ready).toBe(false);
    expect(report.checks.find((check) => check.name === "env:JPYC_POLYGON_ADDRESS")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "jpyc:name")?.detail).toBe("expected JPY Coin, got Other Token");
    expect(report.checks.find((check) => check.name === "jpyc:decimals")?.detail).toBe("expected 18, got 6");
    expect(report.checks.find((check) => check.name === "jpyc:authorizationStateSelector")?.detail).toBe("authorizationState selector reverted");
    expect(report.checks.find((check) => check.name === "batch:channelsSelector")?.detail).toBe("channels selector reverted");
  });

  it("rejects missing required env before relying on RPC", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "",
        BATCH_SETTLEMENT_FEE_AMOUNT: "",
        BATCH_WITHDRAW_DELAY_SECONDS: "",
        JPYC_EIP712_VERSION: "",
        POLYGON_RPC_URL: ""
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.checks.find((check) => check.name === "env:POLYGON_RPC_URL")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "env:JPYC_EIP712_VERSION")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "env:BATCH_SETTLEMENT_CONTRACT")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "env:BATCH_WITHDRAW_DELAY_SECONDS")?.detail)
      .toBe("未設定");
    expect(report.checks.find((check) => check.name === "env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "env:BATCH_SETTLEMENT_FEE_AMOUNT")?.status).toBe("fail");
    expect(report.checks.find((check) => check.name === "env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL")?.status).toBe("fail");
  });

  it("rejects a non-JPYC EIP-712 version and unsafe withdraw delay", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_WITHDRAW_DELAY_SECONDS: "2592001",
        JPYC_EIP712_VERSION: "2"
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({
      detail: "must be 1",
      name: "env:JPYC_EIP712_VERSION",
      status: "fail"
    });
    expect(report.checks).toContainEqual({
      detail: "must be between 900 and 2592000",
      name: "env:BATCH_WITHDRAW_DELAY_SECONDS",
      status: "fail"
    });
  });

  it("rejects invalid batch authorizer key and settlement fee env", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: "0x1234",
        BATCH_SETTLEMENT_FEE_AMOUNT: "0"
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({
      detail: "0x-prefixed 32-byte private key ではない",
      name: "env:BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY",
      status: "fail"
    });
    expect(report.checks).toContainEqual({
      detail: "positive integer ではない",
      name: "env:BATCH_SETTLEMENT_FEE_AMOUNT",
      status: "fail"
    });
  });

  it("rejects using the facilitator key as the batch receiver authorizer key", async () => {
    const sharedKey = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY: sharedKey,
        FACILITATOR_EVM_PRIVATE_KEY: sharedKey
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({
      detail: "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY must not derive the FACILITATOR_EVM_PRIVATE_KEY address",
      name: "env:BATCH_KEY_SEPARATION",
      status: "fail"
    });
  });

  it("rejects a batch settlement fee that exceeds uint128", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_SETTLEMENT_FEE_AMOUNT: "340282366920938463463374607431768211456"
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.checks).toContainEqual({
      detail: "uint128 に収まらない",
      name: "env:BATCH_SETTLEMENT_FEE_AMOUNT",
      status: "fail"
    });
  });

  it("reports an invalid batch settlement contract without throwing", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_SETTLEMENT_CONTRACT: "not an address"
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.batchContract).toBeUndefined();
    expect(report.checks).toContainEqual({
      detail: "non-zero 0x-prefixed EVM address ではない",
      name: "env:BATCH_SETTLEMENT_CONTRACT",
      status: "fail"
    });
  });

  it("rejects a non-canonical batch settlement contract", async () => {
    const report = await checkBatchMainnetPreflight({
      env: {
        ...baseEnv(),
        BATCH_SETTLEMENT_CONTRACT: "0x0000000000000000000000000000000000000001"
      },
      reader: new FakeReader({ batchCode: contractCode })
    });

    expect(report.ready).toBe(false);
    expect(report.batchContract).toBeUndefined();
    expect(report.checks).toContainEqual({
      detail: `official @x402/evm BATCH_SETTLEMENT_ADDRESS ${batchContract} と不一致`,
      name: "env:BATCH_SETTLEMENT_CONTRACT",
      status: "fail"
    });
  });

  it("rejects invalid batch channel storage writer principal", async () => {
    const invalid = await checkBatchMainnetPreflight({
      env: { ...baseEnv(), BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "not a principal" },
      reader: new FakeReader({ batchCode: contractCode })
    });
    expect(invalid.ready).toBe(false);
    expect(invalid.checks).toContainEqual({
      detail: "IC principal ではない",
      name: "env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
      status: "fail"
    });

    const system = await checkBatchMainnetPreflight({
      env: { ...baseEnv(), BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL: "2vxsx-fae" },
      reader: new FakeReader({ batchCode: contractCode })
    });
    expect(system.ready).toBe(false);
    expect(system.checks).toContainEqual({
      detail: "system principal は不可",
      name: "env:BATCH_CHANNEL_STORAGE_WRITER_PRINCIPAL",
      status: "fail"
    });
  });

  it("requires a HTTPS Polygon RPC endpoint without userinfo or fragment", async () => {
    for (const value of [
      "http://polygon.example",
      "https://trusted.example@evil.example",
      "https://polygon.example/#x",
      "https://polygon.example/v2/key#x"
    ]) {
      const report = await checkBatchMainnetPreflight({
        env: { ...baseEnv(), POLYGON_RPC_URL: value },
        reader: new FakeReader({ batchCode: contractCode })
      });
      expect(report.ready).toBe(false);
      expect(report.checks).toContainEqual({
        detail: "userinfo/fragment なしの HTTPS URL ではない",
        name: "env:POLYGON_RPC_URL",
        status: "fail"
      });
    }

    for (const value of [
      "https://polygon.example:443",
      "https://polygon-mainnet.example/v2/api-key",
      "https://polygon-mainnet.example/rpc?apikey=abc"
    ]) {
      const report = await checkBatchMainnetPreflight({
        env: { ...baseEnv(), POLYGON_RPC_URL: value },
        reader: new FakeReader({ batchCode: contractCode })
      });
      expect(report.checks.find((check) => check.name === "env:POLYGON_RPC_URL")?.status).toBe("ok");
    }
  });

  it("does not call the RPC reader when the RPC URL fails local validation", async () => {
    const reader = new CountingReader({ batchCode: contractCode });
    const report = await checkBatchMainnetPreflight({
      env: { ...baseEnv(), POLYGON_RPC_URL: "https://trusted.example@evil.example" },
      reader
    });

    expect(report.ready).toBe(false);
    expect(reader.calls).toBe(0);
    expect(report.checks.map((check) => check.name)).not.toContain("polygon:chainId");
  });
});
