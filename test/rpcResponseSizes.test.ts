import { describe, expect, it } from "vitest";

import {
  jsonUtf8Bytes,
  measureResponse,
  recommendedResponseBytes,
  responseCyclesSaved,
  validateJsonRpcResponse
} from "../scripts/rpc_response_sizes";

describe("RPC response size measurement", () => {
  it("counts serialized UTF-8 bytes instead of characters", () => {
    expect(jsonUtf8Bytes({ result: "円" })).toBe(Buffer.byteLength('{"result":"円"}', "utf8"));
  });

  it("adds 64 bytes and rounds fixed responses to 64-byte units", () => {
    expect(recommendedResponseBytes(0)).toBe(64);
    expect(recommendedResponseBytes(45)).toBe(128);
    expect(recommendedResponseBytes(102)).toBe(192);
    expect(recommendedResponseBytes(224)).toBe(320);
    expect(() => recommendedResponseBytes(-1)).toThrow("non-negative safe integer");
  });

  it("adds 25 percent and rounds receipts to 1 KiB", () => {
    expect(recommendedResponseBytes(1_031, "eth_getTransactionReceipt")).toBe(2_048);
    expect(recommendedResponseBytes(3_258, "eth_getTransactionReceipt")).toBe(4_096);
  });

  it("calculates direct HTTPS outcall response-byte savings for 13 nodes", () => {
    expect(responseCyclesSaved(1_024)).toBe(197_350_400n);
    expect(responseCyclesSaved(20_000)).toBe(0n);
    expect(responseCyclesSaved(21_000)).toBe(0n);
  });

  it("reports receipt log count and uses the whole JSON-RPC response", () => {
    const response = {
      id: 1,
      jsonrpc: "2.0",
      result: { logs: [{ data: "0x" }, { data: "0x01" }], status: "0x1" }
    };
    const result = measureResponse("batch-claim", "eth_getTransactionReceipt", response);
    expect(result.logCount).toBe(2);
    expect(result.responseWithoutLogsBytes).toBeLessThan(result.rawResponseBytes);
    expect(result.rawResponseBytes).toBe(jsonUtf8Bytes(response));
    expect(result.resultBytes).toBe(jsonUtf8Bytes(response.result));
  });

  it("keeps large variable-log receipts at or above the existing limit", () => {
    const response = {
      id: 1,
      jsonrpc: "2.0",
      result: {
        logs: Array.from({ length: 60 }, (_, index) => ({
          address: "0x431D5dfF03120AFA4bDf332c61A6e1766eF37BDB",
          data: `0x${index.toString(16).padStart(64, "0")}`,
          topics: ["0x" + "a".repeat(64), "0x" + "b".repeat(64), "0x" + "c".repeat(64)]
        })),
        status: "0x1"
      }
    };
    const result = measureResponse("large-receipt", "eth_getTransactionReceipt", response);
    expect(result.rawResponseBytes).toBeGreaterThan(20_000);
    expect(result.recommendedResponseBytes).toBeGreaterThan(20_000);
    expect(result.cyclesSavedFrom20Kb).toBe("0");
  });

  it("rejects JSON-RPC errors, null results, and mismatched receipt hashes", () => {
    expect(() => validateJsonRpcResponse("eth_call", {
      id: 1,
      jsonrpc: "2.0",
      error: { code: -1 },
    })).toThrow("JSON-RPC error");
    expect(() => validateJsonRpcResponse("eth_call", {
      id: 1,
      jsonrpc: "2.0",
      result: null,
    })).toThrow("missing non-null result");
    expect(() => validateJsonRpcResponse("eth_getTransactionReceipt", {
      id: 1,
      jsonrpc: "2.0",
      result: { transactionHash: "0xdef" },
    }, "0xabc")).toThrow("transaction hash mismatch");
  });

  it("accepts a valid receipt envelope with the requested hash", () => {
    expect(() => validateJsonRpcResponse("eth_getTransactionReceipt", {
      id: 1,
      jsonrpc: "2.0",
      result: { transactionHash: "0xAbC" },
    }, "0xabc")).not.toThrow();
  });
});
