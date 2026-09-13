import { decodeAbiParameters, encodeFunctionData, parseAbi, parseAbiParameters } from "viem";
import type { Address, Hex } from "viem";

const channelParameters = parseAbiParameters("(address,address,address,address,address,uint40,bytes32)");
const abi = parseAbi([
  "function claimWithSignature((((address,address,address,address,address,uint40,bytes32),uint128),bytes,uint128)[],bytes)",
  "function deposit((address,address,address,address,address,uint40,bytes32),uint128,address,bytes)",
  "function refundWithSignature((address,address,address,address,address,uint40,bytes32),uint128,uint256,bytes)",
  "function settle(address,address)",
  "function multicall(bytes[])",
]);

function channel(words: string) {
  return decodeAbiParameters(channelParameters, `0x${words}`)[0];
}

export function claimInputFor(claims: readonly { readonly configWords: string; readonly totalClaimed: bigint }[]): Hex {
  return encodeFunctionData({ abi, functionName: "claimWithSignature", args: [
    claims.map(({ configWords, totalClaimed }) => [[channel(configWords), 100n], `0x${"11".repeat(65)}`, totalClaimed] as const),
    `0x${"22".repeat(65)}`,
  ] });
}

export function refundInputFor(configWords: string, nonce: bigint): Hex {
  return encodeFunctionData({ abi, functionName: "refundWithSignature", args: [channel(configWords), 1500n, nonce, `0x${"44".repeat(65)}`] });
}

export function depositInputFor(configWords: string, collector: Address, amount: bigint): Hex {
  return encodeFunctionData({ abi, functionName: "deposit", args: [channel(configWords), amount, collector, "0x"] });
}

export function settleInputFor(receiver: Address, token: Address): Hex {
  return encodeFunctionData({ abi, functionName: "settle", args: [receiver, token] });
}

export function multicallInputFor(calls: readonly Hex[]): Hex {
  return encodeFunctionData({ abi, functionName: "multicall", args: [calls] });
}
