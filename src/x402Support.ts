// src/x402Support.ts: facilitator support で要求する x402/JPYC 前提を共有する。
import type { SupportedResponse } from "@x402/core/types";

export const EXPECTED_X402_VERSION = 2;
export const EXPECTED_NETWORK = "eip155:137";
export const EXPECTED_SCHEME = "exact";
export const EXPECTED_TRANSFER_METHOD = "eip3009";

export function supportsExpectedX402Kind(kinds: SupportedResponse["kinds"]): boolean {
  return kinds.some(
    (kind) =>
      kind.x402Version === EXPECTED_X402_VERSION &&
      kind.network === EXPECTED_NETWORK &&
      kind.scheme === EXPECTED_SCHEME &&
      kind.extra?.assetTransferMethod === EXPECTED_TRANSFER_METHOD &&
      kind.extra?.name === "JPY Coin" &&
      typeof kind.extra?.version === "string" &&
      kind.extra.version.length > 0
  );
}

export function expectedX402SupportLabel(): string {
  return `x402 v${EXPECTED_X402_VERSION} ${EXPECTED_SCHEME}/${EXPECTED_NETWORK}/${EXPECTED_TRANSFER_METHOD}`;
}
