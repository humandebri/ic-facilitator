// src/x402Support.ts: facilitator support で要求する x402/JPYC 前提を共有する。
import type { SupportedResponse } from "@x402/core/types";

export const EXPECTED_X402_VERSION = 2;
export const EXPECTED_NETWORK = "eip155:137";
export const EXPECTED_SCHEME = "exact";

export function supportsExpectedX402Kind(kinds: SupportedResponse["kinds"]): boolean {
  return kinds.some(
    (kind) =>
      kind.x402Version === EXPECTED_X402_VERSION &&
      kind.network === EXPECTED_NETWORK &&
      kind.scheme === EXPECTED_SCHEME
  );
}

export function expectedX402SupportLabel(): string {
  return `x402 v${EXPECTED_X402_VERSION} ${EXPECTED_SCHEME}/${EXPECTED_NETWORK}`;
}
