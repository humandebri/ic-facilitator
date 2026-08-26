import type { Health } from "./types";

export type RuntimeMatchConfig = {
  environment: "preview" | "production";
  chainId: number;
  tokenAddress: string;
  batchSettlementContract: string;
};

export function healthMatchesWebConfig(
  health: Health | undefined,
  config: RuntimeMatchConfig,
): boolean {
  if (!health) return false;
  const expectedProfile = config.environment === "preview" ? "amoy" : "polygon";
  return health.ok
    && health.readiness === true
    && health.chainId === config.chainId
    && health.network === `eip155:${config.chainId}`
    && health.networkProfile === expectedProfile
    && health.token?.toLowerCase() === config.tokenAddress.toLowerCase()
    && health.batchSettlementContract?.toLowerCase() === config.batchSettlementContract.toLowerCase();
}
