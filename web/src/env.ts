export type WebConfig = {
  facilitatorUrl: string;
  chainId: number;
  explorerUrl: string;
  environment: "preview" | "production";
  tokenAddress: string;
  batchSettlementContract: string;
  legalVersions: {
    terms: string;
    privacy: string;
    assetBoundary: string;
  };
};

const environment = (import.meta.env.VITE_APP_ENV ?? "preview") as WebConfig["environment"];
if (environment !== "preview" && environment !== "production") throw new Error("Invalid VITE_APP_ENV");

const chainId = Number(import.meta.env.VITE_CHAIN_ID ?? (environment === "preview" ? "80002" : "137"));
const allowedChain = environment === "preview" ? 80002 : 137;
if (chainId !== allowedChain) throw new Error(`Environment ${environment} must use chain ${allowedChain}`);

const facilitatorUrl = String(import.meta.env.VITE_FACILITATOR_URL ?? "").replace(/\/$/, "");
if (import.meta.env.PROD && !facilitatorUrl) throw new Error("VITE_FACILITATOR_URL is required");
if (import.meta.env.PROD && !/^https:\/\//.test(facilitatorUrl)) throw new Error("VITE_FACILITATOR_URL must be HTTPS");

function requiredEvmAddress(name: string, value: unknown): string {
  const address = String(value ?? "");
  if (!/^0x[0-9a-fA-F]{40}$/.test(address) || /^0x0{40}$/i.test(address)) {
    throw new Error(`${name} must be a non-zero EVM address`);
  }
  return address;
}

const tokenAddress = requiredEvmAddress("VITE_TOKEN_ADDRESS", import.meta.env.VITE_TOKEN_ADDRESS);
const batchSettlementContract = requiredEvmAddress(
  "VITE_BATCH_SETTLEMENT_CONTRACT",
  import.meta.env.VITE_BATCH_SETTLEMENT_CONTRACT,
);

const legalVersions = {
  terms: String(import.meta.env.VITE_SELLER_TERMS_VERSION ?? "2026-07-13-draft"),
  privacy: String(import.meta.env.VITE_PRIVACY_VERSION ?? "2026-07-13-draft"),
  assetBoundary: String(import.meta.env.VITE_ASSET_BOUNDARY_VERSION ?? "2026-07-13-draft"),
};
if (environment === "production" && Object.values(legalVersions).some((version) => version.endsWith("-draft"))) {
  throw new Error("Production build requires approved, non-draft legal document versions");
}

export const config: WebConfig = {
  environment,
  chainId,
  facilitatorUrl,
  tokenAddress,
  batchSettlementContract,
  explorerUrl: String(import.meta.env.VITE_EXPLORER_URL ?? (chainId === 80002 ? "https://amoy.polygonscan.com" : "https://polygonscan.com")),
  legalVersions,
};
