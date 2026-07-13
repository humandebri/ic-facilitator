export type WebConfig = {
  facilitatorUrl: string;
  chainId: number;
  explorerUrl: string;
  environment: "preview" | "production";
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
  explorerUrl: String(import.meta.env.VITE_EXPLORER_URL ?? (chainId === 80002 ? "https://amoy.polygonscan.com" : "https://polygonscan.com")),
  legalVersions,
};
