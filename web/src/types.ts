export type Health = {
  ok: boolean;
  network: string;
  networkProfile?: string;
  chainId?: number;
  token?: string;
  facilitatorAddress: string;
  polygonRpcConfigured: boolean;
  sellerSettlementFeeAmount?: string | null;
  batchSettlementFeeAmount?: string | null;
  receiverAuthorizer?: string | null;
  readiness?: boolean;
  documentVersions?: { terms: string; privacy: string; assetBoundary: string };
};

export type SellerAcceptance = {
  seller: string;
  status: string;
  termsVersion: string;
  privacyVersion: string;
  assetBoundaryVersion: string;
  acceptedAt: number;
  superseded: boolean;
};

export type AcceptanceChallenge = {
  seller: string;
  nonce: string;
  expiresAt: number;
  message: string;
};

export type SettlementItem = {
  key: string;
  kind: "exact" | "batch";
  status: string;
  payer: string;
  seller: string;
  amount: string;
  fee: string;
  transaction: string;
  confirmations: number;
  failureReason?: string | null;
  createdAt: number;
  updatedAt: number;
};

export type SettlementPage = { items: SettlementItem[]; nextCursor?: string | null };
