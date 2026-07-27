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
  batchFees?: {
    deposit?: string | null;
    claim?: string | null;
    settle?: string | null;
    refund?: string | null;
  };
  batchClaimFeeSchedule?: {
    claim1FeeAmount?: string;
    claim10FeeAmount?: string;
    claim50FeeAmount?: string;
    claim100FeeAmount?: string;
    refundWithClaim1FeeAmount?: string;
    refundWithClaim10FeeAmount?: string;
    refundWithClaim50FeeAmount?: string;
    refundWithClaim100FeeAmount?: string;
  } | null;
  batchSettlementContract?: string | null;
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
  facilitatorSignature: string;
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
