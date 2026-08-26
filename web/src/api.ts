import type { AcceptanceChallenge, Health, SellerAcceptance, SettlementPage } from "./types";
import { config } from "./env";

function apiUrl(path: string): string {
  if (!config.facilitatorUrl) throw new Error("Facilitator canisterの接続先が設定されていません。");
  return `${config.facilitatorUrl}${path}`;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), { ...init, headers: { Accept: "application/json", "Content-Type": "application/json", ...init?.headers } });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message = typeof body === "object" && body && "message" in body ? String(body.message) : `HTTP ${response.status}`;
    throw new Error(message);
  }
  return body as T;
}

export const api = {
  health: () => json<Health>("/health"),
  credit: (seller: string) => json<{ seller: string; creditAtoms: string }>(`/seller-credit-balance?seller=${encodeURIComponent(seller)}`),
  acceptance: (seller: string) => json<SellerAcceptance | null>(`/seller-acceptance?seller=${encodeURIComponent(seller)}`),
  challenge: (seller: string) => json<AcceptanceChallenge>(`/seller-acceptance/challenge?seller=${encodeURIComponent(seller)}`, { method: "POST", body: "{}" }),
  accept: (challenge: AcceptanceChallenge, signature: string) => json<SellerAcceptance>("/seller-acceptance", { method: "POST", body: JSON.stringify({ ...challenge, signature }) }),
  settlements: (seller: string, cursor?: string) => json<SettlementPage>(`/seller-settlements?seller=${encodeURIComponent(seller)}&limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
};
