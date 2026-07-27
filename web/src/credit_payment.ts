export type PaidTopupResponse = {
  creditAtoms?: string | number;
  settlement?: { transaction?: string; errorReason?: string };
  message?: string;
};

export type CreditPaymentOutcome =
  | { kind: "pending"; transaction?: string }
  | { kind: "success"; creditAtoms: string };

export function creditPaymentOutcome(
  status: number,
  body: PaidTopupResponse | null,
): CreditPaymentOutcome {
  if (status === 202) {
    const transaction = body?.settlement?.transaction;
    return transaction
      ? { kind: "pending", transaction }
      : { kind: "pending" };
  }
  if (status < 200 || status >= 300) {
    throw new Error(body?.message ?? `Creditを追加できませんでした（HTTP ${status}）。`);
  }
  return {
    kind: "success",
    creditAtoms: body?.creditAtoms == null ? "不明" : String(body.creditAtoms),
  };
}

export function confirmedCreditMessage(creditAtoms: string, refreshFailed = false): string {
  return refreshFailed
    ? `Creditを追加しました。残高の再取得には失敗しましたが、購入結果は確定しています（${creditAtoms} atomic units）。`
    : `Creditを追加しました。現在の残高は ${creditAtoms} atomic unitsです。`;
}
