import { useState } from "react";
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import type { Network } from "@x402/core/types";
import type { ClientEvmSigner } from "@x402/evm";
import { parseUnits } from "viem";
import { api } from "../api";
import { Address, Notice, PageHeader, SellerNav } from "../components";
import { config } from "../env";
import { connectWallet, requireChain } from "../wallet";

type PreparedTopup = {
  seller: string;
  amount: string;
  amountAtoms: string;
  payTo: string;
  asset: string;
  network: string;
};

function validateAmount(value: string): string {
  if (!/^\d+(\.\d{1,18})?$/.test(value) || Number(value) < 1 || Number(value) > 10_000) {
    throw new Error("1〜10,000 JPYCを小数18桁以内で入力してください。");
  }
  return parseUnits(value, 18).toString();
}

async function loadRequirements(seller: string, amount: string) {
  const url = `${config.facilitatorUrl}/seller-credit?seller=${seller}&amount=${encodeURIComponent(amount)}`;
  const [health, unpaid] = await Promise.all([
    api.health(),
    fetch(url, { headers: { Accept: "application/json" } }),
  ]);
  if (unpaid.status !== 402) throw new Error(`支払い条件を取得できませんでした（HTTP ${unpaid.status}）。時間をおいて再試行してください。`);
  const parser = new x402HTTPClient(new x402Client());
  const required = parser.getPaymentRequiredResponse((name) => unpaid.headers.get(name));
  if (required.accepts.length !== 1) throw new Error("利用できる支払い条件を1件に特定できませんでした。運営者へお問い合わせください。");
  const requirement = required.accepts[0]!;
  const amountAtoms = validateAmount(amount);
  if (requirement.network !== `eip155:${config.chainId}`) throw new Error("支払い条件のnetworkが現在の環境と一致しません。");
  if (requirement.amount !== amountAtoms) throw new Error("支払い条件の金額が入力額と一致しません。");
  if (!health.token || requirement.asset.toLowerCase() !== health.token.toLowerCase()) throw new Error("支払い条件のtokenがfacilitator設定と一致しません。");
  if (requirement.payTo.toLowerCase() === seller.toLowerCase()) throw new Error("Creditの送金先がSeller自身になっています。");
  return { url, unpaid, required, requirement, amountAtoms };
}

export function Credit() {
  const [amount, setAmount] = useState("100");
  const [prepared, setPrepared] = useState<PreparedTopup>();
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [amountError, setAmountError] = useState("");
  const [busy, setBusy] = useState(false);

  async function prepare() {
    setBusy(true); setError(""); setAmountError(""); setStatus("");
    try {
      validateAmount(amount);
      const wallet = await connectWallet();
      await requireChain(wallet.provider, config.chainId);
      const { requirement, amountAtoms } = await loadRequirements(wallet.address, amount);
      setPrepared({ seller: wallet.address, amount, amountAtoms, payTo: requirement.payTo, asset: requirement.asset, network: requirement.network });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      if (message.startsWith("1〜10,000")) setAmountError(message); else setError(message);
    } finally { setBusy(false); }
  }

  async function confirmAndPay() {
    if (!prepared) return;
    setBusy(true); setError("");
    try {
      const wallet = await connectWallet();
      if (wallet.address.toLowerCase() !== prepared.seller.toLowerCase()) throw new Error("確認時と異なるSeller walletが接続されています。元のwalletへ戻してください。");
      await requireChain(wallet.provider, config.chainId);
      const current = await loadRequirements(wallet.address, prepared.amount);
      const unchanged = current.amountAtoms === prepared.amountAtoms
        && current.requirement.payTo.toLowerCase() === prepared.payTo.toLowerCase()
        && current.requirement.asset.toLowerCase() === prepared.asset.toLowerCase()
        && current.requirement.network === prepared.network;
      if (!unchanged) throw new Error("確認後に支払い条件が変更されました。内容をもう一度確認してください。");

      const core = new x402Client();
      const signer: ClientEvmSigner = { address: wallet.address, signTypedData: (args) => wallet.client.signTypedData({ account: wallet.address, ...args }) };
      registerExactEvmScheme(core, { signer, networks: [`eip155:${config.chainId}` as Network] });
      const client = new x402HTTPClient(core);
      const payload = await client.createPaymentPayload(current.required);
      const paid = await fetch(current.url, { headers: { Accept: "application/json", ...client.encodePaymentSignatureHeader(payload) } });
      const body: unknown = await paid.json().catch(() => null);
      if (!paid.ok) throw new Error(typeof body === "object" && body && "message" in body ? String(body.message) : `Creditを追加できませんでした（HTTP ${paid.status}）。`);
      const credit = await api.credit(wallet.address);
      setPrepared(undefined);
      setStatus(`Creditを追加しました。現在の残高は ${credit.creditAtoms} atomic unitsです。`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); }
    finally { setBusy(false); }
  }

  return <section className="page narrow"><SellerNav/><PageHeader eyebrow="SELLER CREDIT" title="手数料Creditを追加" lead="入力額と実際の支払い条件を確認してから、Seller walletで署名します。"/>
    {error&&<Notice tone="warning">{error}</Notice>}{status&&<Notice tone="success">{status}</Notice>}
    <div className="payment-card">
      <label htmlFor="credit-amount">追加する金額</label>
      <span className="amount-input"><input id="credit-amount" name="creditAmount" type="text" inputMode="decimal" autoComplete="off" aria-describedby={amountError?"credit-amount-error":undefined} aria-invalid={Boolean(amountError)} value={amount} onChange={(event)=>{setAmount(event.target.value);setPrepared(undefined);setAmountError("");}}/><b>JPYC</b></span>
      {amountError&&<p id="credit-amount-error" className="field-error" role="alert">{amountError}</p>}
      {!prepared?<>
        <dl><div><dt>用途</dt><dd>Facilitatorの決済手数料のみ</dd></div><div><dt>追加予定</dt><dd>{amount||"0"} JPYC相当</dd></div><div><dt>Gas</dt><dd>Settlement送信時はFacilitatorが負担</dd></div></dl>
        <Notice>次の画面で、実際の送金先・token・networkを確認できます。この段階では署名しません。</Notice>
        <button className="button full" disabled={busy} onClick={()=>void prepare()}>{busy?"支払い条件を取得中…":"支払い条件を確認"}</button>
      </>:<div className="payment-confirm" aria-live="polite">
        <p className="eyebrow">SIGNATURE PREVIEW</p><h2>この内容で署名します</h2>
        <dl><div><dt>支払額</dt><dd><strong>{prepared.amount} JPYC</strong></dd></div><div><dt>送金先</dt><dd><Address value={prepared.payTo}/></dd></div><div><dt>Token</dt><dd><Address value={prepared.asset}/></dd></div><div><dt>Network</dt><dd>{prepared.network}</dd></div><div><dt>用途</dt><dd>Facilitatorの決済手数料のみ</dd></div></dl>
        <Notice>Credit購入後、Settlement transactionをbroadcastした後の手数料は原則返還されません。同じ支払い署名を再送してもCreditは二重加算されません。</Notice>
        <div className="confirm-actions"><button className="button secondary" disabled={busy} onClick={()=>setPrepared(undefined)}>金額を変更</button><button className="button" disabled={busy} onClick={()=>void confirmAndPay()}>{busy?"Walletで署名中…":"表示内容を確認して署名"}</button></div>
      </div>}
    </div>
  </section>;
}
