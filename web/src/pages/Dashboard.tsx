import { useState } from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api";
import { Address, Notice, PageHeader, SellerNav, Stat } from "../components";
import { formatJpyc } from "../format";
import { connectWallet } from "../wallet";
import type { Health, SellerAcceptance, SettlementItem } from "../types";

export function Dashboard() {
  const [address, setAddress] = useState("");
  const [health, setHealth] = useState<Health>();
  const [acceptance, setAcceptance] = useState<SellerAcceptance | null>();
  const [credit, setCredit] = useState<string>();
  const [recent, setRecent] = useState<SettlementItem[]>([]);
  const [error, setError] = useState("");
  const [loadState, setLoadState] = useState<"idle"|"loading"|"ready"|"error">("idle");

  async function load() {
    try {
      setLoadState("loading"); setError("");
      const wallet = await connectWallet();
      setAddress(wallet.address);
      const [nextHealth, nextAcceptance, nextCredit, settlements] = await Promise.all([
        api.health(), api.acceptance(wallet.address), api.credit(wallet.address), api.settlements(wallet.address),
      ]);
      setHealth(nextHealth); setAcceptance(nextAcceptance); setCredit(nextCredit.creditAtoms); setRecent(settlements.items.slice(0, 5));
      setLoadState("ready");
    } catch (cause) { setError(cause instanceof Error ? cause.message : String(cause)); setLoadState("error"); }
  }

  return <section className="page"><SellerNav/><PageHeader eyebrow="SELLER DASHBOARD" title="決済の準備状況" lead="同意、Credit、Facilitatorの基本設定を一か所で確認できます。"/>
    {!address&&<button className="button" disabled={loadState==="loading"} onClick={()=>void load()}>{loadState==="loading"?"読み込み中…":"Seller walletを接続"}</button>}{error&&<Notice tone="warning">{error} <button className="text-link" onClick={()=>void load()}>再試行</button></Notice>}
    {address&&<><div className="identity"><div><span>Seller</span><Address value={address}/></div><span className={`status ${loadState==="ready"&&health?.readiness?"ready":"waiting"}`}>{loadState==="loading"?"読み込み中":loadState==="ready"&&health?.readiness?"基本設定済み":"設定確認が必要"}</span></div>
      {loadState==="ready"&&health&&credit!==undefined&&<div className="stats"><Stat label="Seller Credit" value={formatJpyc(credit)} note="Facilitator手数料専用"/><Stat label="Exact料金" value={formatJpyc(health.sellerSettlementFeeAmount)}/><Stat label="Batch settle料金" value={formatJpyc(health.batchFees?.settle)}/></div>}
      {loadState==="loading"&&<p role="status">Seller情報を読み込んでいます…</p>}
      {loadState==="ready"&&<>
      {!acceptance||acceptance.superseded?<Notice tone="warning">現行versionへの同意が必要です。 <NavLink to="/seller/onboarding">同意を更新</NavLink></Notice>:<Notice tone="success">Seller登録は有効です。</Notice>}
      <div className="dashboard-grid"><article><div className="section-title"><h2>最近のSettlement</h2><NavLink to="/seller/settlements">すべて見る</NavLink></div>{recent.length===0?<p className="empty">Settlementはまだありません。</p>:recent.map((item)=><div className="list-row" key={item.key}><span className={`dot ${item.status}`} aria-hidden="true"/><div><b>{item.kind}</b><small>{formatJpyc(item.amount)}</small></div><code>{item.status}</code></div>)}</article>
        <article><h2>Facilitator</h2><dl><div><dt>Network</dt><dd>{health!.networkProfile??health!.network}</dd></div><div><dt>Receiver authorizer</dt><dd>{health!.receiverAuthorizer?<Address value={health!.receiverAuthorizer}/> : "—"}</dd></div><div><dt>RPC</dt><dd>{health!.polygonRpcConfigured?"設定済み":"未設定"}</dd></div></dl><NavLink className="button secondary" to="/seller/credit">Creditを追加</NavLink></article></div></>}
    </>}
  </section>;
}
