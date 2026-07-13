import { useEffect, useState } from "react";
import { api } from "../api";
import { Notice, PageHeader } from "../components";
import { config } from "../env";
import { legalVersionsMatch } from "../legal";
import { connectWallet, requireChain, type WalletState } from "../wallet";
import type { Health, SellerAcceptance } from "../types";

export function Onboarding() {
  const [wallet, setWallet] = useState<WalletState>(); const [health, setHealth] = useState<Health>(); const [checks, setChecks] = useState([false,false,false]); const [result,setResult]=useState<SellerAcceptance>(); const [error,setError]=useState(""); const [busy,setBusy]=useState(false);
  useEffect(() => { void api.health().then(setHealth).catch(e => setError(String(e))); }, []);
  async function connect() { try { setWallet(await connectWallet()); setError(""); } catch(e) { setError(e instanceof Error ? e.message : String(e)); } }
  const versionsMatch = legalVersionsMatch(config.legalVersions, health?.documentVersions);
  async function accept() { if (!wallet || !checks.every(Boolean) || !versionsMatch) return; setBusy(true); setError(""); try { await requireChain(wallet.provider, config.chainId); const challenge=await api.challenge(wallet.address); const signature=await wallet.client.signMessage({ account: wallet.address, message: challenge.message }); setResult(await api.accept(challenge,signature)); } catch(e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); } }
  const docs=[["/legal/terms","Seller利用規約",health?.documentVersions?.terms],["/legal/privacy","プライバシーポリシー",health?.documentVersions?.privacy],["/legal/asset-boundary","資産管理境界",health?.documentVersions?.assetBoundary]] as const;
  return <section className="page narrow"><PageHeader eyebrow="SELLER ONBOARDING" title="署名して利用を開始" lead="3つの文書と対象networkを確認し、seller walletで同意を記録します。"/>{error&&<Notice tone="warning">{error}</Notice>}{health&&!versionsMatch&&<Notice tone="warning">法務文書versionがfacilitator設定と一致しないため、署名を停止しています。</Notice>}{result?<Notice tone="success">登録が完了しました。受付時刻: {new Date(result.acceptedAt*1000).toLocaleString("ja-JP")}</Notice>:<div className="step-card"><div className="step-row"><span>1</span><div><h2>Wallet</h2>{wallet?<code>{wallet.address}</code>:<button className="button" onClick={() => void connect()}>Rabby / MetaMaskを接続</button>}</div></div><div className="step-row"><span>2</span><div><h2>Network</h2><p>{health?.networkProfile ?? config.environment} · Chain {health?.chainId ?? config.chainId}</p></div></div><div className="step-row"><span>3</span><div><h2>文書を確認</h2>{docs.map(([path,label,version],i)=><label className="check" key={label}><input type="checkbox" checked={checks[i]} disabled={!versionsMatch} onChange={e=>setChecks(v=>v.map((x,j)=>j===i?e.target.checked:x))}/><span><a href={String(path)} target="_blank">{label}</a> <small>version {version??"draft"}</small></span></label>)}</div></div><button className="button full" disabled={!wallet||!checks.every(Boolean)||busy||!versionsMatch} onClick={() => void accept()}>{busy?"署名を確認中…":"同意に署名して登録"}</button></div>}</section>;
}
