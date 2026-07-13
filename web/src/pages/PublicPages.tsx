import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api } from "../api";
import { PageHeader } from "../components";
import { formatJpyc } from "../format";
import type { Health } from "../types";

export function Home() { return <>
  <section className="hero"><div><p className="eyebrow">JPYC × x402 × ICP</p><h1>支払いの約束を、<br/><em>そのまま決済へ。</em></h1><p className="lead">payerとsellerが署名した条件をcanisterで検証し、条件を変えずにPolygonへ送信します。</p><div className="actions"><NavLink className="button" to="/seller/onboarding">Sellerとして始める</NavLink><NavLink className="text-link" to="/how-it-works">仕組みを見る →</NavLink></div></div><PaymentRail /></section>
  <section className="section"><p className="eyebrow">担当すること</p><h2>決済だけに、責任を絞る</h2><div className="three"><article><b>01</b><h3>署名を検証</h3><p>金額、receiver、期限、nonceを照合します。</p></article><article><b>02</b><h3>取引を送信</h3><p>検証済みcalldataをPolygonへ送り、gasを負担します。</p></article><article><b>03</b><h3>結果を記録</h3><p>transaction receiptと状態をcanisterへ残します。</p></article></div></section>
  <section className="boundary"><div><p className="eyebrow">担当しないこと</p><h2>商品、注文、任意送金は管理しません。</h2></div><p>商品や注文の正本はmerchant側です。Batch depositのJPYCは公式contract上にあり、facilitator walletやICP canisterへ移りません。</p></section>
  </>; }

function PaymentRail() { return <div className="rail" aria-label="決済の流れ"><div><span>Payer</span><b>署名</b></div><i>→</i><div><span>Canister</span><b>検証</b></div><i>→</i><div><span>Polygon</span><b>決済</b></div><p>条件はレールの途中で変わりません</p></div>; }

export function HowItWorks() { return <section className="page"><PageHeader eyebrow="HOW IT WORKS" title="2つの決済方法" lead="一回ごとに完了するExactと、署名済み上限の範囲でまとめるBatchがあります。"/><div className="flow-block"><h2>Exact settlement</h2><ol><li><b>Payer</b><span>EIP-3009で今回の金額を許可</span></li><li><b>Seller</b><span>支払条件をEIP-191で承認</span></li><li><b>Facilitator</b><span>両方を検証し、transferWithAuthorizationを送信</span></li></ol></div><div className="flow-block"><h2>Batch settlement</h2><ol><li><b>Payer</b><span>公式contractへdeposit</span></li><li><b>Payer authorizer</b><span>累積maxClaimableAmountへ署名</span></li><li><b>Facilitator</b><span>上限内でclaimし、receiverへsettle</span></li></ol></div></section>; }

export function Pricing() { const [health,setHealth]=useState<Health>();const [error,setError]=useState("");useEffect(()=>{void api.health().then(setHealth).catch(()=>setError("現在の料金を取得できませんでした。時間をおいて再読み込みしてください。"));},[]);return <section className="page"><PageHeader eyebrow="PRICING" title="現在の決済手数料" lead="Canisterに設定されている手数料を表示します。実行前にSeller dashboardでも確認できます。"/>{error&&<div className="notice warning" role="status">{error}</div>}<div className="price-grid"><article><p>Exact</p><strong>{health?formatJpyc(health.sellerSettlementFeeAmount):"取得中…"}</strong><span>通常Settlement 1件</span></article><article className="featured"><p>Batch action</p><strong>{health?formatJpyc(health.batchSettlementFeeAmount):"取得中…"}</strong><span>deposit / claim / settle / refund</span></article></div><div className="notice info">Polygon gasはFacilitatorの送信walletが負担します。Seller Creditは手数料専用で、送金・譲渡・換金はできません。</div></section>; }
