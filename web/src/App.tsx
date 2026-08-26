import { lazy } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { LazyRoute } from "./LazyRoute";

const Home = lazy(() => import("./pages/PublicPages").then((module) => ({ default: module.Home })));
const HowItWorks = lazy(() => import("./pages/PublicPages").then((module) => ({ default: module.HowItWorks })));
const Pricing = lazy(() => import("./pages/PublicPages").then((module) => ({ default: module.Pricing })));
const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const Onboarding = lazy(() => import("./pages/Onboarding").then((module) => ({ default: module.Onboarding })));
const Credit = lazy(() => import("./pages/Credit").then((module) => ({ default: module.Credit })));
const Settlements = lazy(() => import("./pages/Settlements").then((module) => ({ default: module.Settlements })));
const LegalPage = lazy(() => import("./pages/Legal").then((module) => ({ default: module.LegalPage })));

const nav = [["/how-it-works", "仕組み"], ["/pricing", "料金"], ["/seller", "Seller"]] as const;

export function App() {
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">本文へ移動</a>
    <header className="site-header"><NavLink className="brand" to="/"><span className="brand-mark">F</span><span>JPYC Facilitator</span></NavLink><nav aria-label="メインナビゲーション">{nav.map(([to,label]) => <NavLink key={to} to={to}>{label}</NavLink>)}</nav></header>
    <main id="main-content" tabIndex={-1}><LazyRoute><Routes>
      <Route path="/" element={<Home />} />
      <Route path="/how-it-works" element={<HowItWorks />} />
      <Route path="/pricing" element={<Pricing />} />
      <Route path="/seller/onboarding" element={<Onboarding />} />
      <Route path="/seller" element={<Dashboard />} />
      <Route path="/seller/credit" element={<Credit />} />
      <Route path="/seller/settlements" element={<Settlements />} />
      <Route path="/legal/terms" element={<LegalPage kind="terms" />} />
      <Route path="/legal/privacy" element={<LegalPage kind="privacy" />} />
      <Route path="/legal/asset-boundary" element={<LegalPage kind="asset" />} />
      <Route path="*" element={<section className="page"><p className="eyebrow">404</p><h1>ページが見つかりません</h1><NavLink className="button" to="/">トップへ戻る</NavLink></section>} />
    </Routes></LazyRoute></main>
    <footer><div><strong>JPYC Facilitator</strong><p>署名条件に沿って決済を検証し、Polygonへ送信します。</p></div><div className="footer-links"><NavLink to="/legal/terms">利用規約</NavLink><NavLink to="/legal/privacy">プライバシー</NavLink><NavLink to="/legal/asset-boundary">資産管理境界</NavLink></div></footer>
  </div>;
}
