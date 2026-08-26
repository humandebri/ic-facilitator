import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { shortAddress } from "./format";

export function PageHeader({ eyebrow, title, lead }: { eyebrow: string; title: string; lead: string }) { return <header className="page-heading"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="lead">{lead}</p></header>; }
export function Notice({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "success" | "warning" }) { return <div className={`notice ${tone}`} role="status">{children}</div>; }
export function Address({ value }: { value: string }) { return <button className="address" title={value} onClick={() => void navigator.clipboard.writeText(value)}>{shortAddress(value)} <span>コピー</span></button>; }
export function SellerNav() { return <nav className="subnav" aria-label="Sellerメニュー"><NavLink end to="/seller">概要</NavLink><NavLink to="/seller/credit">Credit</NavLink><NavLink to="/seller/settlements">Settlement</NavLink></nav>; }
export function Stat({ label, value, note }: { label: string; value: string; note?: string }) { return <div className="stat"><span>{label}</span><strong>{value}</strong>{note && <small>{note}</small>}</div>; }
