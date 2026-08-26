import { formatUnits } from "viem";

export function shortAddress(value: string): string { return value.length > 12 ? `${value.slice(0, 6)}…${value.slice(-4)}` : value; }
export function formatJpyc(value?: string | null): string { try { return `${formatUnits(BigInt(value ?? "0"), 18)} JPYC`; } catch { return "—"; } }
export function formatDate(seconds: number): string { return new Intl.DateTimeFormat("ja-JP", { dateStyle: "medium", timeStyle: "short" }).format(new Date(seconds * 1000)); }
