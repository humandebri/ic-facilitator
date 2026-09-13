import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { loadDotenv } from "./env_file";

type FeeHistory = {
  oldestBlock: string;
  baseFeePerGas: string[];
  reward: string[][];
  gasUsedRatio: number[];
};

export function effectiveGasSamples(history: FeeHistory): number[] {
  const count = history.gasUsedRatio.length;
  if (history.baseFeePerGas.length !== count + 1 || history.reward.length !== count) {
    throw new Error("incomplete fee history");
  }
  return history.gasUsedRatio.flatMap((ratio, index) => {
    if (ratio === 0) return [];
    const base = history.baseFeePerGas[index];
    const priority = history.reward[index]?.[0];
    if (!base || !priority || !/^0x[0-9a-f]+$/i.test(base) || !/^0x[0-9a-f]+$/i.test(priority)) {
      throw new Error("invalid fee history quantities");
    }
    return [Number(BigInt(base) + BigInt(priority)) / 1e9];
  });
}

export function gasStatistics(values: readonly number[]) {
  if (!values.length || values.some((value) => !Number.isFinite(value) || value < 0)) {
    throw new Error("valid gas samples are required");
  }
  const sorted = [...values].sort((a, b) => a - b);
  const percentile = (p: number) => sorted[Math.ceil(sorted.length * p) - 1]!;
  return {
    blocks: sorted.length,
    meanGwei: sorted.reduce((sum, value) => sum + value, 0) / sorted.length,
    medianGwei: percentile(0.5),
    p90Gwei: percentile(0.9),
    minGwei: sorted[0]!,
    maxGwei: sorted.at(-1)!,
  };
}

async function main() {
  loadDotenv();
  const endpoint = process.env.POLYGON_RPC_URL ?? "https://polygon.drpc.org";
  let id = 0;
  async function rpc<T>(method: string, params: unknown[]): Promise<T> {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`${method}: HTTP ${response.status}`);
    const body = await response.json() as { result?: T; error?: { code: number } };
    if (body.error || body.result === undefined) throw new Error(`${method}: RPC error ${body.error?.code}`);
    return body.result;
  }
  if (await rpc<string>("eth_chainId", []) !== "0x89") throw new Error("Polygon mainnet required");
  const latest = await rpc<{ number: string; timestamp: string }>("eth_getBlockByNumber", ["latest", false]);
  const end = Number(BigInt(latest.number));
  const previous = await rpc<{ timestamp: string }>("eth_getBlockByNumber", [`0x${(end - 2400).toString(16)}`, false]);
  const secondsPerBlock = (Number(BigInt(latest.timestamp)) - Number(BigInt(previous.timestamp))) / 2400;
  if (!(secondsPerBlock > 0)) throw new Error("invalid block timestamps");
  const stride = Math.round(3600 / secondsPerBlock);
  const windows = [];
  const samples: number[] = [];
  for (let hour = 0; hour < 168; hour++) {
    const block = end - hour * stride;
    const history = await rpc<FeeHistory>("eth_feeHistory", ["0x40", `0x${block.toString(16)}`, [50]]);
    if (Number(BigInt(history.oldestBlock)) !== block - 63 || history.gasUsedRatio.length !== 64) {
      throw new Error("RPC returned a different historical window");
    }
    const values = effectiveGasSamples(history);
    samples.push(...values);
    windows.push({ oldestBlock: history.oldestBlock, newestBlock: block, ...gasStatistics(values) });
    if ((hour + 1) % 24 === 0) console.error(`Collected ${hour + 1}/168 windows`);
  }
  const first = await rpc<{ timestamp: string }>("eth_getBlockByNumber", [windows.at(-1)!.oldestBlock, false]);
  const report = {
    collectedAt: new Date().toISOString(),
    chainId: 137,
    method: "eth_feeHistory: base fee + gas-weighted median priority fee per non-empty block; equal-weight block mean across 168 approximately hourly windows of 64 blocks",
    startTime: new Date(Number(BigInt(first.timestamp)) * 1000).toISOString(),
    endTime: new Date(Number(BigInt(latest.timestamp)) * 1000).toISOString(),
    secondsPerBlock,
    ...gasStatistics(samples),
    windows,
  };
  writeFileSync("docs/polygon-gas-baseline.json", `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify({ ...report, windows: report.windows.length }, null, 2));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch(() => {
    // Provider errors can contain API keys embedded in URLs.
    console.error("Polygon gas sampling failed; no complete baseline was written.");
    process.exitCode = 1;
  });
}
