// scripts/smoke_canister.ts: facilitator canister が x402 v2 exact Polygon Permit2 support を返すことを確認する。
import { pathToFileURL } from "node:url";

import { loadDotenv } from "./env_file";

const DEFAULT_BASE_URL = "http://edge.local.localhost:8000";
const EXPECTED_NETWORK = "eip155:137";
const EXPECTED_METHOD = "permit2";

export type CanisterSmokeOptions = {
  readonly allowMissingSeller?: boolean;
  readonly env?: NodeJS.ProcessEnv;
  readonly fetchFn?: typeof fetch;
};

export type CanisterSmokeResult = {
  readonly baseUrl: string;
  readonly facilitatorAddress: string;
  readonly healthStatus: number;
  readonly supportedStatus: number;
  readonly support: unknown;
  readonly unpaidStatus?: number;
};

function readEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name];
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

async function json(response: Response, expectedStatus: number): Promise<unknown> {
  const text = await response.text();
  if (response.status !== expectedStatus) {
    throw new Error(`expected ${expectedStatus}, got ${response.status}: ${text}`);
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`response is not JSON: ${text}`);
  }
}

export async function checkCanisterSmoke(options: CanisterSmokeOptions = {}): Promise<CanisterSmokeResult> {
  const env = options.env ?? process.env;
  const fetchFn = options.fetchFn ?? fetch;
  const baseUrl = (readEnv(env, "X402_BASE_URL") ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const healthResponse = await fetchFn(`${baseUrl}/health`);
  const health = requireRecord(await json(healthResponse, 200), "health");
  const facilitatorAddress = requireString(health.facilitatorAddress, "health.facilitatorAddress");
  if (!/^0x[0-9a-fA-F]{40}$/.test(facilitatorAddress)) {
    throw new Error("health.facilitatorAddress must be an EVM address");
  }

  const supportedResponse = await fetchFn(`${baseUrl}/supported`);
  const supported = requireRecord(await json(supportedResponse, 200), "supported");
  const kinds = Array.isArray(supported.kinds) ? supported.kinds : [];
  const exact = kinds.find((item) => {
    const kind = requireRecord(item, "supported.kind");
    const extra = requireRecord(kind.extra, "supported.kind.extra");
    return kind.x402Version === 2 &&
      kind.scheme === "exact" &&
      kind.network === EXPECTED_NETWORK &&
      extra.assetTransferMethod === EXPECTED_METHOD;
  });
  if (!exact) {
    throw new Error("supported lacks x402 v2 exact/eip155:137 permit2");
  }

  return {
    baseUrl,
    facilitatorAddress,
    healthStatus: healthResponse.status,
    supportedStatus: supportedResponse.status,
    support: supported
  };
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  loadDotenv();
  checkCanisterSmoke()
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error: unknown) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exitCode = 1;
    });
}
