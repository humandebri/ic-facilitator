// scripts/smoke_canister_paid_negative.ts: 不正 payment header で canister endpoint が開かないことを確認する。
import { pathToFileURL } from "node:url";

import { decodePaymentRequiredHeader } from "@x402/core/http";
import { loadDotenv } from "./env_file";

const DEFAULT_BASE_URL = "http://edge.local.localhost:8000";

export type PaidNegativeSmokeResult = {
  readonly baseUrl: string;
  readonly body: unknown;
  readonly fakePaidStatus: number;
  readonly initialStatus: number;
};

function readEnv(env: NodeJS.ProcessEnv, name: string): string | undefined {
  return env[name];
}

function requireHeader(response: Response, name: string): string {
  const value = response.headers.get(name);
  if (!value) {
    throw new Error(`missing response header: ${name}`);
  }
  return value;
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text === "") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed;
  } catch {
    return text;
  }
}

export async function checkPaidNegativeSmoke(
  env: NodeJS.ProcessEnv = process.env,
  fetchFn: typeof fetch = fetch
): Promise<PaidNegativeSmokeResult> {
  const baseUrl = (readEnv(env, "X402_BASE_URL") ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const targetUrl = `${baseUrl}/jpyc/report`;
  const unpaid = await fetchFn(targetUrl, {
    headers: { Accept: "application/json" }
  });

  if (unpaid.status !== 402) {
    throw new Error(`expected initial 402, got ${unpaid.status}`);
  }

  const paymentRequired = decodePaymentRequiredHeader(requireHeader(unpaid, "payment-required"));
  const accepted = paymentRequired.accepts[0];
  if (!accepted) {
    throw new Error("payment-required accepts is empty");
  }

  const paidAttempt = await fetchFn(targetUrl, {
    headers: {
      Accept: "application/json",
      "PAYMENT-SIGNATURE": "not-a-valid-x402-payment"
    }
  });
  const body = await readBody(paidAttempt);

  if (paidAttempt.status !== 402) {
    throw new Error(`expected malformed payment to return 402, got ${paidAttempt.status}: ${JSON.stringify(body)}`);
  }
  if (paidAttempt.headers.get("payment-response")) {
    throw new Error("fake paid request returned payment-response");
  }

  return { baseUrl, initialStatus: unpaid.status, fakePaidStatus: paidAttempt.status, body };
}

async function main(): Promise<void> {
  console.log(JSON.stringify(await checkPaidNegativeSmoke(process.env), null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  loadDotenv();
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  });
}
