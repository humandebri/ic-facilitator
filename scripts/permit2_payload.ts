// scripts/permit2_payload.ts: buyer が生成した exact Permit2 payment payload の重要フィールドを検証する。
import type { PaymentPayload } from "@x402/core/types";
import { x402ExactPermit2ProxyAddress } from "@x402/evm";

export type ExpectedPermit2Payload = {
  readonly amount: string;
  readonly asset: string;
  readonly buyer: string;
  readonly maxTimeoutSeconds: number;
  readonly payTo: string;
  readonly resourceUrl: string;
};

function property(value: unknown, name: string): unknown {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  return Object.getOwnPropertyDescriptor(value, name)?.value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new Error(`missing payment payload field: ${label}`);
  }
  return value;
}

function equalsAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function requireAddress(value: unknown, label: string): string {
  const address = requireString(value, label);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`invalid payment payload address: ${label}`);
  }
  return address;
}

function requireDigits(value: unknown, label: string): string {
  const digits = requireString(value, label);
  if (!/^[0-9]+$/.test(digits)) {
    throw new Error(`invalid payment payload integer: ${label}`);
  }
  return digits;
}

export function validateExactPermit2PaymentPayload(payload: PaymentPayload, expected: ExpectedPermit2Payload): void {
  const permit2Authorization = property(payload.payload, "permit2Authorization");
  const permitted = property(permit2Authorization, "permitted");
  const witness = property(permit2Authorization, "witness");
  const signature = requireString(property(payload.payload, "signature"), "signature");

  if (payload.x402Version !== 2) {
    throw new Error("unexpected payment payload x402 version");
  }
  if (payload.resource?.url !== expected.resourceUrl) {
    throw new Error("unexpected payment payload resource");
  }
  if (payload.accepted.scheme !== "exact" || payload.accepted.network !== "eip155:137") {
    throw new Error("unexpected payment payload accepted kind");
  }
  if (!equalsAddress(payload.accepted.asset, expected.asset) || !equalsAddress(payload.accepted.payTo, expected.payTo)) {
    throw new Error("unexpected payment payload accepted receiver");
  }
  if (payload.accepted.amount !== expected.amount) {
    throw new Error("unexpected payment payload accepted amount");
  }
  if (payload.accepted.maxTimeoutSeconds !== expected.maxTimeoutSeconds) {
    throw new Error("unexpected payment payload accepted timeout");
  }
  if (payload.accepted.extra?.assetTransferMethod !== "permit2") {
    throw new Error("unexpected payment payload accepted transfer method");
  }
  if (!/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new Error("invalid payment payload signature");
  }
  if (!equalsAddress(requireAddress(property(permit2Authorization, "from"), "from"), expected.buyer)) {
    throw new Error("unexpected payment payload buyer");
  }
  if (!equalsAddress(requireAddress(property(permitted, "token"), "permitted.token"), expected.asset)) {
    throw new Error("unexpected payment payload token");
  }
  if (requireDigits(property(permitted, "amount"), "permitted.amount") !== expected.amount) {
    throw new Error("unexpected payment payload amount");
  }
  if (!equalsAddress(requireAddress(property(permit2Authorization, "spender"), "spender"), x402ExactPermit2ProxyAddress)) {
    throw new Error("unexpected payment payload spender");
  }
  if (!equalsAddress(requireAddress(property(witness, "to"), "witness.to"), expected.payTo)) {
    throw new Error("unexpected payment payload receiver");
  }
  requireDigits(property(permit2Authorization, "nonce"), "nonce");
  requireDigits(property(permit2Authorization, "deadline"), "deadline");
}
