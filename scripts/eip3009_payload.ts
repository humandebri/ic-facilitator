// scripts/eip3009_payload.ts: buyer が生成した exact EIP-3009 payment payload の重要フィールドを検証する。
import type { PaymentPayload } from "@x402/core/types";

export const JPYC_EIP712_NAME = "JPY Coin";

export type ExpectedEip3009Payload = {
  readonly amount: string;
  readonly asset: string;
  readonly buyer: string;
  readonly eip712Version: string;
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

function requireBytes32(value: unknown, label: string): string {
  const bytes = requireString(value, label);
  if (!/^0x[0-9a-fA-F]{64}$/.test(bytes)) {
    throw new Error(`invalid payment payload bytes32: ${label}`);
  }
  return bytes;
}

export function validateExactEip3009PaymentPayload(payload: PaymentPayload, expected: ExpectedEip3009Payload): void {
  const authorization = property(payload.payload, "authorization");
  const signature = requireString(property(payload.payload, "signature"), "signature");

  if (property(payload.payload, "permit2Authorization") !== undefined) {
    throw new Error("unexpected Permit2 payment payload");
  }
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
  if (payload.accepted.extra?.assetTransferMethod !== "eip3009") {
    throw new Error("unexpected payment payload accepted transfer method");
  }
  if (payload.accepted.extra?.name !== JPYC_EIP712_NAME || payload.accepted.extra?.version !== expected.eip712Version) {
    throw new Error("unexpected payment payload EIP-712 domain");
  }
  if (!/^0x[0-9a-fA-F]+$/.test(signature)) {
    throw new Error("invalid payment payload signature");
  }
  if (!equalsAddress(requireAddress(property(authorization, "from"), "authorization.from"), expected.buyer)) {
    throw new Error("unexpected payment payload buyer");
  }
  if (!equalsAddress(requireAddress(property(authorization, "to"), "authorization.to"), expected.payTo)) {
    throw new Error("unexpected payment payload receiver");
  }
  if (requireDigits(property(authorization, "value"), "authorization.value") !== expected.amount) {
    throw new Error("unexpected payment payload amount");
  }
  requireDigits(property(authorization, "validAfter"), "authorization.validAfter");
  requireDigits(property(authorization, "validBefore"), "authorization.validBefore");
  requireBytes32(property(authorization, "nonce"), "authorization.nonce");
}
