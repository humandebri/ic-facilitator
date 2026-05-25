// src/amount.ts: JPYC 表示単位を ERC-20 atomic unit へ決定的に変換する。
export function decimalToAtomicUnits(value: string, decimals: number): string {
  const normalized = value.trim();
  if (!/^\d+(\.\d+)?$/.test(normalized)) {
    throw new Error("amount must be a non-negative decimal string");
  }

  const parts = normalized.split(".");
  const whole = parts[0] ?? "0";
  const fraction = parts[1] ?? "";
  if (fraction.length > decimals) {
    throw new Error(`amount has more than ${decimals} decimal places`);
  }

  const scale = 10n ** BigInt(decimals);
  const wholeUnits = BigInt(whole) * scale;
  const paddedFraction = fraction.padEnd(decimals, "0");
  const fractionUnits = paddedFraction === "" ? 0n : BigInt(paddedFraction);
  return (wholeUnits + fractionUnits).toString();
}

export function isPositiveDecimalString(value: string): boolean {
  const normalized = value.trim();
  return /^\d+(\.\d+)?$/.test(normalized) && /[1-9]/.test(normalized);
}

export function positiveDecimalToAtomicUnits(value: string, decimals: number, name: string): string {
  if (!isPositiveDecimalString(value)) {
    throw new Error(`${name} must be a positive decimal string`);
  }
  try {
    return decimalToAtomicUnits(value, decimals);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${name} ${message}`);
  }
}
