export function requireFacilitatorUrl(value: string | undefined): string {
  if (!value) throw new Error("VITE_FACILITATOR_URL is required");
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) throw new Error();
  } catch {
    throw new Error("VITE_FACILITATOR_URL must be an HTTPS URL without credentials");
  }
  return value;
}

export function requireEvmAddress(name: string, value: string | undefined): string {
  if (!value) throw new Error(`${name} is required`);
  if (!/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/i.test(value)) {
    throw new Error(`${name} must be a non-zero EVM address`);
  }
  return value;
}
