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
