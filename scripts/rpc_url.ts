// scripts/rpc_url.ts: Polygon RPC URL の検証契約を CLI 間で共有する。

const POLYGON_RPC_URL_ERROR = "must be a HTTPS RPC URL without userinfo or fragment";

export function isPolygonRpcUrl(value: string): boolean {
  if (!value.startsWith("https://") || /\s/.test(value)) {
    return false;
  }
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.hostname !== "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}

export function normalizePolygonRpcUrl(value: string, name = "POLYGON_RPC_URL"): string {
  if (!isPolygonRpcUrl(value)) {
    throw new Error(`${name} ${POLYGON_RPC_URL_ERROR}`);
  }
  return value;
}
