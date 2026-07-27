import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";
import { requireEvmAddress, requireFacilitatorUrl } from "./buildEnv";

export default defineConfig(({ mode }) => {
  const root = fileURLToPath(new URL(".", import.meta.url));
  const env = loadEnv(mode, root, "VITE_");
  requireFacilitatorUrl(env.VITE_FACILITATOR_URL);
  requireEvmAddress("VITE_TOKEN_ADDRESS", env.VITE_TOKEN_ADDRESS);
  requireEvmAddress("VITE_BATCH_SETTLEMENT_CONTRACT", env.VITE_BATCH_SETTLEMENT_CONTRACT);
  if (env.VITE_APP_ENV === "production") {
    for (const name of ["VITE_SELLER_TERMS_VERSION", "VITE_PRIVACY_VERSION", "VITE_ASSET_BOUNDARY_VERSION"] as const) {
      if (!env[name] || env[name].endsWith("-draft")) throw new Error(`${name} must be an approved, non-draft version for production`);
    }
  }
  return {
    root,
    plugins: [react()],
    build: {
      outDir: "dist",
      emptyOutDir: true,
      manifest: true,
    },
    server: { port: 4173 },
  };
});
