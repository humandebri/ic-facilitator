// vitest.config.ts: batch readiness tests use crypto-heavy fixtures, so the default 5s limit is too tight under parallel load.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    testTimeout: 15_000
  }
});
