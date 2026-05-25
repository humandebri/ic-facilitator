// test/envFile.test.ts: .env parser が既存 env を上書きせず補完することを確認する。
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { loadDotenv, parseDotenv } from "../scripts/env_file";

describe("env file loader", () => {
  it("parses dotenv and export lines", () => {
    expect(parseDotenv("A=1\nexport B=two\n# comment\nC=\"three\\nline\"\n")).toEqual({
      A: "1",
      B: "two",
      C: "three\nline"
    });
  });

  it("loads missing env values without overriding existing ones", () => {
    const dir = mkdtempSync(join(tmpdir(), "ic-facilitator-env-"));
    const path = join(dir, ".env");
    const env: NodeJS.ProcessEnv = { FACILITATOR_EVM_PRIVATE_KEY: "shell-value" };
    writeFileSync(path, "FACILITATOR_EVM_PRIVATE_KEY=file-value\nPOLYGON_RPC_SERVICES=https://polygon.example\n", "utf8");

    const result = loadDotenv(env, path);

    expect(result.loaded).toEqual(["POLYGON_RPC_SERVICES"]);
    expect(env.FACILITATOR_EVM_PRIVATE_KEY).toBe("shell-value");
    expect(env.POLYGON_RPC_SERVICES).toBe("https://polygon.example");
  });
});
