// test/cleanBuildArtifacts.test.ts: build artifact cleanup script の dry-run が削除対象を限定表示することを確認する。
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

describe("clean build artifacts script", () => {
  it("requires explicit confirmation and lists generated targets only", () => {
    const result = spawnSync("bash", ["scripts/clean_build_artifacts.sh"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("target");
    expect(result.stdout).toContain("dist");
    expect(result.stdout).toContain("--yes");
    expect(result.stdout).not.toContain(".icp/cache/networks/local");
  });
});
