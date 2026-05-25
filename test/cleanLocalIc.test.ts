// test/cleanLocalIc.test.ts: local IC cleanup script の dry-run が削除対象を限定表示することを確認する。
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

describe("clean local IC script", () => {
  it("requires explicit confirmation and lists generated targets", () => {
    const result = spawnSync("bash", ["scripts/clean_local_ic.sh"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    expect(result.status).toBe(1);
    expect(result.stdout).toContain(".icp/cache/networks/local");
    expect(result.stdout).toContain("--yes");
  });
});
