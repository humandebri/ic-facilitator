// test/requireCanisterDisk.test.ts: canister build/upload 前の disk guard を fake df で検証する。
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

function fakeDfDir(availableKiB: number): string {
  const dir = mkdtempSync(join(tmpdir(), "ic-facilitator-df-"));
  const fakeDf = join(dir, "df");
  writeFileSync(
    fakeDf,
    [
      "#!/usr/bin/env bash",
      "printf '%s\\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on'",
      `printf '%s\\n' '/dev/test 4096000 1 ${availableKiB} 1% /'`
    ].join("\n")
  );
  chmodSync(fakeDf, 0o755);
  return dir;
}

describe("require_canister_disk", () => {
  it("passes when enough disk is available", () => {
    const dir = fakeDfDir(2_097_152);
    try {
      const result = spawnSync("bash", ["scripts/require_canister_disk.sh", "."], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` }
      });
      expect(result.status).toBe(0);
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });

  it("fails before canister build when disk is low", () => {
    const dir = fakeDfDir(1_048_576);
    try {
      const result = spawnSync("bash", ["scripts/require_canister_disk.sh", "."], {
        cwd: process.cwd(),
        encoding: "utf8",
        env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` }
      });
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("disk-space check failed");
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });
});
