// test/doctorDisk.test.ts: doctor の disk-space 事前診断用 df parser を確認する。
import { describe, expect, it } from "vitest";

import { parseAvailableDiskKiB } from "../scripts/doctor";

describe("doctor disk space parser", () => {
  it("reads available KiB from POSIX df output", () => {
    const output = [
      "Filesystem 1024-blocks Used Available Capacity Mounted on",
      "/dev/disk3s5 239362496 210475328 419160 100% /System/Volumes/Data"
    ].join("\n");

    expect(parseAvailableDiskKiB(output)).toBe(419160);
  });

  it("returns null for unparseable df output", () => {
    expect(parseAvailableDiskKiB("Filesystem\n")).toBeNull();
  });
});
