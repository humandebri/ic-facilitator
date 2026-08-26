// test/generateDid.test.ts: DID 生成の原子的更新と失敗時保護を確認する。
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import { describe, expect, it } from "vitest";

import { generateDid, type CandidExtractorResult } from "../scripts/generate_did";

function tempDidPath(): string {
  return join(mkdtempSync(join(tmpdir(), "ic-facilitator-did-")), "dist", "facilitator.did");
}

function ok(stdout: string): CandidExtractorResult {
  return { status: 0, stdout, stderr: "" };
}

describe("generateDid", () => {
  it("writes extracted service DID through the requested output path", () => {
    const didPath = tempDidPath();
    const generated = "service : {}\n";

    generateDid({
      didPath,
      runCandidExtractor(wasmPath: string) {
        expect(wasmPath).toBe("facilitator.wasm");
        return ok(generated);
      },
      wasmPath: "facilitator.wasm"
    });

    expect(readFileSync(didPath, "utf8")).toBe(generated);
  });

  it("normalizes a no-arg service constructor for committed DID compatibility", () => {
    const didPath = tempDidPath();

    generateDid({
      didPath,
      runCandidExtractor() {
        return ok("service : () -> { ping : () -> (); }\n");
      },
      wasmPath: "facilitator.wasm"
    });

    expect(readFileSync(didPath, "utf8")).toBe("service : { ping : () -> (); }\n");
  });

  it("does not overwrite an existing DID when candid-extractor fails", () => {
    const didPath = tempDidPath();
    const existing = "service : { old : () -> (); }\n";
    mkdirSync(dirname(didPath), { recursive: true });
    writeFileSync(didPath, existing, "utf8");

    expect(() => generateDid({
      didPath,
      runCandidExtractor() {
        return { status: 1, stdout: "", stderr: "extract failed\n" };
      },
      wasmPath: "facilitator.wasm"
    })).toThrow("extract failed");

    expect(readFileSync(didPath, "utf8")).toBe(existing);
  });

  it("surfaces candid-extractor spawn errors", () => {
    const didPath = tempDidPath();

    expect(() => generateDid({
      didPath,
      runCandidExtractor() {
        return { error: "spawn candid-extractor ENOENT", status: null, stdout: "", stderr: "" };
      },
      wasmPath: "facilitator.wasm"
    })).toThrow("spawn candid-extractor ENOENT");
  });

  it("rejects non-service output without leaving temporary files", () => {
    const didPath = tempDidPath();

    expect(() => generateDid({
      didPath,
      runCandidExtractor() {
        return ok("type OnlyTypes = record {}\n");
      },
      wasmPath: "facilitator.wasm"
    })).toThrow("service definition");

    const temporaryFiles = existsSync(dirname(didPath))
      ? readdirSync(dirname(didPath), { withFileTypes: true })
        .filter((entry) => entry.name.startsWith(`${basename(didPath)}.tmp-`))
      : [];
    expect(temporaryFiles).toEqual([]);
  });
});
