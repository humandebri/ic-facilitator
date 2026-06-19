// scripts/generate_did.ts: local wasm から facilitator DID を安全に再生成する。
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const DEFAULT_WASM_PATH = "target/wasm32-unknown-unknown/release/jpyc_x402_facilitator.wasm";
const DEFAULT_DID_PATH = "dist/facilitator.did";

export type CandidExtractorResult = {
  readonly error?: string;
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

export type GenerateDidOptions = {
  readonly didPath: string;
  readonly runCandidExtractor?: (wasmPath: string) => CandidExtractorResult;
  readonly wasmPath: string;
};

export function normalizeDidServiceConstructor(did: string): string {
  return did.replace(/\bservice\s*:\s*\(\s*\)\s*->\s*\{/, "service : {");
}

function runCandidExtractor(wasmPath: string): CandidExtractorResult {
  const result = spawnSync("candid-extractor", [wasmPath], { encoding: "utf8" });
  const error = result.error instanceof Error
    ? result.error.message
    : result.error === undefined
      ? undefined
      : String(result.error);
  const output: CandidExtractorResult = {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? ""
  };
  if (error !== undefined) {
    return { ...output, error };
  }
  return output;
}

export function generateDid(options: GenerateDidOptions): void {
  const result = (options.runCandidExtractor ?? runCandidExtractor)(options.wasmPath);
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  if (result.status !== 0) {
    throw new Error(
      stderr.trim() ||
      result.error ||
      `candid-extractor failed with status ${result.status ?? "unknown"}`
    );
  }
  const normalized = normalizeDidServiceConstructor(stdout);
  if (!normalized.includes("service :")) {
    throw new Error("candid-extractor output did not include a service definition");
  }

  mkdirSync(dirname(options.didPath), { recursive: true });
  const tmpPath = `${options.didPath}.tmp-${process.pid}`;
  try {
    writeFileSync(tmpPath, normalized);
    renameSync(tmpPath, options.didPath);
  } catch (error: unknown) {
    rmSync(tmpPath, { force: true });
    throw error;
  }
}

function isDirectRun(): boolean {
  const entry = process.argv[1];
  return typeof entry === "string" && import.meta.url === pathToFileURL(entry).href;
}

if (isDirectRun()) {
  try {
    generateDid({
      didPath: process.argv[3] ?? DEFAULT_DID_PATH,
      wasmPath: process.argv[2] ?? DEFAULT_WASM_PATH
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  }
}
