// scripts/env_file.ts: Node CLI 用に .env を依存なしで読み込み、既存 env を優先する。
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export type DotenvLoadResult = {
  readonly loaded: readonly string[];
  readonly path: string;
};

function unquote(value: string): string {
  if (value.length >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
    return value.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, "\"").replace(/\\\\/g, "\\");
  }
  if (value.length >= 2 && value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1);
  }
  return value;
}

export function parseDotenv(text: string): Record<string, string> {
  const entries: Record<string, string> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith("#")) { continue; }
    const normalized = line.startsWith("export ") ? line.slice("export ".length).trimStart() : line;
    const index = normalized.indexOf("=");
    if (index <= 0) { continue; }
    const name = normalized.slice(0, index).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) { continue; }
    entries[name] = unquote(normalized.slice(index + 1).trim());
  }
  return entries;
}

export function loadDotenv(env: NodeJS.ProcessEnv = process.env, path = resolve(process.cwd(), ".env")): DotenvLoadResult {
  if (!existsSync(path)) { return { loaded: [], path }; }
  const parsed = parseDotenv(readFileSync(path, "utf8"));
  const loaded: string[] = [];
  for (const [name, value] of Object.entries(parsed)) {
    if (!env[name] || env[name]?.trim() === "") {
      env[name] = value;
      loaded.push(name);
    }
  }
  return { loaded, path };
}
