import { readFileSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { gzipSync } from "node:zlib";

const root = resolve(process.cwd(), "web/dist");
const manifest = JSON.parse(readFileSync(resolve(root, ".vite/manifest.json"), "utf8"));
const entries = Object.entries(manifest);
const htmlEntry = manifest["index.html"];
const creditEntry = manifest["src/pages/Credit.tsx"];
if (!htmlEntry?.isEntry || !creditEntry?.isDynamicEntry) {
  throw new Error("web manifest must contain the HTML entry and lazy Credit route");
}

const jsFiles = new Set(entries.map(([, value]) => value.file).filter((file) => file.endsWith(".js")));
for (const file of jsFiles) {
  const bytes = statSync(resolve(root, file)).size;
  if (bytes >= 500_000) throw new Error(`${file} is ${bytes} bytes; every JS chunk must be below 500000 bytes`);
}

const byFile = new Map(entries.map(([, value]) => [value.file, value]));
const initialFiles = new Set();
function visitInitial(file) {
  if (initialFiles.has(file)) return;
  initialFiles.add(file);
  for (const imported of byFile.get(file)?.imports ?? []) {
    const importedFile = manifest[imported]?.file ?? imported;
    visitInitial(importedFile);
  }
}
visitInitial(htmlEntry.file);
if (initialFiles.has(creditEntry.file)) throw new Error("Credit/x402 route must not be part of the initial bundle");

const initialGzipBytes = [...initialFiles]
  .filter((file) => file.endsWith(".js"))
  .reduce((total, file) => total + gzipSync(readFileSync(resolve(root, file))).byteLength, 0);
if (initialGzipBytes >= 150_000) {
  throw new Error(`initial JS is ${initialGzipBytes} gzip bytes; expected below 150000`);
}

console.log(JSON.stringify({ initialGzipBytes, jsChunks: jsFiles.size, largestChunkBytes: Math.max(...[...jsFiles].map((file) => statSync(resolve(root, file)).size)) }));
