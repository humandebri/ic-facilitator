// scripts/check_hidden_unicode.mjs: fail CI when tracked source contains hidden Unicode controls.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const hiddenUnicode = /[\u061c\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu;
const decoder = new TextDecoder("utf-8", { fatal: true });
const files = execFileSync("git", ["ls-files", "-z"]).toString("utf8").split("\0").filter(Boolean);
const failures = [];

for (const file of files) {
  let text;
  try {
    text = decoder.decode(readFileSync(file));
  } catch {
    continue;
  }

  hiddenUnicode.lastIndex = 0;
  for (const match of text.matchAll(hiddenUnicode)) {
    const index = match.index ?? 0;
    const line = text.slice(0, index).split("\n").length;
    const codePoint = match[0]?.codePointAt(0);
    if (codePoint === undefined) {
      continue;
    }
    failures.push(`${file}:${line}: hidden unicode U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`);
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
