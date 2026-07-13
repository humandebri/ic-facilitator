import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";

const source = readFileSync("rust/facilitator/src/lib.rs", "utf8");
const migrationSql = /const BATCH_SQLITE_MIGRATIONS_V3:[\s\S]*?sql: "([\s\S]*?)",\n\}\];/.exec(source)?.[1];
if (!migrationSql) throw new Error("BATCH_SQLITE_MIGRATIONS_V3 SQL was not found");

function legacyDatabase() {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE payment_intents(intent_id TEXT); CREATE TABLE batch_channel_bindings(channel_id TEXT);");
  return db;
}

describe("payment-intent removal migration", () => {
  it("drops empty legacy tables", () => {
    const db = legacyDatabase();
    db.exec(migrationSql);
    const remaining = db.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE name IN ('payment_intents', 'batch_channel_bindings')").get() as { count: number };
    expect(remaining.count).toBe(0);
    db.close();
  });

  it("keeps non-empty legacy tables and can retry after rows are cleared", () => {
    const db = legacyDatabase();
    db.exec("INSERT INTO payment_intents VALUES ('intent-1')");
    expect(() => db.exec(migrationSql)).toThrow();
    expect(db.prepare("SELECT COUNT(*) AS count FROM payment_intents").get()).toEqual({ count: 1 });
    db.exec("DELETE FROM payment_intents");
    expect(() => db.exec(migrationSql)).not.toThrow();
    db.close();
  });
});
