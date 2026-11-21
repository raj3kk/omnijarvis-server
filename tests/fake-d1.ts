/**
 * Fake D1 for vitest — minimal SQL engine for exactly the queries
 * src/ uses (single-condition WHEREs, INSERT ... ON CONFLICT upserts,
 * UPDATE ... WHERE, DELETE ... WHERE, COUNT(*), LIKE substring).
 * NOT a general SQL engine — unknown shapes throw (fail loudly).
 */
import type { D1Like, D1PreparedLike } from "../src/db";

type Row = Record<string, unknown>;

const PK: Record<string, string[]> = {
  devices: ["device_id"],
  pairing_tokens: ["token"],
  sync_state: ["device_id", "table_name"],
  traces: ["id"],
  usage_counters: ["tenant_id", "period"],
  sessions: ["device_id"],
  nonces: ["nonce"],
  pending_steps: ["id"],
};

export class FakeD1 implements D1Like {
  tables = new Map<string, Map<string, Row>>();
  autoInc = new Map<string, number>();

  // Public for FakePrepared (test fake — no encapsulation needed).
  table(name: string): Map<string, Row> {
    if (!this.tables.has(name)) this.tables.set(name, new Map());
    return this.tables.get(name)!;
  }

  pkOf(table: string, row: Row): string {
    return PK[table].map((c) => String(row[c] ?? "")).join("|");
  }

  prepare(query: string): D1PreparedLike {
    const q = query.trim().replace(/\s+/g, " ");
    return new FakePrepared(this, q);
  }
}

class FakePrepared implements D1PreparedLike {
  private args: unknown[] = [];
  constructor(
    private db: FakeD1,
    private q: string,
  ) {}

  bind(...args: unknown[]): D1PreparedLike {
    this.args = args;
    return this;
  }

  async run(): Promise<{ success: boolean; meta?: unknown }> {
    this.execSync();
    return { success: true };
  }

  async all<T = Record<string, unknown>>(): Promise<{ results: T[] }> {
    return { results: this.execSync() as T[] };
  }

  async first<T = Record<string, unknown>>(): Promise<T | null> {
    const rows = this.execSync();
    return (rows[0] as T) ?? null;
  }

  /** Sync core (DO fake uses it — real DO sql.exec is synchronous). */
  execSync(): Row[] {
    const q = this.q;
    if (q.startsWith("INSERT INTO")) return this.insert();
    if (q.startsWith("SELECT")) return this.select();
    if (q.startsWith("UPDATE")) return this.update();
    if (q.startsWith("DELETE")) return this.delete();
    if (q.startsWith("CREATE TABLE") || q.startsWith("CREATE INDEX")) return [];
    throw new Error(`FakeD1: unsupported SQL: ${q}`);
  }

  private insert(): Row[] {
    const m = this.q.match(/^INSERT INTO (\w+) \(([^)]+)\) VALUES \(([^)]+)\)(?: ON CONFLICT.*)?$/);
    if (!m) throw new Error(`FakeD1: cannot parse INSERT: ${this.q}`);
    const [, table, colsStr] = m;
    const cols = colsStr.split(",").map((c) => c.trim());
    const row: Row = {};
    cols.forEach((c, i) => {
      row[c] = this.args[i];
    });
    const t = this.db["table"](table);
    if (table === "traces" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    if (table === "pending_steps" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    const pk = this.db["pkOf"](table, row);
    const existing = t.get(pk);
    if (existing && this.q.includes("ON CONFLICT")) {
      // Upsert: ON CONFLICT ... DO UPDATE SET col = excluded.col / expr.
      // Our upserts only set scalar excluded.* columns or increment
      // usage_counters (replies/e2b_runs += excluded). Handle both.
      const setPart = this.q.split("DO UPDATE SET")[1] ?? "";
      for (const assign of setPart.split(",")) {
        const am = assign.trim().match(/^([\w.]+)\s*=\s*(.+)$/);
        if (!am) continue;
        const col = am[1].split(".").pop()!;
        const expr = am[2].trim();
        if (expr === "excluded." + col) {
          existing[col] = row[col];
        } else if (expr.includes("+ excluded." + col)) {
          existing[col] = Number(existing[col] ?? 0) + Number(row[col] ?? 0);
        } else if (expr === "excluded.last_seq") {
          existing[col] = row[col];
        }
      }
      return [];
    }
    if (existing) throw new Error(`FakeD1: UNIQUE constraint failed: ${table}.${pk}`);
    t.set(pk, row);
    return [];
  }

  private select(): Row[] {
    // COUNT(*) variant
    const countM = this.q.match(/^SELECT COUNT\(\*\) AS (\w+) FROM (\w+)(?: WHERE (.+))?$/);
    if (countM) {
      const [, alias, table, where] = countM;
      const rows = this.filterRows(table, where);
      return [{ [alias]: rows.length }];
    }
    const m = this.q.match(/^SELECT (.+) FROM (\w+)(?: WHERE (.+?))?(?: ORDER BY (\w+)(?: ASC| DESC)?)?(?: LIMIT (\d+))?$/);
    if (!m) throw new Error(`FakeD1: cannot parse SELECT: ${this.q}`);
    const [, colsStr, table, where, orderBy] = m;
    let rows = this.filterRows(table, where);
    if (orderBy) {
      rows = [...rows].sort((a, b) => Number(a[orderBy] ?? 0) - Number(b[orderBy] ?? 0));
    }
    if (colsStr.trim() !== "*") {
      const cols = colsStr.split(",").map((c) => c.trim().split(" ").pop()!);
      rows = rows.map((r) => {
        const out: Row = {};
        for (const c of cols) out[c] = r[c];
        return out;
      });
    }
    return rows;
  }

  private filterRows(table: string, where: string | undefined): Row[] {
    const t = this.db["table"](table);
    let rows = [...t.values()];
    if (!where) return rows;
    const conds = where.split(" AND ").map((c) => c.trim());
    let argIdx = 0;
    for (const cond of conds) {
      const likeM = cond.match(/^(\w+) LIKE \?$/);
      if (likeM) {
        const col = likeM[1];
        const pattern = String(this.args[argIdx++]).replace(/^%|%$/g, "");
        rows = rows.filter((r) => String(r[col] ?? "").includes(pattern));
        continue;
      }
      const eqM = cond.match(/^(\w+) (?:=|<=|>=|<|>) \?$/);
      if (!eqM) throw new Error(`FakeD1: cannot parse WHERE: ${cond}`);
      const col = eqM[1];
      const op = cond.match(/(=|<=|>=|<|>)/)?.[1] ?? "=";
      const val = this.args[argIdx++];
      rows = rows.filter((r) => {
        const rv = r[col];
        if (op === "=") return rv === val;
        if (op === "<=") return Number(rv) <= Number(val);
        if (op === ">=") return Number(rv) >= Number(val);
        if (op === "<") return Number(rv) < Number(val);
        return Number(rv) > Number(val);
      });
    }
    return rows;
  }

  private update(): Row[] {
    const m = this.q.match(/^UPDATE (\w+) SET (.+) WHERE (.+)$/);
    if (!m) throw new Error(`FakeD1: cannot parse UPDATE: ${this.q}`);
    const [, table, setStr, where] = m;
    const sets = setStr.split(",").map((s) => s.trim());
    // SET args come first, WHERE args after.
    const setVals = this.args.slice(0, sets.length);
    const whereArgs = this.args.slice(sets.length);
    const rows = this.filterRowsWithArgs(table, where, whereArgs);
    sets.forEach((s, i) => {
      const col = s.split("=")[0].trim();
      for (const r of rows) r[col] = setVals[i];
    });
    return [];
  }

  private filterRowsWithArgs(table: string, where: string, args: unknown[]): Row[] {
    const saved = this.args;
    this.args = args;
    try {
      return this.filterRows(table, where);
    } finally {
      this.args = saved;
    }
  }

  private delete(): Row[] {
    const m = this.q.match(/^DELETE FROM (\w+)(?: WHERE (.+))?$/);
    if (!m) throw new Error(`FakeD1: cannot parse DELETE: ${this.q}`);
    const [, table, where] = m;
    const t = this.db["table"](table);
    if (!where) {
      t.clear();
      return [];
    }
    for (const r of this.filterRows(table, where)) {
      t.delete(this.db["pkOf"](table, r));
    }
    return [];
  }
}
