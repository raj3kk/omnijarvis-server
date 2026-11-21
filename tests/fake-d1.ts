/**
 * Fake D1 for vitest — minimal SQL engine for exactly the queries
 * src/ + licence-worker/ use (single-condition WHEREs, INSERT ... ON
 * CONFLICT upserts, UPDATE ... WHERE, DELETE ... WHERE, COUNT(*),
 * LIKE substring, IS NULL / IS NOT NULL, string literals, ORDER BY
 * ASC/DESC + LIMIT).
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
  licences: ["key"],
  learned_patterns: ["template_hash"],
  tenants: ["id"],
  scheduled_jobs: ["id"],
  global_skills: ["id"],
  llm_usage: ["id"],
  doc_jobs: ["id"],
  certificates: ["id"],
  browser_tasks: ["id"],
  skill_reviews: ["id"],
  skill_signatures: ["skill_id"],
  memories: ["id"],
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
    return { success: true, meta: { changes: this.execSync().length } };
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
    const [, table, colsStr, valsStr] = m;
    const cols = colsStr.split(",").map((c) => c.trim());
    const vals = valsStr.split(",").map((v) => v.trim());
    const row: Row = {};
    let argIdx = 0;
    cols.forEach((c, i) => {
      const v = vals[i];
      if (v === "?") row[c] = this.args[argIdx++];
      else if (v === "NULL") row[c] = null;
      else if (/^'.*'$/.test(v)) row[c] = v.slice(1, -1);
      else row[c] = Number(v);
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
    if (table === "llm_usage" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    if (table === "doc_jobs" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    if (table === "certificates" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    if (table === "skill_reviews" && row.id === undefined) {
      const next = (this.db["autoInc"].get(table) ?? 0) + 1;
      this.db["autoInc"].set(table, next);
      row.id = next;
    }
    if (table === "memories" && row.id === undefined) {
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
    return [row];
  }

  private select(): Row[] {
    // COUNT(*) variant
    const countM = this.q.match(/^SELECT COUNT\(\*\) AS (\w+) FROM (\w+)(?: WHERE (.+))?$/);
    if (countM) {
      const [, alias, table, where] = countM;
      const rows = this.filterRows(table, where, [...this.args]);
      return [{ [alias]: rows.length }];
    }
    const m = this.q.match(/^SELECT (.+) FROM (\w+)(?: WHERE (.+?))?(?: ORDER BY (\w+)(?: (ASC|DESC))?)?(?: LIMIT (\d+))?$/);
    if (!m) throw new Error(`FakeD1: cannot parse SELECT: ${this.q}`);
    const [, colsStr, table, where, orderBy, orderDir, limit] = m;
    let rows = this.filterRows(table, where, [...this.args]);
    if (orderBy) {
      const dir = orderDir === "DESC" ? -1 : 1;
      rows = [...rows].sort((a, b) => dir * (Number(a[orderBy] ?? 0) - Number(b[orderBy] ?? 0)));
    }
    if (limit) rows = rows.slice(0, Number(limit));
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

  private filterRows(table: string, where: string | undefined, args: unknown[]): Row[] {
    const t = this.db["table"](table);
    let rows = [...t.values()];
    if (!where) return rows;
    const conds = where.split(" AND ").map((c) => c.trim());
    // Fresh arg cursor per row: a shared cursor would drain on row 1.
    return rows.filter((r) => {
      let argIdx = 0;
      for (const cond of conds) {
        const likeM = cond.match(/^(\w+) LIKE \?$/);
        if (likeM) {
          const col = likeM[1];
          const pattern = String(args[argIdx++] ?? "").replace(/^%|%$/g, "");
          if (!String(r[col] ?? "").includes(pattern)) return false;
          continue;
        }
        const nullM = cond.match(/^(\w+) IS (NOT )?NULL$/);
        if (nullM) {
          const isNull = r[nullM[1]] === null || r[nullM[1]] === undefined;
          if (nullM[2] ? isNull : !isNull) return false;
          continue;
        }
        const litM = cond.match(/^(\w+) = '([^']*)'$/);
        if (litM) {
          if (r[litM[1]] !== litM[2]) return false;
          continue;
        }
        // Number literal: `approved = 1` (licence Worker patternsGet).
        const numM = cond.match(/^(\w+) = (\d+)$/);
        if (numM) {
          if (r[numM[1]] !== Number(numM[2])) return false;
          continue;
        }
        const eqM = cond.match(/^(\w+) (?:=|<=|>=|<|>) \?$/);
        if (!eqM) throw new Error(`FakeD1: cannot parse WHERE: ${cond}`);
        const col = eqM[1];
        const op = cond.match(/(=|<=|>=|<|>)/)?.[1] ?? "=";
        const val = args[argIdx++];
        const rv = r[col];
        if (op === "=" && rv !== val) return false;
        if (op === "<=" && !(Number(rv) <= Number(val))) return false;
        if (op === ">=" && !(Number(rv) >= Number(val))) return false;
        if (op === "<" && !(Number(rv) < Number(val))) return false;
        if (op === ">" && !(Number(rv) > Number(val))) return false;
      }
      return true;
    });
  }

  private update(): Row[] {
    const m = this.q.match(/^UPDATE (\w+) SET (.+) WHERE (.+)$/);
    if (!m) throw new Error(`FakeD1: cannot parse UPDATE: ${this.q}`);
    const [, table, setStr, where] = m;
    const sets = setStr.split(",").map((s) => s.trim());
    // SET args come first, WHERE args after. A SET value may be a `?`
    // placeholder (consumes one arg) or a NULL literal (consumes none).
    const args = [...this.args];
    let argIdx = 0;
    const setVals: unknown[] = sets.map((s) => {
      const sm = s.match(/^([\w.]+)\s*=\s*(.+)$/);
      if (!sm) throw new Error(`FakeD1: cannot parse SET: ${s}`);
      if (sm[2].trim() === "?") return args[argIdx++];
      if (sm[2].trim() === "NULL") return null;
      throw new Error(`FakeD1: cannot parse SET value: ${s}`);
    });
    const whereArgs = args.slice(argIdx);
    const rows = this.filterRows(table, where, whereArgs);
    sets.forEach((s, i) => {
      const col = s.split("=")[0].trim();
      for (const r of rows) r[col] = setVals[i];
    });
    return rows;
  }

  private delete(): Row[] {
    const m = this.q.match(/^DELETE FROM (\w+)(?: WHERE (.+))?$/);
    if (!m) throw new Error(`FakeD1: cannot parse DELETE: ${this.q}`);
    const [, table, where] = m;
    const t = this.db["table"](table);
    if (!where) {
      const n = t.size;
      t.clear();
      return Array.from({ length: n }, () => ({}));
    }
    const hit = this.filterRows(table, where, [...this.args]);
    for (const r of hit) {
      t.delete(this.db["pkOf"](table, r));
    }
    return hit;
  }
}
