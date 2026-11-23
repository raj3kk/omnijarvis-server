/**
 * Fake D1 for vitest — minimal SQL engine for exactly the queries
 * src/ + licence-worker/ use (single-condition WHEREs, INSERT ... ON
 * CONFLICT upserts, UPDATE ... WHERE, DELETE ... WHERE, COUNT(*),
 * LIKE substring, IS NULL / IS NOT NULL, string literals, IN (?, ...)
 * lists, ORDER BY ASC/DESC + LIMIT).
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
  // D3 locked (captcha-solver DESIGN §4.1, migration 0009).
  captcha_solves: ["id"],
  skill_reviews: ["id"],
  skill_signatures: ["skill_id"],
  memories: ["id"],
  // Track E #27 (0010 Google OAuth vault).
  google_tokens: ["tenant_id"],
  google_oauth_states: ["state"],
  // Phase 4 (0007 billing): TEXT ids, no autoInc branch needed.
  subscriptions: ["id"],
  payments: ["id"],
  refunds: ["id"],
  ledger_events: ["id"],
  e2b_runs: ["id"],
  admin_settings: ["key"],
  // Track C (0009 email + B2): TEXT ids.
  email_sends: ["id"],
  backups: ["id"],
  // 1.12.0 FCM (0012): device_id PK for tokens, TEXT id for sends.
  fcm_tokens: ["device_id"],
  fcm_sends: ["id"],
  // M-I-28 licence web (0013): email PK, (email, purpose) PK, token-hash PK.
  licence_web_users: ["email"],
  licence_email_codes: ["email", "purpose"],
  licence_web_sessions: ["token_hash"],
  // R1 Main Executor (0014 main_jobs, 0015 key_audit): TEXT ids.
  main_jobs: ["id"],
  key_audit: ["id"],
  // R2 shared memory (0016 jarvis_events, d1_migrations): TEXT id / name.
  jarvis_events: ["id"],
  d1_migrations: ["name"],
  // R4 (0017): Gmail-send idempotency + cap warnings.
  idempotency_keys: ["tenant_id", "key"],
  cap_warnings: ["id"],
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

  /**
   * Phase 4 (GAP-10 fix): D1 batch = one transaction. Snapshot every
   * table (deep copy of rows) + autoInc; run each statement in order;
   * on ANY throw, restore the snapshot (full rollback) and re-throw.
   * Live D1 batch has the same all-or-nothing semantics.
   */
  async batch(statements: D1PreparedLike[]): Promise<unknown[]> {
    const snapshot = new Map<string, Map<string, Row>>();
    for (const [name, table] of this.tables) {
      const copy = new Map<string, Row>();
      for (const [k, row] of table) copy.set(k, { ...row });
      snapshot.set(name, copy);
    }
    const autoIncSnapshot = new Map(this.autoInc);
    const out: unknown[] = [];
    try {
      for (const s of statements) {
        const prepared = s as unknown as FakePrepared;
        out.push({ success: true, meta: { changes: prepared.execSync().length } });
      }
    } catch (e) {
      // Full rollback: restore snapshotted tables AND drop tables the
      // batch created (they were not in the snapshot).
      for (const key of [...this.tables.keys()]) {
        if (!snapshot.has(key)) this.tables.delete(key);
      }
      for (const [name, table] of snapshot) this.tables.set(name, table);
      this.autoInc = autoIncSnapshot;
      throw e;
    }
    return out;
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
    // R2 shared memory (0016 jarvis_events): INTEGER PK AUTOINCREMENT.
    if (table === "jarvis_events" && row.id === undefined) {
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
    // SUM() aggregate variant (Phase 4 reconciliation):
    // SELECT SUM(<col>) AS <alias> FROM <table> [WHERE <conds>]
    const sumM = this.q.match(/^SELECT SUM\((\w+)\) AS (\w+) FROM (\w+)(?: WHERE (.+))?$/);
    if (sumM) {
      const [, col, alias, table, where] = sumM;
      const rows = this.filterRows(table, where, [...this.args]);
      let total = 0;
      for (const r of rows) total += Number(r[col] ?? 0);
      return [{ [alias]: total }];
    }
    // COUNT(*) variant
    const countM = this.q.match(/^SELECT COUNT\(\*\) AS (\w+) FROM (\w+)(?: WHERE (.+))?$/);
    if (countM) {
      const [, alias, table, where] = countM;
      const rows = this.filterRows(table, where, [...this.args]);
      return [{ [alias]: rows.length }];
    }
    // R2: LIMIT may be a bound parameter (LIMIT ?) — the bound value is
    // the arg after the WHERE placeholders.
    const m = this.q.match(/^SELECT (.+) FROM (\w+)(?: WHERE (.+?))?(?: ORDER BY (\w+)(?: (ASC|DESC))?)?(?: LIMIT (\d+|\?))?$/);
    if (!m) throw new Error(`FakeD1: cannot parse SELECT: ${this.q}`);
    const [, colsStr, table, where, orderBy, orderDir, limitTok] = m;
    let rows = this.filterRows(table, where, [...this.args]);
    if (orderBy) {
      const dir = orderDir === "DESC" ? -1 : 1;
      rows = [...rows].sort((a, b) => {
        const av = a[orderBy];
        const bv = b[orderBy];
        // ISO-8601 TEXT timestamps sort lexicographically; numbers numerically.
        if (typeof av === "string" && typeof bv === "string") {
          return dir * (av < bv ? -1 : av > bv ? 1 : 0);
        }
        return dir * (Number(av ?? 0) - Number(bv ?? 0));
      });
    }
    let limit: number | undefined;
    if (limitTok === "?") {
      const wherePlaceholders = (where?.match(/\?/g) ?? []).length;
      limit = Number(this.args[wherePlaceholders] ?? 0);
    } else if (limitTok) {
      limit = Number(limitTok);
    }
    if (limit) rows = rows.slice(0, limit);
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
        // IN list of placeholders: `id IN (?, ?, ?)` (captcha linkSolveOutcome).
        const inM = cond.match(/^(\w+) IN \(([\?,\s]+)\)$/);
        if (inM) {
          const col = inM[1];
          const count = (inM[2].match(/\?/g) ?? []).length;
          const vals = args.slice(argIdx, argIdx + count);
          argIdx += count;
          if (!vals.includes(r[col])) return false;
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
