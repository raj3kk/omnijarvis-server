/**
 * Fake DurableObjectState + WebSocket for JarvisHub tests.
 * sql.exec is synchronous (like the real DO SQLite API) and backed by
 * the FakeD1 mini engine.
 */
import { FakeD1 } from "./fake-d1";

export class FakeWebSocket {
  sent: string[] = [];
  closed: { code: number; reason: string } | null = null;
  send(data: string): void {
    this.sent.push(data);
  }
  close(code: number, reason: string): void {
    this.closed = { code, reason };
  }
}

export class FakeSql {
  constructor(private db: FakeD1) {}
  exec(query: string, ...params: unknown[]): { toArray: () => Record<string, unknown>[] } {
    const prepared = this.db.prepare(query);
    prepared.bind(...params);
    const rows = (
      prepared as unknown as { execSync: () => Record<string, unknown>[] }
    ).execSync();
    return { toArray: () => rows };
  }
}

export class FakeDOState {
  sql: FakeSql;
  db: FakeD1;
  alarms: number[] = [];
  accepted: FakeWebSocket[] = [];
  storage: {
    sql: FakeSql;
    setAlarm: (ts: number) => Promise<void>;
  };

  constructor(db: FakeD1) {
    this.db = db;
    this.sql = new FakeSql(db);
    this.storage = {
      sql: this.sql,
      setAlarm: async (ts: number) => {
        this.alarms.push(ts);
      },
    };
  }

  acceptWebSocket(ws: FakeWebSocket): void {
    this.accepted.push(ws);
  }
}
