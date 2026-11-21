/**
 * db.ts — D1 helpers (thin wrappers; SQL yahin rehta hai, routes me nahi).
 * Env.DB is a D1Database binding (wrangler.toml). Tests pass a fake
 * implementing the same { prepare } surface.
 */

export interface D1Like {
  prepare(query: string): D1PreparedLike;
}

export interface D1PreparedLike {
  bind(...args: unknown[]): D1PreparedLike;
  run(): Promise<{ success: boolean; meta?: unknown }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  first<T = Record<string, unknown>>(): Promise<T | null>;
}

export async function getDevice(
  db: D1Like,
  deviceId: string,
): Promise<{ device_id: string; tenant_id: string; public_key: string; enabled: number } | null> {
  const row = await db
    .prepare("SELECT device_id, tenant_id, public_key, enabled FROM devices WHERE device_id = ?")
    .bind(deviceId)
    .first<{ device_id: string; tenant_id: string; public_key: string; enabled: number }>();
  return row;
}

export async function insertTrace(
  db: D1Like,
  tenantId: string,
  deviceId: string,
  kind: string,
  detail: Record<string, unknown>,
): Promise<void> {
  await db
    .prepare("INSERT INTO traces (tenant_id, device_id, kind, detail, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(tenantId, deviceId, kind, JSON.stringify(detail), Date.now())
    .run();
}

export async function touchDeviceSeen(db: D1Like, deviceId: string): Promise<void> {
  await db
    .prepare("UPDATE devices SET last_seen = ? WHERE device_id = ?")
    .bind(Date.now(), deviceId)
    .run();
}
