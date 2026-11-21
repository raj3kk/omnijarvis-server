/**
 * supabase.ts — Supabase REST client (service key from Worker secret).
 * Sirf server-side: service key kabhi client/APK ko nahi milta.
 * 2a-2 me sirf cron tick isey use karta hai (scheduled_jobs read);
 * table na ho to PostgREST 42P01 deta hai -> caller 503 schema_pending.
 */

export interface SupabaseEnv {
  SUPABASE_URL?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
}

export class SupabaseMissing extends Error {
  constructor() {
    super("supabase_not_configured");
  }
}

export class SupabaseSchemaPending extends Error {
  constructor() {
    super("schema_pending");
  }
}

export async function supabaseSelect(
  env: SupabaseEnv,
  table: string,
  query: string,
): Promise<Record<string, unknown>[]> {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new SupabaseMissing();
  const url = `${env.SUPABASE_URL}/rest/v1/${table}?${query}`;
  const res = await fetch(url, {
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      Accept: "application/json",
    },
  });
  if (res.status === 404) throw new SupabaseSchemaPending();
  if (!res.ok) {
    const text = await res.text();
    // PostgREST "relation does not exist" (42P01) -> schema pending.
    if (text.includes("42P01") || text.includes("does not exist")) {
      throw new SupabaseSchemaPending();
    }
    throw new Error(`supabase_select_failed:${res.status}`);
  }
  return (await res.json()) as Record<string, unknown>[];
}

export async function supabaseUpdate(
  env: SupabaseEnv,
  table: string,
  match: string,
  patch: Record<string, unknown>,
): Promise<void> {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new SupabaseMissing();
  const url = `${env.SUPABASE_URL}/rest/v1/${table}?${match}`;
  const res = await fetch(url, {
    method: "PATCH",
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=minimal",
    },
    body: JSON.stringify(patch),
  });
  if (res.status === 404) throw new SupabaseSchemaPending();
  if (!res.ok) {
    const text = await res.text();
    if (text.includes("42P01") || text.includes("does not exist")) {
      throw new SupabaseSchemaPending();
    }
    throw new Error(`supabase_update_failed:${res.status}`);
  }
}

/**
 * Licence-key check (pairing init): licences table (key, user_id,
 * device_id, status) — status 'active' hona chahiye. Revoked/missing
 * key -> false. Supabase env missing -> SupabaseMissing (fail-closed).
 */
export async function verifyLicenceKey(env: SupabaseEnv, key: string): Promise<boolean> {
  const rows = await supabaseSelect(
    env,
    "licences",
    `select=key,status&key=eq.${encodeURIComponent(key)}`,
  );
  return rows.length > 0 && rows[0].status === "active";
}
