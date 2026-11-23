/**
 * admin.ts — R4.5 admin website v1 (hub-served pages, M-I-19).
 *
 * Auth is the licence-web passwordless email-code session (same cookie,
 * same 30-day HttpOnly session) PLUS an admin flag: only the owner
 * email is admin. The flag lives on licence_web_users.is_admin
 * (migration 0017 sets it for the owner); ensureOwnerAdmin() also sets
 * it at runtime on every /admin visit, so a user row created after the
 * migration still becomes admin. No password, no second login system.
 *
 * Sections (one page, JS-fetched): Dashboard (devices, jobs, usage,
 * health), Keys (status ONLY — key values are never displayed, logged,
 * or returned), Training console (POST /api/admin/train, session-gated),
 * Jobs (Main Executor runs), Users/licences (masked keys), Launch
 * gates, Backups. The sections reuse the existing admin JSON APIs
 * where they exist (launch-gates, backups, licences admin list need
 * x-admin-token and stay token-gated — the page links them with a note);
 * /api/admin/overview is the session-gated aggregate for the dashboard.
 *
 * Keys honesty note: the founder Gemini key CAN be set from this page
 * (it is a tenant BYOK key in D1, live-validated like
 * POST /api/tenants/:id/key). The admin GitHub token CANNOT be set from
 * inside the Worker — Worker secrets are set via the Cloudflare API
 * from outside; the page shows its set/not-set status and the exact
 * owner-side step. Nothing here fakes a token being set.
 */
import type { D1Like } from "./db";
import { maskLicenceKey } from "./licence-web";
import { capWarnings } from "./billing";
import { currentPeriod, getMonthUsage } from "./metering";
import { PLAN_LIMITS } from "./router";

/** The only admin: the owner. No other email can be admin. */
export const OWNER_ADMIN_EMAIL = "flipify.com@gmail.com";

export function isAdminEmail(email: string): boolean {
  return (email ?? "").trim().toLowerCase() === OWNER_ADMIN_EMAIL;
}

/** Idempotent: mark the owner admin whenever they visit /admin. */
export async function ensureOwnerAdmin(db: D1Like, email: string): Promise<void> {
  if (!isAdminEmail(email)) return;
  await db
    .prepare("UPDATE licence_web_users SET is_admin = ? WHERE email = ?")
    .bind(1, email.trim().toLowerCase())
    .run();
}

export async function isAdminUser(db: D1Like, email: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT is_admin FROM licence_web_users WHERE email = ?")
    .bind(email.trim().toLowerCase())
    .first<{ is_admin: number }>();
  if (row?.is_admin === 1) return true;
  // Belt-and-braces: the owner email is admin even if the flag row
  // was never written (migration ran before the user row existed).
  return isAdminEmail(email);
}

export interface AdminOverview {
  version: string;
  devices: { count: number; recent: Array<{ device_id: string; tenant_id: string; last_seen: number; enabled: number }> };
  jobs: { count: number; recent: Array<{ id: string; status: string; ask: string; created_at: number }> };
  usage: { tenant_id: string | null; period: string; replies: number; replies_cap: number; warnings: string[] };
  licences: { count: number; recent: Array<{ key_masked: string; user_id: string; status: string; device_id: string | null }> };
  fcm: { tokens: number };
  health: { last_cron_tick_at: number | null };
}

export async function adminOverview(db: D1Like, version: string): Promise<AdminOverview> {
  const deviceCount = await db
    .prepare("SELECT COUNT(*) AS n FROM devices")
    .bind()
    .first<{ n: number }>();
  const deviceRows = await db
    .prepare("SELECT device_id, tenant_id, last_seen, enabled FROM devices ORDER BY last_seen DESC LIMIT 10")
    .all<{ device_id: string; tenant_id: string; last_seen: number; enabled: number }>();
  const jobCount = await db.prepare("SELECT COUNT(*) AS n FROM main_jobs").bind().first<{ n: number }>();
  const jobRows = await db
    .prepare("SELECT id, status, ask, created_at FROM main_jobs ORDER BY created_at DESC LIMIT 10")
    .all<{ id: string; status: string; ask: string; created_at: number }>();
  const tenantRow = await db
    .prepare("SELECT id, plan_tier FROM tenants WHERE owner_email = ? LIMIT 1")
    .bind(OWNER_ADMIN_EMAIL)
    .first<{ id: string; plan_tier: string }>();
  const period = currentPeriod(Date.now());
  const usage = tenantRow ? await getMonthUsage(db, tenantRow.id, period) : { replies: 0, e2b_runs: 0, llm_calls: 0, input_tokens: 0, output_tokens: 0, cost_usd_micro: 0 };
  const repliesCap = tenantRow ? (PLAN_LIMITS[tenantRow.plan_tier] ?? PLAN_LIMITS.free).replies : 0;
  const warnings = tenantRow
    ? capWarnings({ replies: usage.replies, e2b_runs: usage.e2b_runs, cron_jobs: 0, devices: deviceCount?.n ?? 0 }, tenantRow.plan_tier)
    : [];
  const licenceCount = await db.prepare("SELECT COUNT(*) AS n FROM licences").bind().first<{ n: number }>();
  const licenceRows = await db
    .prepare("SELECT key, user_id, device_id, status FROM licences ORDER BY created_at DESC LIMIT 10")
    .all<{ key: string; user_id: string; device_id: string | null; status: string }>();
  const fcmCount = await db.prepare("SELECT COUNT(*) AS n FROM fcm_tokens").bind().first<{ n: number }>();
  const tickRow = await db
    .prepare("SELECT created_at FROM traces WHERE kind = ? ORDER BY created_at DESC LIMIT 1")
    .bind("cron_trigger")
    .first<{ created_at: number }>();
  return {
    version,
    devices: { count: deviceCount?.n ?? 0, recent: deviceRows.results ?? [] },
    jobs: { count: jobCount?.n ?? 0, recent: jobRows.results ?? [] },
    usage: { tenant_id: tenantRow?.id ?? null, period, replies: usage.replies, replies_cap: repliesCap, warnings },
    licences: {
      count: licenceCount?.n ?? 0,
      recent: (licenceRows.results ?? []).map((l) => ({
        key_masked: maskLicenceKey(l.key),
        user_id: l.user_id,
        status: l.status,
        device_id: l.device_id,
      })),
    },
    fcm: { tokens: fcmCount?.n ?? 0 },
    health: { last_cron_tick_at: tickRow?.created_at ?? null },
  };
}

// ---------------------------------------------------------------- HTML pages
// Same shell style as licence-web.ts (server-rendered, one inline
// <script>, same-origin fetch). No framework, no external assets.

function adminShell(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — OmniJarvis Admin</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px;color:#222}input,button,textarea,select{font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #bbb}input,textarea,select{width:100%;box-sizing:border-box;margin:8px 0}button{background:#111;color:#fff;border:0;cursor:pointer;margin:8px 8px 8px 0}button.secondary{background:#eee;color:#222}.msg{margin:12px 0;padding:10px;border-radius:8px;background:#f0f0f0;display:none}.msg.err{background:#fde8e8}.msg.ok{background:#e6f4ea}code{background:#f0f0f0;padding:2px 6px;border-radius:4px;word-break:break-all}h2{margin-top:32px;border-top:1px solid #ddd;padding-top:16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:14px}</style>
</head><body>${body}</body></html>`;
}

export function adminLoginPage(): string {
  return adminShell(
    "Admin login",
    `<h1>OmniJarvis Admin</h1>
<p>Owner-only. We send a 6-digit code to your email — the same login as the licence dashboard. Only <code>${OWNER_ADMIN_EMAIL}</code> can open this console.</p>
<label>Email<input id="email" type="email" placeholder="you@example.com" autocomplete="email"></label>
<button id="send">Send login code</button>
<div id="codeBox" style="display:none"><label>6-digit code<input id="code" inputmode="numeric" maxlength="6" placeholder="123456"></label>
<button id="verify">Verify &amp; open admin</button></div>
<div id="msg" class="msg"></div>
<p><a href="/licence/login">Licence login</a></p>
<script>
const $=id=>document.getElementById(id);
async function post(path,body){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});return {status:r.status,body:await r.json().catch(()=>({}))};}
function show(msg,ok){const m=$("msg");m.style.display="block";m.className="msg "+(ok?"ok":"err");m.textContent=msg;}
$("send").onclick=async()=>{const email=$("email").value.trim();if(!email)return show("Email likho.",false);
const r=await post("/api/licence-web/login",{email});
if(r.status===200){show("Code bhej diya — apna inbox check karo (10 minute me expire hoga).",true);$("codeBox").style.display="block";}
else show("Error: "+(r.body.error||r.status),false);};
$("verify").onclick=async()=>{const email=$("email").value.trim();const code=$("code").value.trim();
const r=await post("/api/licence-web/verify",{email,code,purpose:"login"});
if(r.status===200){show("Verified! Admin console khul raha hai…",true);location.href="/admin";}
else show("Error: "+(r.body.error||r.status)+" — "+(r.body.detail||"dobara try karo"),false);};
</script>`,
  );
}

export function adminDashboardPage(email: string): string {
  return adminShell(
    "Admin console",
    `<h1>OmniJarvis Admin</h1>
<p>Signed in as <strong>${email}</strong> (owner) — <a href="/licence/dashboard">licence dashboard</a></p>
<div id="msg" class="msg"></div>
<h2>Dashboard</h2><div id="overview">Loading…</div>
<h2>Keys</h2><div id="keys">Loading…</div>
<p style="font-size:14px">Founder Gemini key yahin se set hoti hai (tenant BYOK key, live-validated, encrypted). Admin GitHub token yahan se set NAHI ho sakta — Worker secrets Cloudflare API se bahar se set hote hain; neeche status + step dekho.</p>
<h2>Training console</h2>
<p style="font-size:14px">Jarvis ko train karo — ek instruction per line (max 50). Admin instructions jeet-ti hain (source=admin).</p>
<textarea id="trainText" rows="4" placeholder="Hamesha Hinglish me jawab do&#10;Har subah 8 baje Purnea ka mausam batao"></textarea>
<button id="trainBtn">Train Jarvis</button><span id="trainOut"></span>
<h2>Jobs — Main Executor</h2><div id="jobs">Loading…</div>
<h2>Users / licences</h2><div id="licences">Loading…</div>
<h2>Launch gates &amp; backups</h2>
<p style="font-size:14px">Ye do sections abhi bhi x-admin-token APIs se chalte hain (<code>/api/billing/admin/launch-gates</code>, <code>/api/billing/admin/backups</code>) — token owner ke paas hai, page se nahi khulte. Admin console v2 me session-gated honge.</p>
<script>
const $=id=>document.getElementById(id);
function show(msg,ok){const m=$("msg");m.style.display="block";m.className="msg "+(ok?"ok":"err");m.textContent=msg;}
async function get(path){const r=await fetch(path);return {status:r.status,body:await r.json().catch(()=>({}))};}
async function post(path,body){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});return {status:r.status,body:await r.json().catch(()=>({}))};}
function esc(s){return String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
(async()=>{
const o=await get("/api/admin/overview");
if(o.status!==200){$("overview").textContent="Overview load nahi hua: "+(o.body.error||o.status);return;}
const d=o.body;
window.__tenantId=d.usage.tenant_id;
$("overview").innerHTML="<table><tr><th>Hub version</th><td>"+esc(d.version)+"</td></tr><tr><th>Devices paired</th><td>"+d.devices.count+"</td></tr><tr><th>Main jobs</th><td>"+d.jobs.count+"</td></tr><tr><th>AI replies ("+esc(d.usage.period)+")</th><td>"+d.usage.replies+" / "+d.usage.replies_cap+(d.usage.warnings.length?" — WARNING: "+esc(d.usage.warnings.join(", ")):"")+"</td></tr><tr><th>Licences</th><td>"+d.licences.count+"</td></tr><tr><th>FCM tokens</th><td>"+d.fcm.tokens+"</td></tr><tr><th>Last cron tick</th><td>"+(d.health.last_cron_tick_at?new Date(d.health.last_cron_tick_at).toISOString():"never")+"</td></tr></table>";
$("jobs").innerHTML=d.jobs.recent.length?("<table><tr><th>Job</th><th>Status</th><th>Ask</th></tr>"+d.jobs.recent.map(j=>"<tr><td><code>"+esc(j.id)+"</code></td><td>"+esc(j.status)+"</td><td>"+esc((j.ask||"").slice(0,80))+"</td></tr>").join("")+"</table>"):"<p>No Main jobs yet.</p>";
$("licences").innerHTML=d.licences.recent.length?("<table><tr><th>Licence</th><th>User</th><th>Status</th><th>Device</th></tr>"+d.licences.recent.map(l=>"<tr><td><code>"+esc(l.key_masked)+"</code></td><td>"+esc(l.user_id)+"</td><td>"+esc(l.status)+"</td><td>"+esc(l.device_id||"—")+"</td></tr>").join("")+"</table>"):"<p>No licences yet.</p>";
})();
(async()=>{
const k=await get("/api/admin/keys");
if(k.status!==200){$("keys").textContent="Keys status load nahi hua: "+(k.body.error||k.status);return;}
const d=k.body;
$("keys").innerHTML="<table><tr><th>Tenant Gemini key (BYOK)</th><td>"+(d.has_gemini_key?"set":"not set")+"</td></tr><tr><th>Tenant Groq key (BYOK)</th><td>"+(d.has_groq_key?"set":"not set")+"</td></tr><tr><th>Founder Gemini key (Worker secret)</th><td>"+(d.founder_gemini_key_set?"set":"not set")+"</td></tr><tr><th>Founder Groq key (Worker secret)</th><td>"+(d.founder_groq_key_set?"set":"not set")+"</td></tr><tr><th>Admin GitHub token (Worker secret)</th><td>"+(d.github_admin_token_set?"set":"not set — set it with the Cloudflare API (wrangler secret put GITHUB_ADMIN_TOKEN) — Main Executor ka live PR flow iske bina propose-only rehta hai")+"</td></tr></table>"
+"<label>Founder Gemini key (set/replace — live-validated)<input id='gemKey' type='password' placeholder='AIza…' autocomplete='off'></label><button id='gemBtn'>Set Gemini key</button><span id='gemOut'></span>";
$("gemBtn").onclick=async()=>{const v=$("gemKey").value.trim();if(!v)return show("Key likho.",false);
const r=await post("/api/admin/keys/gemini",{gemini_key:v});
if(r.status===200){show("Gemini key set — live-validated + encrypted.",true);$("gemKey").value="";}
else show("Error: "+(r.body.error||r.status),false);};
})();
$("trainBtn").onclick=async()=>{const lines=$("trainText").value.split("\\n").map(s=>s.trim()).filter(Boolean);
if(!lines.length)return show("Ek instruction likho.",false);
if(!window.__tenantId)return show("Tenant id load nahi hua — page reload karo.",false);
const r=await post("/api/admin/train",{tenant_id:window.__tenantId,instructions:lines.map(t=>({text:t}))});
$("trainOut").textContent=r.status===200?(" Trained: "+r.body.patterns_added+" patterns, "+r.body.memories_added+" memories."):(" Error: "+(r.body.error||r.status));};
</script>`,
  );
}
