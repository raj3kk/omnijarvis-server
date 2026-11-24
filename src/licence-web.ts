/**
 * licence-web.ts — M-I-28: self-serve licence web UI (hub-served).
 *
 * Pure helpers + HTML pages. No fetch, no D1 in this module (the hub
 * routes own I/O) so everything here is unit-testable without mocks.
 *
 * Identity is PASSWORDLESS (design decision): signup and login are both
 * "email -> 6-digit code -> session". No passwords are stored anywhere.
 * Codes are SHA-256 hashed at rest, 10-min expiry, max 5 attempts,
 * single-use. Sessions are random 256-bit tokens, SHA-256 hashed in
 * D1, raw token in an HttpOnly cookie only.
 *
 * Licence issuance is NOT re-implemented here: the hub calls the
 * existing licence Worker's /api/licence/generate with
 * LICENCE_ADMIN_TOKEN (one issuance path; 403 licence_revoked and
 * existing:true are preserved by construction). Licence keys are NEVER
 * logged or traced — only the generate response to the verified owner
 * carries the full key, once.
 */
import { DISPOSABLE_EMAIL_DOMAINS } from "./billing";
import { sha256Hex } from "./docs";
import { esc, siteShell } from "./site";

export const LICENCE_CODE_TTL_MS = 10 * 60_000;
export const LICENCE_CODE_MAX_ATTEMPTS = 5;
export const LICENCE_SESSION_TTL_MS = 30 * 24 * 60 * 60_000;
export const LICENCE_WORKER_URL_DEFAULT = "https://jarvis-licence.rajraj3kk.workers.dev";
export const LICENCE_SESSION_COOKIE = "lic_session";

export function normalizeEmail(email: string): string {
  return (email ?? "").trim().toLowerCase();
}

/** Format check + disposable-domain block (same list as billing). */
export function isValidEmail(email: string): { ok: boolean; error?: string } {
  const e = normalizeEmail(email);
  if (!e || e.length > 254) return { ok: false, error: "invalid_email" };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e)) return { ok: false, error: "invalid_email" };
  const domain = e.split("@")[1];
  if ((DISPOSABLE_EMAIL_DOMAINS as readonly string[]).includes(domain)) return { ok: false, error: "disposable_email" };
  return { ok: true };
}

/** 6-digit code (100000-999999) + its SHA-256 hash for storage. */
export async function newEmailCode(): Promise<{ code: string; codeHash: string }> {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  const n = 100000 + (new DataView(bytes.buffer).getUint32(0) % 900000);
  const code = String(n);
  return { code, codeHash: await sha256Hex(code) };
}

/** Async because sha256Hex is async (WebCrypto). */
export async function hashEmailCode(code: string): Promise<string> {
  return sha256Hex(code.trim());
}

export async function verifyEmailCode(code: string, codeHash: string): Promise<boolean> {
  if (!/^\d{6}$/.test((code ?? "").trim())) return false;
  return (await hashEmailCode(code)) === codeHash;
}

/** 256-bit session token (base64url) + its SHA-256 hash for storage. */
export async function newSessionToken(): Promise<{ token: string; tokenHash: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const token = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return { token, tokenHash: await sha256Hex(token) };
}

export async function hashSessionToken(token: string): Promise<string> {
  return sha256Hex(token);
}

/** "JARVIS-AB12-CD34-EF56-GH78" -> "JARVIS-AB12-••••-••••-GH78". */
export function maskLicenceKey(key: string): string {
  const parts = (key ?? "").split("-");
  if (parts.length !== 5) return "••••";
  return `${parts[0]}-${parts[1]}-••••-••••-${parts[4]}`;
}

export function sessionCookie(token: string, maxAgeSec: number): string {
  return `${LICENCE_SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSec}`;
}

/** Code email (Resend): subject + plain HTML/text. No links — the code
 * is typed into the hub page, so there is no token-in-URL to leak. */
export function licenceCodeEmailContent(code: string, purpose: "signup" | "login"): { subject: string; html: string; text: string } {
  const subject = `Your OmniJarvis ${purpose === "signup" ? "signup" : "login"} code: ${code}`;
  const text = `Your OmniJarvis verification code is ${code}. It expires in 10 minutes. If you did not ask for this, ignore this email.`;
  const html = `<p>Your OmniJarvis verification code is:</p><p style="font-size:28px;letter-spacing:4px"><strong>${code}</strong></p><p>It expires in 10 minutes. If you did not ask for this, ignore this email.</p>`;
  return { subject, html, text };
}

export function clearSessionCookie(): string {
  return `${LICENCE_SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// ---------------------------------------------------------------- HTML pages
// Small server-rendered pages, one inline <script> each (same-origin
// fetch to the JSON API). No framework, no external assets.

function pageShell(title: string, body: string): string {
  // Shared professional shell (site.ts) — same element IDs, same inline
  // JS, same API calls. Only the look changes.
  return siteShell(title, body, { active: "licence", narrow: true });
}

function codeFormScript(purpose: "signup" | "login"): string {
  return `<script>
const $=id=>document.getElementById(id);
async function post(path,body){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});return {status:r.status,body:await r.json().catch(()=>({}))};}
function show(msg,ok){const m=$("msg");m.style.display="block";m.className="msg "+(ok?"ok":"err");m.textContent=msg;}
$("send").onclick=async()=>{const email=$("email").value.trim();if(!email)return show("Email likho.",false);
const r=await post("/api/licence-web/${purpose}",{email});
if(r.status===200){show("Code bhej diya — apna inbox check karo (10 minute me expire hoga).",true);$("codeBox").style.display="block";}
else show("Error: "+(r.body.error||r.status),false);};
$("verify").onclick=async()=>{const email=$("email").value.trim();const code=$("code").value.trim();
const r=await post("/api/licence-web/verify",{email,code,purpose:"${purpose}"});
if(r.status===200){show("Verified! Dashboard khul raha hai…",true);location.href="/licence/dashboard";}
else show("Error: "+(r.body.error||r.status)+" — "+(r.body.detail||"dobara try karo"),false);};
</script>`;
}

export function licenceLandingPage(): string {
  return pageShell(
    "Get your free licence",
    `<h1>Get your free licence</h1>
<p>One licence per user, bound to one device. No payment anywhere. Sign up with your email — we send a 6-digit code, you verify, and your licence key is issued.</p>
<p class="note">Free plan included: 100 AI replies a month, 1 device, 1 skill. Need more? See <a href="/pricing">Pricing</a>.</p>
<label>Email<input id="email" type="email" placeholder="you@example.com" autocomplete="email"></label>
<button id="send">Send verification code</button>
<div id="codeBox" style="display:none"><label>6-digit code<input id="code" inputmode="numeric" maxlength="6" placeholder="123456"></label>
<button id="verify">Verify &amp; continue</button></div>
<div id="msg" class="msg"></div>
<p><a href="/licence/login">Already signed up? Log in</a></p>
${codeFormScript("signup")}`,
  );
}

export function licenceLoginPage(): string {
  return pageShell(
    "Log in",
    `<h1>Log in</h1>
<p>We send a 6-digit code to your email — no password to remember.</p>
<label>Email<input id="email" type="email" placeholder="you@example.com" autocomplete="email"></label>
<button id="send">Send login code</button>
<div id="codeBox" style="display:none"><label>6-digit code<input id="code" inputmode="numeric" maxlength="6" placeholder="123456"></label>
<button id="verify">Verify &amp; log in</button></div>
<div id="msg" class="msg"></div>
<p><a href="/licence">New here? Sign up</a></p>
${codeFormScript("login")}`,
  );
}

export interface DashboardLicence {
  key_masked: string;
  status: string;
  device_id: string | null;
  created_at: string | null;
}

export function licenceDashboardPage(email: string, licence: DashboardLicence | null, justIssuedKey?: string): string {
  const licBlock = justIssuedKey
    ? `<p>Your licence key (shown ONCE — copy it now, it will be masked afterwards):</p><p class="key"><code>${justIssuedKey}</code></p>`
    : licence
      ? `<p>Licence: <code>${licence.key_masked}</code> — ${licence.status}${licence.device_id ? ` — bound to device <code>${licence.device_id}</code>` : " — not bound to a device yet"}</p>`
      : `<p>No licence yet — generate one below (one per verified email).</p>`;
  return pageShell(
    "Dashboard",
    `<h1>Your licence</h1>
<p>Signed in as <strong>${esc(email)}</strong></p>
${licBlock}
<button id="gen">Generate my licence</button>
<button id="rel" class="secondary">Release device</button>
<button id="out" class="secondary">Log out</button>
<div id="keyBox"></div>
<div id="msg" class="msg"></div>
<h2>How to use it</h2>
<p>Paste the key in the OmniJarvis app when it asks for a licence, then pair your device. The key binds to the first device that verifies it — releasing frees it for another device.</p>
<script>
const $=id=>document.getElementById(id);
async function post(path,body){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});return {status:r.status,body:await r.json().catch(()=>({}))};}
function show(msg,ok){const m=$("msg");m.style.display="block";m.className="msg "+(ok?"ok":"err");m.textContent=msg;}
$("gen").onclick=async()=>{const r=await post("/api/licence-web/generate");
if(r.status===200){if(r.body.licence&&r.body.licence.key){$("keyBox").innerHTML="<p>Your licence key (shown ONCE — copy it now):</p><p class='key'><code>"+r.body.licence.key+"</code></p>";show("Licence issued — copy the key above now. It will be masked on your next visit.",true);}
else show("You already have a licence — it is shown above (masked).",true);}
else show("Error: "+(r.body.error||r.status),false);};
$("rel").onclick=async()=>{if(!confirm("Release the bound device? The licence stays yours and can bind again."))return;const r=await post("/api/licence-web/release");show(r.status===200?"Device released.":("Error: "+(r.body.error||r.status)),r.status===200);if(r.status===200)setTimeout(()=>location.reload(),800);};
$("out").onclick=async()=>{await post("/api/licence-web/logout");location.href="/licence/login";};
</script>`,
  );
}

export function licenceAdminPage(): string {
  return pageShell(
    "Owner — licences",
    `<h1>Owner — licences</h1>
<p>Admin token (owner only) — it is sent as a header, never stored in a cookie.</p>
<label>Admin token<input id="token" type="password" placeholder="LLM admin token"></label>
<button id="load">Load licences</button>
<div id="list"></div>
<div id="msg" class="msg"></div>
<script>
const $=id=>document.getElementById(id);
function show(msg,ok){const m=$("msg");m.style.display="block";m.className="msg "+(ok?"ok":"err");m.textContent=msg;}
$("load").onclick=async()=>{const t=$("token").value.trim();if(!t)return show("Token chahiye.",false);
const r=await fetch("/api/licence-web/admin/licences",{headers:{"x-admin-token":t}});
const b=await r.json().catch(()=>({}));if(r.status!==200)return show("Error: "+(b.error||r.status),false);
$("list").innerHTML=b.licences.map(l=>"<p><code>"+l.key+"</code> — "+l.user_id+" — "+l.status+" — device "+(l.device_id||"—")+" <button data-k='"+l.key+"' class='rev'>Revoke</button></p>").join("")||"<p>No licences.</p>";
document.querySelectorAll(".rev").forEach(btn=>btn.onclick=async()=>{if(!confirm("Revoke "+btn.dataset.k+"? The user can never generate again."))return;
const rr=await fetch("/api/licence-web/admin/revoke",{method:"POST",headers:{"Content-Type":"application/json","x-admin-token":t},body:JSON.stringify({key:btn.dataset.k})});
show(rr.status===200?"Revoked.":"Error: "+rr.status,rr.status===200);if(rr.status===200)$("load").click();});};
</script>`,
  );
}
