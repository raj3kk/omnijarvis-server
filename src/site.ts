/**
 * site.ts — OmniJarvis public website (hub-served HTML, no external assets).
 *
 * One shared design system for EVERY hub-served page: the public site
 * (landing, pricing, download, docs, legal), the licence portal and the
 * admin console all render through `siteShell` so the whole site looks
 * like one product. Creamy whitish theme (user-locked), mobile-first,
 * system fonts only (fast, no CDN), no emojis as decoration.
 *
 * Rules: only HTML changes here — no API route, no auth flow, no
 * billing logic. Licence/admin pages keep their element IDs and their
 * inline JS verbatim (see licence-web.ts / admin.ts); this module only
 * supplies the shell + CSS they render inside.
 */

export const APK_VERSION = "1.20.0";
export const APK_SIZE = "16.06 MiB";
export const APK_DOWNLOAD_URL =
  "https://drive.google.com/uc?export=download&id=1OYKdlqFwEUlD7C7vceUDhNMG7DY7kCDN";

/** HTML-escape for server-rendered user data (emails, masked keys). */
export function esc(s: string): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export const SITE_CSS = `
:root{--bg:#fbf7ef;--surface:#fffdf7;--card:#ffffff;--ink:#221c14;--muted:#6f6455;--line:#e9dfcd;--line2:#efe7d6;--accent:#92400e;--accent-soft:#fdf0dd;--ok:#1e7b34;--err:#b3261e;--radius:14px}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.6;font-size:16px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{line-height:1.25;margin:0 0 12px}
h1{font-size:clamp(30px,7vw,46px);letter-spacing:-.02em}
h2{font-size:clamp(22px,5vw,28px);letter-spacing:-.01em;margin-top:36px}
h3{font-size:18px}
p{margin:0 0 14px}
small,.muted{color:var(--muted)}
code{background:#f3ecdc;padding:2px 6px;border-radius:6px;word-break:break-all;font-size:.9em}
header.site{position:sticky;top:0;z-index:10;background:rgba(251,247,239,.96);backdrop-filter:blur(6px);border-bottom:1px solid var(--line)}
.navwrap{max-width:1060px;margin:0 auto;padding:12px 16px;display:flex;align-items:center;gap:18px}
.brand{font-weight:800;font-size:19px;letter-spacing:-.02em;color:var(--ink);white-space:nowrap}
.brand span{color:var(--accent)}
nav.main{display:flex;gap:4px;overflow-x:auto;scrollbar-width:none;flex:1}
nav.main::-webkit-scrollbar{display:none}
nav.main a{color:var(--ink);font-size:15px;padding:8px 10px;border-radius:8px;white-space:nowrap}
nav.main a:hover{background:var(--accent-soft);text-decoration:none}
nav.main a.active{background:var(--ink);color:var(--bg)}
.navcta{white-space:nowrap}
.wrap{max-width:1060px;margin:0 auto;padding:28px 16px 64px}
.narrow{max-width:720px;margin:0 auto;padding:28px 16px 64px}
footer.site{border-top:1px solid var(--line);background:var(--surface)}
.footwrap{max-width:1060px;margin:0 auto;padding:32px 16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:24px}
.footwrap h4{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.footwrap a{display:block;color:var(--ink);font-size:15px;padding:3px 0}
.footbottom{border-top:1px solid var(--line2);padding:16px;text-align:center;color:var(--muted);font-size:14px}
.hero{padding:44px 0 8px;text-align:left}
.eyebrow{display:inline-block;background:var(--accent-soft);color:var(--accent);font-weight:700;font-size:13px;letter-spacing:.05em;text-transform:uppercase;padding:6px 12px;border-radius:999px;margin-bottom:16px}
.lead{font-size:clamp(17px,4vw,20px);color:var(--muted);max-width:640px}
.cta{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0 10px}
.btn{display:inline-block;background:var(--ink);color:var(--bg);font-weight:700;padding:12px 20px;border-radius:10px;border:1px solid var(--ink);cursor:pointer;font-size:16px}
.btn:hover{text-decoration:none;opacity:.92}
.btn.ghost{background:transparent;color:var(--ink)}
.btn.amber{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.small{padding:9px 14px;font-size:15px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}
.chip{background:var(--surface);border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:13px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:20px}
.card h3{margin-bottom:6px}
.card p{color:var(--muted);font-size:15px;margin-bottom:0}
.card .price{font-size:34px;font-weight:800;letter-spacing:-.02em}
.card .per{color:var(--muted);font-size:14px}
.card.popular{border:2px solid var(--accent);position:relative}
.tag{position:absolute;top:-12px;right:16px;background:var(--accent);color:#fff;font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px}
ul.check{list-style:none;padding:0;margin:14px 0}
ul.check li{padding:5px 0 5px 26px;position:relative;font-size:15px}
ul.check li::before{content:"";position:absolute;left:2px;top:11px;width:14px;height:8px;border-left:2px solid var(--ok);border-bottom:2px solid var(--ok);transform:rotate(-45deg)}
ul.check li.no{color:var(--muted)}
ul.check li.no::before{border-color:#c9bda6}
.steps{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:18px;counter-reset:step}
.step{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:20px}
.step .n{width:34px;height:34px;border-radius:50%;background:var(--ink);color:var(--bg);font-weight:800;display:flex;align-items:center;justify-content:center;margin-bottom:12px}
details{border:1px solid var(--line);border-radius:12px;background:var(--card);padding:14px 18px;margin:10px 0}
summary{font-weight:700;cursor:pointer}
details p{margin:10px 0 0;color:var(--muted);font-size:15px}
table{border-collapse:collapse;width:100%;background:var(--card)}
td,th{border:1px solid var(--line);padding:8px 10px;text-align:left;font-size:14px;vertical-align:top}
th{background:var(--surface)}
label{display:block;font-weight:600;margin:14px 0 4px}
input,textarea,select{font:inherit;padding:11px 12px;border-radius:10px;border:1px solid #cfc4ae;width:100%;box-sizing:border-box;margin:6px 0;background:#fff}
input:focus,textarea:focus,select:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
button{font:inherit;padding:11px 18px;border-radius:10px;border:0;background:var(--ink);color:var(--bg);font-weight:700;cursor:pointer;margin:8px 8px 8px 0}
button.secondary{background:#efe7d6;color:var(--ink)}
button:disabled{opacity:.55;cursor:wait}
.msg{margin:14px 0;padding:12px 14px;border-radius:10px;background:#f3ecdc;display:none}
.msg.err{background:#fde8e8;color:#7a1a14;display:block}
.msg.ok{background:#e6f4ea;color:#14532d;display:block}
.skel{border-radius:10px;background:linear-gradient(90deg,#f0e8d8 25%,#faf4e6 50%,#f0e8d8 75%);background-size:200% 100%;animation:shimmer 1.4s infinite linear;min-height:20px;margin:8px 0}
.skel.tall{min-height:120px}
@keyframes shimmer{to{background-position:-200% 0}}
.callout{background:var(--accent-soft);border:1px solid #f0d9b5;border-radius:var(--radius);padding:16px 20px;margin:18px 0}
.callout.warn{background:#fdf3e3;border-color:#ecd9ae}
.note{font-size:14px;color:var(--muted)}
.key{font-size:18px;letter-spacing:1px;word-break:break-all}
.section{margin-top:44px}
@media (max-width:640px){.navwrap{gap:10px}.brand{font-size:17px}.wrap,.narrow{padding:20px 14px 48px}button{width:100%;margin:8px 0}.cta .btn{flex:1;text-align:center}}
`;

export type SiteNav = "home" | "pricing" | "download" | "docs" | "licence" | "admin" | "";

/** Shared shell for every hub-served page. `narrow` = form-style pages (licence/admin login). */
export function siteShell(title: string, body: string, opts: { active?: SiteNav; description?: string; narrow?: boolean } = {}): string {
  const active = opts.active ?? "";
  const link = (href: string, label: string, key: SiteNav) =>
    `<a href="${href}"${active === key ? ' class="active"' : ""}>${label}</a>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} — OmniJarvis</title>${opts.description ? `<meta name="description" content="${esc(opts.description)}">` : ""}
<style>${SITE_CSS}</style>
</head><body>
<header class="site"><div class="navwrap">
<a class="brand" href="/">Omni<span>Jarvis</span></a>
<nav class="main">${link("/", "Home", "home")}${link("/pricing", "Pricing", "pricing")}${link("/download", "Download", "download")}${link("/docs", "Docs", "docs")}${link("/licence", "Licence", "licence")}${link("/admin", "Admin", "admin")}</nav>
<a class="btn small navcta" href="/licence">Get free licence</a>
</div></header>
<main class="${opts.narrow ? "narrow" : "wrap"}">${body}</main>
<footer class="site"><div class="footwrap">
<div><h4>Product</h4><a href="/pricing">Pricing</a><a href="/download">Download the app</a><a href="/docs">Docs &amp; help</a></div>
<div><h4>Account</h4><a href="/licence">Get a free licence</a><a href="/licence/login">Log in</a><a href="/licence/dashboard">Licence dashboard</a></div>
<div><h4>Legal</h4><a href="/privacy">Privacy Policy</a><a href="/terms">Terms of Service</a><a href="/refund">Refund Policy</a></div>
<div><h4>OmniJarvis</h4><p class="note">Your phone, your AI assistant. Free to start, no card. Talker talks, Executor works.</p></div>
</div><div class="footbottom">© 2026 OmniJarvis · P.R. Digital Enterprises, India · Hub v21</div></footer>
</body></html>`;
}

// ---------------------------------------------------------------- Landing

export function landingPage(): string {
  return siteShell(
    "Your phone, your AI assistant",
    `<section class="hero">
<span class="eyebrow">Free to start · No card · Android</span>
<h1>Your phone, your AI assistant.</h1>
<p class="lead">OmniJarvis is the assistant that lives on your phone and does the work — it talks with you, plans the job, opens the browser, taps, types and finishes it. No steps to confirm, no dashboard to babysit.</p>
<div class="cta"><a class="btn amber" href="/download">Download the app</a><a class="btn ghost" href="/licence">Get your free licence</a></div>
<div class="chips"><span class="chip">App v${APK_VERSION} · ${APK_SIZE}</span><span class="chip">Free plan · 100 AI replies/month</span><span class="chip">Talker + Executor</span><span class="chip">Your Gemini key (BYOK)</span></div>
</section>

<section class="section"><h2>Talker talks. Executor works.</h2>
<div class="grid">
<div class="card"><h3>Talker</h3><p>Talk or type in Hinglish or English. Swara voice replies, live status, no filler. The Talker only talks — it never pretends to work.</p></div>
<div class="card"><h3>Phone Executor</h3><p>Your phone is the computer: it plans, checks its own work, fixes mistakes and finishes the job — browser, taps, files, memory, scheduling, all on-device.</p></div>
<div class="card"><h3>In-app browser</h3><p>A real browser inside Jarvis — log in once, stay logged in, with screenshot evidence of every step it takes for you.</p></div>
<div class="card"><h3>Trained Jarvis</h3><p>Show it once, it remembers. Your documents, patterns and routines live in one shared memory for the Talker and the Executor.</p></div>
<div class="card"><h3>Main Executor (server)</h3><p>When the phone needs help, the server-side Main Executor researches, writes the fix and opens a pull request — you still merge it yourself.</p></div>
<div class="card"><h3>Schedule &amp; self-check</h3><p>Cron jobs, reminders and a self-check loop that re-verifies its own work. Nothing is called done without evidence.</p></div>
</div></section>

<section class="section"><h2>How it works</h2>
<div class="steps">
<div class="step"><div class="n">1</div><h3>Download &amp; install</h3><p>Get the APK, install it over any previous version. Never uninstall — uninstalling wipes your on-device documents and memory.</p></div>
<div class="step"><div class="n">2</div><h3>Get your free licence</h3><p>Sign up with your email, verify the 6-digit code, and your licence key is issued. One licence per user, bound to one device.</p></div>
<div class="step"><div class="n">3</div><h3>Pair &amp; talk</h3><p>Paste the licence in the app, pair your device, add your Gemini key — then just talk. Jarvis does the rest.</p></div>
</div></section>

<section class="section"><h2>Pricing</h2>
<p class="muted">Start free. Upgrade only when you need more. Payment is UPI-only — pay, submit the UTR, the admin approves, your plan activates. No card, no auto-charge.</p>
<div class="grid">
<div class="card"><h3>Free</h3><p class="price">₹0</p><p class="per">forever</p><ul class="check"><li>100 AI replies / month</li><li>1 device · 1 skill</li><li>Device-only, no server runs</li><li class="no">No cron jobs</li><li class="no">No document extraction</li></ul><a class="btn ghost" href="/licence">Start free</a></div>
<div class="card popular"><span class="tag">Most popular</span><h3>Pro</h3><p class="price">₹999</p><p class="per">per month · ₹10,989 / year</p><ul class="check"><li>2,500 AI replies / month</li><li>3 devices · skill library</li><li>5 cron jobs · 30 server runs / mo</li><li>Document extraction + certificates</li></ul><a class="btn amber" href="/pricing">See Pro</a></div>
<div class="card"><h3>Business</h3><p class="price">₹2,999</p><p class="per">per month · ₹32,989 / year</p><ul class="check"><li>7,500 AI replies / month</li><li>10 devices · 3 team seats</li><li>20 cron jobs · 100 server runs / mo</li><li>Priority support</li></ul><a class="btn ghost" href="/pricing">See Business</a></div>
</div></section>

<section class="section"><h2>Questions, answered</h2>
<details><summary>Does Jarvis work offline?</summary><p>No. All chat runs through the cloud (Gemini, with your own key). With no internet the app shows a clear message — it never crashes and never fakes an answer.</p></details>
<details><summary>Whose Gemini key does it use?</summary><p>Yours. Jarvis is BYOK (bring your own key): you add your Gemini API key once in the app, and chat runs on it. The founder never pays for your usage.</p></details>
<details><summary>Is my data private?</summary><p>Your documents and memories stay on your phone. The server stores only what it must: your licence, usage counters and learned patterns (templates only — never names, numbers or content). You can ask for a full wipe. See the <a href="/privacy">Privacy Policy</a>.</p></details>
<details><summary>What if Jarvis gets stuck?</summary><p>It checks its own work, retries, and escalates to the server-side Main Executor when needed. You always see the evidence — screenshots, not claims.</p></details>
<details><summary>How do I pay for Pro or Business?</summary><p>UPI only. Choose a plan, pay by UPI, submit the 12-digit UTR, and the admin approves it — then your plan activates. No card details are ever collected. See <a href="/pricing">Pricing</a>.</p></details>
</section>`,
    { active: "home", description: "OmniJarvis — the AI assistant that lives on your phone. Talker talks, Executor works. Free to start, no card." },
  );
}

// ---------------------------------------------------------------- Pricing

export function pricingPage(): string {
  return siteShell(
    "Pricing",
    `<h1>Pricing</h1>
<p class="lead">Start free. Upgrade only when you need more. Annual = 11× monthly — you pay for 11 months, the 12th is on us.</p>
<div class="grid">
<div class="card"><h3>Free</h3><p class="price">₹0</p><p class="per">forever</p><ul class="check"><li>100 AI replies / month</li><li>1 device · 1 skill</li><li>Device-only — no server runs</li><li>On-device memory</li><li class="no">No cron jobs</li><li class="no">No document extraction</li></ul><a class="btn ghost" href="/licence">Start free</a></div>
<div class="card popular"><span class="tag">Most popular</span><h3>Pro</h3><p class="price">₹999</p><p class="per">per month · ₹10,989 / year</p><ul class="check"><li>2,500 AI replies / month</li><li>3 devices · skill library</li><li>5 cron jobs</li><li>30 server runs / month (E2B)</li><li>Document extraction + certificates</li></ul><a class="btn amber" href="/download">Get Pro</a></div>
<div class="card"><h3>Business</h3><p class="price">₹2,999</p><p class="per">per month · ₹32,989 / year</p><ul class="check"><li>7,500 AI replies / month</li><li>10 devices · 3 team seats</li><li>20 cron jobs</li><li>100 server runs / month (E2B)</li><li>Priority support</li></ul><a class="btn ghost" href="/download">Get Business</a></div>
</div>

<section class="section"><h2>How payment works (UPI-only)</h2>
<div class="steps">
<div class="step"><div class="n">1</div><h3>Choose a plan</h3><p>Pick Pro or Business, monthly or annual, in the app or by contacting the admin.</p></div>
<div class="step"><div class="n">2</div><h3>Pay by UPI</h3><p>Pay the exact plan amount to the admin UPI ID shown to you. Keep the 12-digit UTR from your UPI app.</p></div>
<div class="step"><div class="n">3</div><h3>Submit the UTR</h3><p>Submit the UTR in the app. The admin verifies it and approves — your plan activates. No card details are ever collected, and there is no auto-charge or auto-renewal.</p></div>
</div>
<div class="callout"><strong>Refunds:</strong> if a payment is approved by mistake or a plan is cancelled, refunds are sent manually by UPI and recorded in the ledger. Full refund ends the subscription; a partial refund keeps it active. See the <a href="/refund">Refund Policy</a>.</div>
<p class="note">Caps are hard-enforced: when your monthly replies run out, Jarvis tells you plainly and stops — it never silently charges or overspends. Unused replies do not carry over.</p></section>`,
    { active: "pricing", description: "OmniJarvis pricing — Free ₹0, Pro ₹999/month, Business ₹2,999/month. UPI-only, no card." },
  );
}

// ---------------------------------------------------------------- Download

export function downloadPage(): string {
  return siteShell(
    "Download",
    `<h1>Download OmniJarvis</h1>
<p class="lead">The Android app. Free to start — your free licence covers the Free plan.</p>
<div class="card"><h3>OmniJarvis for Android — v${APK_VERSION}</h3>
<p class="muted">APK size: ${APK_SIZE} · Android 8+ · Your Gemini key is needed for chat (BYOK).</p>
<div class="cta"><a class="btn amber" href="${APK_DOWNLOAD_URL}">Download APK (v${APK_VERSION}, ${APK_SIZE})</a></div>
<p class="note">The file downloads from Google Drive. If your browser warns about the file, choose “Download anyway” — the APK is signed with the official OmniJarvis release key.</p></div>

<section class="section"><h2>Install — read this first</h2>
<div class="steps">
<div class="step"><div class="n">1</div><h3>Install over the old version</h3><p>Open the APK and tap Install. <strong>Never uninstall first</strong> — uninstalling wipes your on-device documents, memories and Trained Jarvis data.</p></div>
<div class="step"><div class="n">2</div><h3>Allow install from this source</h3><p>Android may ask you to allow installs from your browser or file manager. Allow it once for this install.</p></div>
<div class="step"><div class="n">3</div><h3>Get your free licence</h3><p>Open the app, sign up at <a href="/licence">/licence</a> with your email, verify the code, paste the key in the app and pair your device.</p></div>
</div>
<div class="callout warn"><strong>What you need:</strong> an Android phone, internet (chat is cloud-only — with no internet the app shows a clear message instead of answering), and your own Gemini API key, added once in the app (AI Brain → Gemini). No key, no chat — the app will tell you exactly that.</div></section>

<section class="section"><h2>What changed in v${APK_VERSION}</h2>
<ul class="check"><li>Gemma on-device model removed — all chat is now cloud-only (Gemini, your key)</li><li>APK is 22.7 MB smaller than v1.19.0 (was 37.75 MB, now ${APK_SIZE})</li><li>No “Free Local Model” card, no model download — AI Brain shows Gemini, OpenAI, Groq, OpenRouter only</li><li>Offline: clear message, no crash, no faked answer</li><li>Everything else unchanged — Talker, Executor, browser, overlay, Trained Jarvis, FCM, pairing</li></ul>
<p class="note">Full history: every release since v1.4.23 is listed in the app’s release notes. The current hub version is v21.</p></section>`,
    { active: "download", description: "Download OmniJarvis for Android — v1.20.0, 16.06 MiB. Install over the previous version, never uninstall." },
  );
}

// ---------------------------------------------------------------- Docs

export function docsPage(): string {
  return siteShell(
    "Docs & help",
    `<h1>Docs &amp; help</h1>
<p class="lead">How Jarvis works, how to set it up, and what to do when something goes wrong.</p>

<section class="section"><h2>Pair your device</h2>
<ol><li>Install the app (<a href="/download">Download</a>) over any previous version.</li><li>Get your free licence at <a href="/licence">/licence</a> — email, 6-digit code, done.</li><li>Open the app, paste the licence key when asked, and pair. The key binds to the first device that verifies it.</li><li>Add your Gemini API key in the app (AI Brain → Gemini). Chat runs on your key (BYOK).</li><li>To move to another device, release the old one from <a href="/licence/dashboard">your licence dashboard</a> first.</li></ol></section>

<section class="section"><h2>How Talker &amp; Executor work</h2>
<p><strong>Talker</strong> is the voice you talk to — it listens, replies (Swara voice), and shows live status. It never does the work itself. <strong>Executor</strong> is the worker on your phone: it plans the task, does it, checks its own work, fixes mistakes and only then reports DONE — with evidence (screenshots, not claims). There are no steps to confirm and no mid-task stops; the Executor runs until the job is done or it hits one of the 5 hard gates (OTP, login, payment, biometric, destructive confirm), where it asks you.</p>
<p><strong>Main Executor</strong> lives on the server. When the phone Executor is stuck, it escalates: Main researches, writes a fix and opens a pull request. Only you merge it — Main never merges anything.</p></section>

<section class="section"><h2>The in-app browser</h2>
<p>Jarvis has a real browser built in. Log in to a site once and it stays logged in (cookies on your phone). When Jarvis works in the browser it takes screenshots, so you can see exactly what it did. Human-assist only for captchas — Jarvis detects them and asks you; it never auto-solves a captcha.</p></section>

<section class="section"><h2>Trained Jarvis</h2>
<p>Show Jarvis a document or a routine once and it remembers it — in one shared memory used by both the Talker and the Executor. Your documents stay on your phone. To teach it something new, use the Trained tab in the app; to correct it, say so in chat and it updates the memory.</p></section>

<section class="section"><h2>Scheduling</h2>
<p>Ask Jarvis to remind you or to run something on a schedule (Pro: 5 cron jobs, Business: 20). Jobs are dispatched by the server tick every 5 minutes and executed on your phone. If your phone is off at the due time, the job runs when it comes back online.</p></section>

<section class="section"><h2>Troubleshooting</h2>
<details><summary>“Internet nahi hai” — chat won’t reply</summary><p>Chat is cloud-only and needs internet + your Gemini key. Check your connection, then check AI Brain → Gemini has a key saved. Without either, the app shows a clear message — that is by design.</p></details>
<details><summary>Jarvis forgot my chat history</summary><p>History is stored on your phone in the Jarvis Store file. If the app was uninstalled, the history is gone by design (uninstall wipes it). Always install over the previous version, never uninstall.</p></details>
<details><summary>Licence says “already bound” on a new phone</summary><p>Release the old device from <a href="/licence/dashboard">your licence dashboard</a> (“Release device”), then pair the new one.</p></details>
<details><summary>Mic doesn’t start</summary><p>The mic never auto-starts. Tap it once to turn it on — it stays on until you turn it off. Check the microphone permission in Android Settings → Apps → OmniJarvis.</p></details>
<details><summary>Something is slow</summary><p>First replies can take a few seconds (model warm-up). If a turn is very slow, the app writes a diagnostics entry — tell the admin the time it happened and it can be traced.</p></details>
</section>

<section class="section"><h2>Quick self-check (after every update)</h2>
<ul class="check"><li>Install succeeds over the previous version; app size is about 16 MB</li><li>Casual chat works on the cloud (needs internet + saved Gemini key)</li><li>AI Brain shows only Gemini, OpenAI, Groq, OpenRouter — no Local chip</li><li>Airplane mode: clear “Internet nahi hai…” message, no crash, no faked answer</li><li>No “Free Local Model” card, download button or HF token field anywhere</li></ul></section>`,
    { active: "docs", description: "OmniJarvis docs — pairing, Talker and Executor, the in-app browser, Trained Jarvis, scheduling, troubleshooting." },
  );
}

// ---------------------------------------------------------------- Legal

function legalShell(title: string, body: string): string {
  return siteShell(title, body, { active: "" });
}

export function privacyPage(): string {
  return legalShell(
    "Privacy Policy",
    `<h1>Privacy Policy</h1>
<p class="muted">Last updated: 24 November 2026 · P.R. Digital Enterprises, India</p>

<h2>What we collect</h2>
<p><strong>Licence account:</strong> your email address (for the passwordless login code and your licence) and your licence key status. <strong>Device:</strong> a device id and a public key for pairing — never your contacts, photos, or other apps’ data. <strong>Usage:</strong> counters only — AI replies used this month, server runs, cron jobs. <strong>Learned patterns:</strong> templates of what you taught Jarvis (for example “always reply in Hinglish”) — never names, phone numbers, or message content. <strong>Documents:</strong> your documents stay on your phone. If you use document extraction, the text is processed to extract the fields you asked for; personal fields (Aadhaar, PAN, account numbers) are stored only if you gave explicit consent, otherwise they are replaced with <code>[REDACTED]</code>.</p>

<h2>What we never collect</h2>
<p>Your Gemini/Groq API keys are encrypted and never shown to anyone (not even the admin — only “set / not set”). Your chat content is not stored on the server. We never sell data, never show ads, and never share data with advertisers.</p>

<h2>Your keys (BYOK)</h2>
<p>Chat runs on <em>your</em> Gemini key, stored encrypted in the database. You can replace or remove it at any time in the app (AI Brain). The founder’s keys are used only for server-side Main Executor work and are never a fallback for your chat.</p>

<h2>Cookies</h2>
<p>One session cookie (<code>lic_session</code>, HttpOnly, Secure, 30 days) keeps you logged in to the licence dashboard and admin console. No tracking cookies, no analytics cookies.</p>

<h2>Data wipe (DPDP)</h2>
<p>You can ask for a complete wipe of your data at any time — email the admin from your registered email. The wipe deletes your tenant, usage, patterns, memories, documents index and licences from the server database and is recorded as a single audit row (so the wipe itself is provable). Data on your phone is deleted by uninstalling the app.</p>

<h2>Grievance Officer</h2>
<p><strong>Not yet appointed.</strong> A Grievance Officer (name, designation, email) will be listed here when appointed; until then, grievances go to the admin by email from your registered address. Note: without a Grievance Officer, the safe-harbour protection of Section 79 of the IT Act 2000 may not apply — this is a known, deferred item, recorded in the launch checklist.</p>

<h2>Changes</h2>
<p>If this policy changes materially, the new version is published here with a new “last updated” date. Continued use after a change means you accept it.</p>`,
  );
}

export function termsPage(): string {
  return legalShell(
    "Terms of Service",
    `<h1>Terms of Service</h1>
<p class="muted">Last updated: 24 November 2026 · P.R. Digital Enterprises, India</p>

<h2>The service</h2>
<p>OmniJarvis is an AI assistant app for Android, with a server control plane (licences, sync, Main Executor, push notifications). The Free plan is free forever. Paid plans (Pro, Business) are billed monthly or annually and paid by UPI only — see <a href="/pricing">Pricing</a>.</p>

<h2>Licence</h2>
<p>One licence per user, bound to one device at a time. You may release the device and bind another. A licence can be revoked for abuse (spam, reselling, attempts to break the service) — a revoked licence can never generate again. Your licence key is shown once; keep it safe.</p>

<h2>Your keys &amp; your responsibility</h2>
<p>Chat runs on your own Gemini key (BYOK). You are responsible for your key and for what you ask Jarvis to do. Jarvis refuses nothing, but it will not complete actions that need your OTP, login, payment confirmation or biometric — those are hard gates where you must act yourself.</p>

<h2>Fair use &amp; caps</h2>
<p>Monthly caps are hard-enforced (Free 100 replies, Pro 2,500, Business 7,500). When the cap is reached, Jarvis stops and tells you. Unused replies do not carry over. Server runs, cron jobs, devices and skills are capped per plan as shown on <a href="/pricing">Pricing</a>.</p>

<h2>No warranty</h2>
<p>The service is provided “as is”, without warranty of any kind. Jarvis may make mistakes — check important results yourself before acting on them (payments, messages sent on your behalf, documents). We are not liable for actions Jarvis takes on your instructions.</p>

<h2>Payments</h2>
<p>Paid plans are UPI-only: you pay, submit the 12-digit UTR, the admin verifies and approves, and the plan activates. No card details are collected. There is no auto-renewal — when a plan expires it downgrades to Free unless you pay again.</p>

<h2>Grievance Officer</h2>
<p>Not yet appointed — see the <a href="/privacy">Privacy Policy</a> for the placeholder and the Section 79 note.</p>

<h2>Changes</h2>
<p>These terms may change; the current version is always published here. Continued use after a change means you accept it.</p>`,
  );
}

export function refundPage(): string {
  return legalShell(
    "Refund Policy",
    `<h1>Refund Policy</h1>
<p class="muted">Last updated: 24 November 2026 · P.R. Digital Enterprises, India</p>

<h2>How refunds work</h2>
<p>Payments are UPI-only, and refunds are manual: the admin sends the refund from the admin UPI app and records it in the ledger (refund UTR, amount, reason). There is no automatic refund and no card chargeback path, because no card is ever charged.</p>

<h2>Full refund</h2>
<p>If a payment was approved by mistake, was duplicated, or the plan was never activated, you get a full refund to the same UPI ID you paid from. A full refund ends the subscription (it is marked expired).</p>

<h2>Partial refund</h2>
<p>If you used part of a plan period and then cancel, a partial refund may be given for the unused part, at the admin’s discretion. A partial refund keeps the subscription active until its current expiry.</p>

<h2>How to ask for a refund</h2>
<p>Email the admin from your registered email with: the plan, the amount, the 12-digit UTR of the original payment, and the reason. Refunds are processed within 7 working days of approval.</p>

<h2>What is not refunded</h2>
<p>Free plan: nothing was paid, nothing to refund. Usage already consumed (AI replies, server runs) is not refunded. A licence revoked for abuse (spam, reselling, breaking the service) is not refunded.</p>

<h2>Duplicate payments</h2>
<p>If you paid twice for the same plan, the second payment is refunded in full automatically once spotted (duplicate UTRs are rejected at submission, so this is rare).</p>`,
  );
}
