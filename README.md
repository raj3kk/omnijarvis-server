# OmniJarvis Server — Cloud Control Plane

**Repo:** `raj3kk/omnijarvis-server` (public). **App repo:** `raj3kk/jarvis-agent-app` (APK only — server code yahan nahi aata).

## Kya hai ye

OmniJarvis ka cloud control plane — free-tier, no card:

| Component | Tech | Free tier |
|---|---|---|
| Control-plane API + WS hub | Cloudflare Workers + Durable Objects (SQLite-backed, hibernation) | 100k req/day, 13,000 GB-s/day, 5 GB SQLite |
| Sync store (default) | Cloudflare D1 (`omnijarvis-db`) | 5M reads/day, 100k writes/day, 5 GB |
| Licence API host | Cloudflare Worker `jarvis-licence` (ALAG script — is repo me nahi; Phase 0 me bana) | Workers free |
| Cron dispatcher | GitHub Actions scheduled workflows (public repo = unlimited minutes), 5-min tick | Unlimited (public repo) |
| Rate limits | Upstash Redis | 500K commands/mo |
| Observability | Langfuse + Sentry | 50k traces/mo + 5k events/mo |
| Light Python worker | Render (ephemeral, stateless — pdfplumber + Tesseract + WeasyPrint + Mem0-lib only) | 512 MB / 750 hrs/mo |
| Vectors | Qdrant Cloud free | 1 GB RAM, ~1M vectors |

## Layout

```
src/hub.ts          # Worker entry: route dispatch
src/do/JarvisHub.ts # Durable Object: WS hibernation + presence + dispatch
src/pairing.ts      # pairing token / 6-digit / register
src/crypto.ts       # Ed25519 verify + nonce store
src/sync.ts         # D1 proxy + conflict rule (server-wins)
src/cron.ts         # tick handler + due-job selection + idempotency
src/ratelimit.ts    # Upstash Redis + budgets (in-memory fallback, flagged)
src/observability.ts# Langfuse + Sentry (env-gated, no keys = no-op)
d1/migrations/      # versioned D1 SQL (0001: devices/sync/traces/counters; 0002: tenants/jobs/skills + licences/patterns — Supabase port, 2026-11-21)
render/worker/      # light Python worker (health + smoke only in Phase 2)
.github/workflows/  # ci, dispatcher (5-min), keepalive-daily, keepalive-check
tests/              # vitest
```

## Rules (non-negotiable)

- **Free / no card** — koi spend, koi card kahin nahi.
- **Koi secret code/repo/logs me nahi** — repo PUBLIC hai. Keys sirf Worker secrets / CI secrets / 0600 env files me.
- **Koi `[skip ci]`** commit message me nahi.
- **D1 API token kabhi APK me nahi** — phone hamesha Workers proxy se baat karta hai. (Supabase fully removed 2026-11-21 — D1 is the only store.)
- **No plain `accept()` DO me** — hibernation API only (duration charge hota hai).
- **No Render Postgres / disk state** — Render ephemeral hai.
- **No auto global skill publish** — quarantine + human approval ke bina kabhi nahi.
- **No phone-only cron** — server dispatcher mandatory (Doze phone cron ko maar deta hai).

## Staging (Phase 2)

- **2a-1:** repo skeleton + health route + vitest + CI (ye commit).
- **2a-2:** control-plane Worker (pairing/sync/cron/keep-alive/health) + DO + D1 migrations v1 + vitest.
- **2a-3:** Supabase schemas v1 (tenants, scheduled_jobs, global_skills QUARANTINED-only) — versioned SQL + RLS. **SUPERSEDED 2026-11-21 by the D1 migration (D12 reframed): same tables now live in D1 migration 0002; Supabase project abandoned, `supabase/` deleted.**
- **2a-4:** cron dispatcher + keep-alive + Upstash rate limits + Langfuse/Sentry.
- **2a-5:** Render light Python worker (health/smoke only).
- **2b:** app 1.6.x — pairing UI + WS client + D1 sync client + licence URL switch.

## Run

```bash
npm install
npm test            # vitest
npx tsc --noEmit    # typecheck
npx wrangler dev    # local dev (needs wrangler login for DO/D1 bindings)
```

Deploy: Cloudflare Scripts API via stored credential (raw API, no wrangler login) — see `~/workspace/omnijarvis-implementation/jarvis-licence-worker/deploy_jarvis_licence_worker.py` pattern.

## Docs

- Plan: `~/workspace/omnijarvis-plan/plan-document.md` (Phase 2 §d)
- Pehle-Jaanch Phase 2: `~/workspace/omnijarvis-implementation/phase-2/PEHLE_JAANCH_PHASE2.md`
- Decisions: `~/workspace/omnijarvis-implementation/DECISIONS.md`
