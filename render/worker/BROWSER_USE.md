# Browser-Use — Pehle-Jaanch design note (Track D, item #18)

Date: 2026-11-22. Question: can Playwright + Chromium + browser-use run
in the HF Spaces free container (2 vCPU / 16 GB) alongside the existing
worker, and if so, what does the agent loop + safety model look like?

## Verdict: YES — with conditions (evidence below)

A minimal, gated `/browse/run` endpoint is implemented in `main.py`.
The full agent loop is live-unproven until the Track B HF deploy lands
(no hub router reachable from this VM, no Chromium here yet).

## Evidence

### 1. Host capacity (HF Spaces free, CPU Basic)
- Official HF docs (huggingface.co/docs/hub/spaces-overview, crawled
  ~2026-11-08): **2 vCPU, 16 GB RAM, 50 GB disk, free**.
- **OPEN RISK for Track B:** the same official page now says Docker
  Spaces "require a paid plan to create" and free accounts get "up to
  2 Gradio Spaces running on ZeroGPU". Community guides still describe
  free Docker CPU-Basic Spaces. Track B must verify at Space-creation
  time whether a Docker Space can be created on a free account; if it
  cannot, this worker cannot deploy there at all (Gradio SDK cannot
  host a FastAPI worker). This is a Track B blocker, not a Track D one.

### 2. Package sizes (measured 2026-11-22, PyPI wheels, this VM)
| component | size | note |
|---|---|---|
| browser-use 0.7.6 wheel | 0.37 MB | pure Python agent loop |
| playwright 1.55.0 wheel | 46 MB | Python driver only |
| Chromium (playwright `install chromium`) | ~150–170 MB download | to confirm with `playwright install --dry-run` on the deploy image; not yet measured here |
| Full `pip install browser-use` tree | not yet measured end-to-end | deps: langchain-core, pydantic, playwright, anyio, etc. — estimated 150–250 MB installed |

### 3. Runtime RAM (estimates — to be measured live on the deploy)
| process | RAM |
|---|---|
| worker base (FastAPI + pdfplumber + Tesseract) | ~110 MB peak (measured: smoke_check RSS_PEAK_MB=108.1) |
| headless Chromium, 1 tab | ~300–500 MB (standard headless figure) |
| browser-use agent loop | negligible (Python orchestration) |
| Docling model (only when a /doc/extract-docling call runs) | ~2–4 GB transient |
| **Total worst case, one job at a time** | **< 5 GB of 16 GB** |

The 16 GB ceiling is comfortable IF jobs are serialised: lazy imports
(already the pattern in main.py) + one browser run at a time (a
process-wide lock in the endpoint) + never load Docling and Chromium
in the same request. The old Render 512 MB host could never do this —
that is why this is HF-only, never Render.

### 4. CPU
2 vCPU is enough for a headless-Chromium agent loop (page load + DOM
snapshot + one LLM call per step). It will be slower than a desktop
(steps take seconds, not ms) — acceptable for the hub's agent tasks,
which are minutes-scale, not interactive.

## Agent loop (who calls the LLM)

```
hub (tenant request) -> worker POST /browse/run {tenant_id, task, url?, max_steps}
  -> gates (enabled? allowlisted URL? caps?) -> browser-use Agent
  -> per step: Agent -> router-backed chat model -> hub /api/llm/route
        (kind "agent_plan", x-internal-secret; hub owns keys/BYOK/caps)
     -> Playwright/Chromium acts (navigate/click/type/read)
  -> run ends: done / max_steps / needs_human / error
  -> worker returns {ok, status, steps[], final_text?, urls_visited[]}
```

- The worker holds **no LLM key**. The chat model is a small
  `BaseChatModel` subclass whose `_generate` POSTs to the hub router
  and returns the text as an `AIMessage`. Every agent step is therefore
  one metered, tenant-scoped router call — the hub can cap/refuse it
  like any other LLM call.
- `max_steps` default 10, hard cap 25. One run at a time (async lock);
  a second concurrent call gets 429 `browser_busy`.
- No state is kept between runs; the browser profile is a fresh
  ephemeral context per run (no cookies persist across runs).

## Safety gates (non-negotiable)

1. **Default OFF.** `BROWSER_USE_ENABLED=1` must be set in the deploy
   env; otherwise `/browse/run` returns 503 `browser_disabled`.
2. **URL allowlist.** `BROWSER_ALLOWLIST` (comma-separated hosts).
   Empty = deny all. Any navigation to a non-allowlisted host is
   refused (403 `url_not_allowed`); the agent is instructed to stay
   within the allowlisted host, and the run aborts if it leaves it.
3. **Credential vault: never in prompts.** No secret, password, OTP or
   key is ever passed to the agent, the browser, or the LLM prompt.
   The agent only navigates and reads public/logged-out pages. Login
   flows are out of scope for the agent.
4. **Human-assist-first (D3 rule stands, no auto-solve).** On any
   login wall, CAPTCHA, or human-verification challenge the run stops
   immediately with status `needs_human` and the step evidence; the
   worker never attempts to solve, bypass, or route around it.
5. **No spend, no writes.** No form submit that pays, orders, or
   changes account state; no file download outside the run temp dir;
   no execution of downloaded code.
6. **Audit, not content.** Logs carry {tenant_id, task hash, URLs
   visited, step count, status} — never page text, credentials, or PII.
7. **Caps.** Task ≤ 1000 chars, max_steps ≤ 25, per-run wall-clock
   timeout (default 300 s, enforced by the endpoint).

## What is NOT built (deliberately)
- No persistent browser profile / cookies across runs.
- No login automation, no 2FA handling, no CAPTCHA solving.
- No multi-tab / multi-run parallelism.
- No screenshots stored (only step text summaries in the response).

## Live-proof checklist (after Track B deploy)
1. `playwright install chromium` size + time on the deploy image.
2. One allowlisted run (e.g. read a docs page) end-to-end via the hub.
3. Peak RSS during a run (Chromium + worker) < 16 GB.
4. Negative tests: non-allowlisted URL -> 403; disabled flag -> 503;
   CAPTCHA/login page -> `needs_human`, no solve attempt.
