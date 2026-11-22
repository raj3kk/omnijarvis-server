---
title: OmniJarvis Render Worker
emoji: 🦉
colorFrom: blue
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
license: apache-2.0
short_description: OmniJarvis light Python worker — PDF extract, Tesseract OCR (eng+hin), WeasyPrint certificates, AST code scan.
tags:
- fastapi
- ocr
- pdf
---

# OmniJarvis Render Worker

Light Python worker for the OmniJarvis hub (Cloudflare Worker). No UI —
this Space is an API backend only. The hub calls it server-side; the
Space itself is public because the worker has no auth by design (same
posture as the Render plan it replaces). The auth boundary is the hub's
`/api/docs/*` routes (signed paired device, or `x-internal-secret`).

## Endpoints

| Route | What it does |
|---|---|
| `GET /health` | `{"ok": true, "service": "omnijarvis-render", "version": "3b"}` |
| `POST /smoke/pdf` | pdfplumber sample/upload extract (no file = built-in sample) |
| `POST /doc/ocr` | Tesseract OCR, image or PDF (5 MB, 10 pages, 30 s; `eng+hin`) |
| `POST /doc/extract` | PDF → pdfplumber text + tables (max 20 pages) |
| `POST /doc/certificate` | HTML → WeasyPrint PDF (300 DPI, A4) + segno QR + SHA-256 hash |
| `POST /doc/scan` | Python source → deterministic AST static scan (no LLM) |

Caps are enforced in `main.py`. No state lives here (ephemeral
filesystem; the Space sleeps after inactivity, like Render's free tier
— the hub retries once after 5 s and reports a `render_warming_up`
hint on cold start).

## Files

- `Dockerfile` — `python:3.12-slim`, tesseract (+Hindi), poppler,
  Devanagari fonts, WeasyPrint libs; runs as UID 1000 on `$PORT`.
- `main.py` — the worker (byte-identical copy of
  `render/worker/main.py` in the `omnijarvis-server` repo).
- `requirements.txt` — pinned FastAPI/uvicorn/pdfplumber/pytesseract/
  WeasyPrint 61 + pydyf 0.10.0 stack.

## Maintainer sync

`main.py` and `requirements.txt` are copies of `render/worker/` in the
`omnijarvis-server` repo. After any change to the canonical files,
re-copy them here and re-run `deploy.py` (it re-uploads and the Space
rebuilds). Never edit the Space copy in place without copying back —
the `render/worker/` copy is the source of truth.

## Deploy

Run `deploy.py` from this directory with `HF_TOKEN` in the
environment (a Hugging Face write token — never committed, never
printed). It creates/updates the Space, waits for the build, and
verifies every endpoint live. See `REPORT.md` in the completeness
work directory for the hub-side secret switch.
