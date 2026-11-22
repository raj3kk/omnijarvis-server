"""OmniJarvis Render light worker (Phase 3, stage 3b) — doc pipeline.

REWRITE (2026-11-22, DESIGN.md render-replacement/rewrite): pure-Python
stack, no system binaries — runs on Vercel Python serverless (Hobby).
Tesseract + poppler + WeasyPrint are GONE; same API contract kept.

Endpoints:
- GET /health -> {"ok": true, ...}
- POST /smoke/pdf -> pdfplumber sample/upload extract (2a-5, untouched).
- POST /doc/ocr -> RapidOCR (image PNG/JPG, or PDF page-by-page via
  pypdfium2 at 150 dpi). Caps: 4 MB, 10 pages, 30s. Response:
  {ok, pages, text, confidence} (per-box mean score x100; empty page ->
  confidence 0, text ""). per_page[].source: "rapidocr" (real OCR) /
  "text_layer" (embedded-text fallback).
- POST /doc/extract -> PDF -> pdfplumber text + tables, max 20 pages.
  Response: {ok, pages, text, tables}.
- POST /doc/certificate -> HTML -> xhtml2pdf PDF (A4) + segno QR (PNG
  data-URI; verification URL + SHA-256 hash of canonical payload).
  Caps: 2 MB HTML, 10 pages. Response: {ok, hash, pdf_base64, pages}.
- POST /doc/scan -> Python source -> AST static scan (deterministic,
  no LLM): dangerous patterns -> {ok, findings[]}. Bandit (Apache 2.0)
  runs alongside the AST scan; its issues are additive fields
  (`bandit_available`, `bandit_findings`) — `findings` stays AST-only
  so the hub's scanSkillCode contract is unchanged.
- POST /mem/extract -> text -> extracted memories (facts/preferences)
  as structured JSON. LLM/embeddings go through the hub router
  (/api/llm/route) when HUB_LLM_URL + INTERNAL_SECRET are set and the
  mem0 library is installed; otherwise a deterministic rule-based
  fallback extracts (engine field says which — never a fake mem0).
  No key is ever baked into the worker; mem0 Platform is never used.
- POST /doc/extract-docling -> PDF -> Docling layout+tables extraction
  (separate endpoint, not a flag on /doc/extract: different heavy dep,
  lazy import, different response shape, /doc/extract stays untouched).
  503 `docling_not_available` when the lib is not installed.
- POST /browse/run -> gated Browser-Use agent run (env-gated, URL
  allowlist, step cap; LLM via the hub router; see BROWSER_USE.md).
  503 `browser_not_available` when disabled or libs are missing.

OCR engine: ONE global lazily-loaded RapidOCR instance, created on the
FIRST /doc/ocr call only — never at import, never on /health. Models are
BUNDLED under render/worker/models/ (PP-OCRv5 det + Devanagari PP-OCRv5
rec + PP-OCRv5 cls + Devanagari dict) and passed as explicit local
paths — no download at runtime. The classifier is DISABLED
(Global.use_cls=False): the v5 cls model (trained for Chinese text
orientation) mis-rotates Devanagari crops and destroys Hindi reads
(verified 2026-11-22: "chalana"->"E2", "dhan'yavad"->"blbhh" with cls on;
both read at 1.00 with cls off). Docs here are upright; orientation
classification is not needed.

RAM discipline (Vercel 2 GB): one page / one doc at a time, 150 dpi
renders, pixmaps freed explicitly. No state on disk (in-memory BytesIO).
Heavy optional deps (docling, mem0ai, bandit, browser-use) are LAZY
imports inside their endpoints, so the base worker starts and serves
the original routes even when none of them is installed.
"""

import ast
import base64
import hashlib
import io
import json
import os
import re
import time
import urllib.request
from pathlib import Path

import pdfplumber
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(title="omnijarvis-render")
SERVICE = "omnijarvis-render"
VERSION = "3b"
MAX_PDF_BYTES = 4 * 1024 * 1024
MAX_PAGES = 20
MAX_OCR_BYTES = 4 * 1024 * 1024
MAX_OCR_PAGES = 10
MAX_OCR_SECONDS = 30
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_CERT_PAGES = 10
MAX_SCAN_BYTES = 512 * 1024
MAX_MEM_TEXT_CHARS = 8000
MAX_MEMORIES_PER_CALL = 20
# Hub router (memory.ts: worker /mem/extract -> hub /api/llm/route).
# Both env vars must be set for the mem0 path; unset -> rule fallback.
HUB_LLM_URL = os.environ.get("HUB_LLM_URL", "").rstrip("/")
INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "")
# Browser-Use (see BROWSER_USE.md): default OFF; allowlist empty = deny all.
BROWSER_USE_ENABLED = os.environ.get("BROWSER_USE_ENABLED", "") == "1"
BROWSER_ALLOWLIST = {
    h.strip().lower()
    for h in os.environ.get("BROWSER_ALLOWLIST", "").split(",")
    if h.strip()
}
MAX_BROWSE_STEPS = 25
MAX_BROWSE_TASK_CHARS = 1000

_WORKER_DIR = Path(__file__).resolve().parent
_MODELS_DIR = _WORKER_DIR / "models"
_FONTS_DIR = _WORKER_DIR / "fonts"
# 150 dpi: A4 -> ~1240x1754 px; one benchmark measured 548 MB peak for a
# single A4 @300 dpi under RapidOCR, so 300 dpi is not used.
_OCR_DPI = 150

_OCR_ENGINE = None


def sample_pdf_bytes() -> bytes:
    """Minimal valid 1-page PDF ("Hello OmniJarvis"), built in-memory with
    a correct xref table (offsets computed, not hand-written)."""
    stream = b"BT /F1 24 Tf 100 700 Td (Hello OmniJarvis) Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def extract(pdf_bytes: bytes) -> dict:
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        pages = pdf.pages[:MAX_PAGES]
        text = "\n".join((p.extract_text() or "") for p in pages)
    return {"pages": len(pages), "chars": len(text), "text_preview": text[:500]}


def _get_ocr_engine():
    """Lazily create the single global RapidOCR engine (first OCR call
    only). Explicit bundled model paths — rapidocr>=3.10 downloads a
    model ONLY when model_path is None, so this never touches the
    network at request time. PP-OCRv5 det + PP-OCRv5 Devanagari rec,
    never mixed versions. Enum-typed params are required by
    rapidocr 3.10 (plain strings raise TypeError)."""
    global _OCR_ENGINE
    if _OCR_ENGINE is not None:
        return _OCR_ENGINE
    from rapidocr import (
        EngineType,
        LangCls,
        LangDet,
        LangRec,
        ModelType,
        OCRVersion,
        RapidOCR,
    )

    models = _MODELS_DIR
    det = models / "ch_PP-OCRv5_det_mobile.onnx"
    rec = models / "devanagari_PP-OCRv5_rec_mobile.onnx"
    cls = models / "ch_PP-LCNet_x0_25_textline_ori_cls_mobile.onnx"
    rec_keys = models / "ppocrv5_devanagari_dict.txt"
    for p in (det, rec, cls, rec_keys):
        if not p.is_file():
            raise FileNotFoundError(f"bundled OCR model missing: {p}")
    _OCR_ENGINE = RapidOCR(
        params={
            "Global.log_level": "warning",
            # Classifier OFF: the v5 cls model mis-rotates Devanagari
            # crops (see module docstring) — upright docs don't need it.
            "Global.use_cls": False,
            "Det.engine_type": EngineType.ONNXRUNTIME,
            "Det.ocr_version": OCRVersion.PPOCRV5,
            "Det.model_type": ModelType.MOBILE,
            "Det.lang_type": LangDet.MULTI,
            "Det.model_path": str(det),
            "Cls.engine_type": EngineType.ONNXRUNTIME,
            "Cls.ocr_version": OCRVersion.PPOCRV5,
            "Cls.model_type": ModelType.MOBILE,
            "Cls.lang_type": LangCls.CH,
            "Cls.model_path": str(cls),
            "Rec.engine_type": EngineType.ONNXRUNTIME,
            "Rec.ocr_version": OCRVersion.PPOCRV5,
            "Rec.model_type": ModelType.MOBILE,
            "Rec.lang_type": LangRec.DEVANAGARI,
            "Rec.model_path": str(rec),
            # ONNX models carry an inner character list, so the dict is
            # a belt-and-braces explicit path (never downloaded).
            "Rec.rec_keys_path": str(rec_keys),
        }
    )
    return _OCR_ENGINE


def _ocr_image_bytes(img_bytes: bytes) -> tuple[str, float]:
    """OCR one image (bytes) -> (text, mean box score 0-100).
    Empty image -> ("", 0). RapidOCR returns per-box scores 0-1."""
    import numpy as np
    from PIL import Image

    img = Image.open(io.BytesIO(img_bytes))
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    # Bound memory on huge uploads: RapidOCR downscales to max side
    # 2000 internally, but cap here first so the numpy array stays small.
    max_side = max(img.size)
    if max_side > 2000:
        scale = 2000 / max_side
        img = img.resize(
            (max(1, int(img.width * scale)), max(1, int(img.height * scale))),
            Image.LANCZOS,
        )
    out = _get_ocr_engine()(np.array(img))
    txts = out.txts or ()
    scores = out.scores or ()
    text = "\n".join(txts)
    conf = round(sum(scores) / len(scores) * 100, 2) if scores else 0.0
    return text, conf


def _ocr_pdf_page_with_pypdfium2(pdf_bytes: bytes, page_index: int) -> tuple[str, float] | None:
    """Render one PDF page to PNG with pypdfium2 (in-process, no poppler)
    at 150 dpi and OCR it. Returns None when the page fails to render —
    caller falls back to the embedded text layer (honest `source` field
    in the response)."""
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(io.BytesIO(pdf_bytes))
    try:
        page = doc[page_index]
        try:
            bitmap = page.render(scale=_OCR_DPI / 72)
            try:
                pil_img = bitmap.to_pil()
                buf = io.BytesIO()
                pil_img.save(buf, format="PNG")
                return _ocr_image_bytes(buf.getvalue())
            finally:
                bitmap.close()
        finally:
            page.close()
    except Exception:
        return None
    finally:
        doc.close()
    return None


@app.get("/health")
def health() -> dict:
    return {"ok": True, "service": SERVICE, "version": VERSION}


@app.post("/smoke/pdf")
async def smoke_pdf(file: UploadFile | None = File(default=None)):
    if file is None:
        data = sample_pdf_bytes()
        source = "sample"
    else:
        data = await file.read()
        source = "upload"
        if len(data) > MAX_PDF_BYTES:
            return JSONResponse({"ok": False, "error": "pdf_too_large"}, status_code=413)
    try:
        result = extract(data)
    except Exception as exc:  # noqa: BLE001 — smoke endpoint: report, don't crash
        return JSONResponse(
            {"ok": False, "error": "pdf_parse_failed", "detail": str(exc)[:200]},
            status_code=422,
        )
    return {"ok": True, "source": source, **result}


@app.post("/doc/ocr")
async def doc_ocr(file: UploadFile = File(...)):
    """RapidOCR: image (PNG/JPG) upload, or PDF (page-by-page).
    Caps: 4 MB, 10 pages, 30s wall-clock.
    Response: {ok, pages, text, confidence, per_page}."""
    started = time.monotonic()
    data = await file.read()
    if len(data) > MAX_OCR_BYTES:
        return JSONResponse({"ok": False, "error": "file_too_large"}, status_code=413)
    name = (file.filename or "").lower()
    try:
        if name.endswith(".pdf") or data[:4] == b"%PDF":
            # PDF: one page at a time — pypdfium2 render + real RapidOCR;
            # a page that fails to render falls back to the embedded text
            # layer (source field me saaf likha — silent empty text
            # kabhi nahi).
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                pages = pdf.pages[:MAX_OCR_PAGES]
                texts: list[str] = []
                per_page: list[dict] = []
                for idx, p in enumerate(pages):
                    if time.monotonic() - started > MAX_OCR_SECONDS:
                        return JSONResponse(
                            {"ok": False, "error": "ocr_timeout"}, status_code=504
                        )
                    rendered = _ocr_pdf_page_with_pypdfium2(data, idx)
                    if rendered is not None:
                        t, c = rendered
                        texts.append(t)
                        per_page.append(
                            {"page": idx + 1, "confidence": c, "source": "rapidocr"}
                        )
                    else:
                        t = p.extract_text() or ""
                        texts.append(t)
                        per_page.append(
                            {"page": idx + 1, "confidence": 100.0 if t else 0.0,
                             "source": "text_layer"}
                        )
            text = "\n".join(texts)
            conf = (
                round(sum(p["confidence"] for p in per_page) / len(per_page), 2)
                if per_page
                else 0.0
            )
            return {
                "ok": True,
                "pages": len(per_page),
                "text": text,
                "confidence": conf,
                "per_page": per_page,
            }
        # Image path: real RapidOCR.
        text, conf = _ocr_image_bytes(data)
        if time.monotonic() - started > MAX_OCR_SECONDS:
            return JSONResponse({"ok": False, "error": "ocr_timeout"}, status_code=504)
        return {
            "ok": True,
            "pages": 1,
            "text": text,
            "confidence": conf,
            "per_page": [{"page": 1, "confidence": conf, "source": "rapidocr"}],
        }
    except Exception as exc:  # noqa: BLE001 — report, don't crash
        return JSONResponse(
            {"ok": False, "error": "ocr_failed", "detail": str(exc)[:200]},
            status_code=422,
        )


@app.post("/doc/extract")
async def doc_extract(file: UploadFile = File(...)):
    """PDF -> pdfplumber text + tables, max 20 pages.
    Response: {ok, pages, text, tables} (tables = per-page row lists)."""
    data = await file.read()
    if len(data) > MAX_PDF_BYTES:
        return JSONResponse({"ok": False, "error": "pdf_too_large"}, status_code=413)
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            pages = pdf.pages[:MAX_PAGES]
            texts: list[str] = []
            tables: list[dict] = []
            for i, p in enumerate(pages, start=1):
                texts.append(p.extract_text() or "")
                try:
                    raw_tables = p.extract_tables() or []
                except Exception:
                    raw_tables = []
                tables.append({"page": i, "tables": raw_tables})
        return {
            "ok": True,
            "pages": len(pages),
            "text": "\n".join(texts),
            "tables": tables,
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"ok": False, "error": "pdf_parse_failed", "detail": str(exc)[:200]},
            status_code=422,
        )


def canonical_payload(payload: dict) -> str:
    """Canonical JSON for hashing: sorted keys, compact separators."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _cert_font_path() -> Path:
    """Bundled Noto Sans Devanagari (OFL) for certificates. Raises if the
    file is missing — a silent Helvetica fallback would render every
    Devanagari char as 'n' (verified 2026-11-22), so fail loudly."""
    path = _FONTS_DIR / "NotoSansDevanagari-Regular.ttf"
    if not path.is_file():
        raise FileNotFoundError(f"bundled certificate font missing: {path}")
    return path


@app.post("/doc/certificate")
async def doc_certificate(
    html: str = Form(...),
    payload: str = Form(default="{}"),
    verify_url: str = Form(default=""),
):
    """HTML -> xhtml2pdf PDF (A4) + segno QR (PNG data-URI).
    hash = SHA-256 of canonical payload JSON. Caps: 2 MB HTML, 10 pages.
    Response: {ok, hash, pdf_base64, pages, bytes}."""
    html_bytes = html.encode("utf-8")
    if len(html_bytes) > MAX_HTML_BYTES:
        return JSONResponse({"ok": False, "error": "html_too_large"}, status_code=413)
    try:
        payload_obj = json.loads(payload) if payload else {}
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_payload"}, status_code=400)
    if not isinstance(payload_obj, dict):
        return JSONResponse({"ok": False, "error": "bad_payload"}, status_code=400)
    digest = hashlib.sha256(canonical_payload(payload_obj).encode("utf-8")).hexdigest()
    try:
        import segno
        from xhtml2pdf import pisa

        _cert_font_path()
        qr_target = f"{verify_url}?hash={digest}" if verify_url else digest
        qr = segno.make(qr_target, error="m")
        qr_png = io.BytesIO()
        qr.save(qr_png, kind="png", scale=4, border=1)
        qr_b64 = base64.b64encode(qr_png.getvalue()).decode("ascii")
        html_with_qr = html.replace(
            "{{QR}}",
            f'<img src="data:image/png;base64,{qr_b64}" alt="verification QR" />',
        )
        # Default body font = bundled Devanagari font (covers Latin too)
        # so Hindi names render even when the hub HTML names no font.
        # A <style> the caller supplies wins over this prelude (it comes
        # later in the document) — their explicit choice is respected.
        # The font MUST come via @font-face with a path relative to the
        # fonts dir (passed as pisa's `path`): a global
        # pdfmetrics.registerFont is invisible to xhtml2pdf's per-document
        # fontList, and an absolute src is denied by xhtml2pdf 0.2.28's
        # resource policy (reads escaping the document dir are blocked).
        # The <meta charset> is REQUIRED: without it html5lib sniffs the
        # UTF-8 bytes as windows-1252 and every Devanagari char becomes
        # latin-1 mojibake before any font is consulted (verified
        # 2026-11-22: 'प्रमाण पत्र' rendered as 'à¤ªà¥...').
        # reportlab has no HarfBuzz shaping — Devanagari conjuncts may
        # shape imperfectly; measured, not claimed (see LOCAL_VERIFY.md).
        style_prelude = (
            "<style>"
            "@font-face { font-family: NotoSansDevanagari; "
            "src: url(NotoSansDevanagari-Regular.ttf); }"
            "* { font-family: NotoSansDevanagari, Helvetica, sans-serif; }"
            "</style>"
        )
        meta_charset = '<meta charset="utf-8" />'
        html_with_meta = html_with_qr
        lower = html_with_meta.lower()
        head_at = lower.find("<head>")
        if head_at != -1:
            html_with_meta = (
                html_with_meta[: head_at + len("<head>")]
                + meta_charset
                + html_with_meta[head_at + len("<head>") :]
            )
        elif "<html>" in lower:
            html_at = lower.find("<html>") + len("<html>")
            html_with_meta = (
                html_with_meta[:html_at]
                + "<head>" + meta_charset + "</head>"
                + html_with_meta[html_at:]
            )
        else:
            html_with_meta = "<head>" + meta_charset + "</head>" + html_with_meta
        html_final = style_prelude + html_with_meta
        pdf_buf = io.BytesIO()
        status = pisa.CreatePDF(
            io.BytesIO(html_final.encode("utf-8")),
            dest=pdf_buf,
            # Document base = fonts dir, so the relative @font-face src
            # above resolves inside it (see comment at style_prelude).
            path=str(_FONTS_DIR / "index.html"),
        )
        if status.err:
            raise RuntimeError(f"xhtml2pdf render failed (err={status.err})")
        pdf_bytes = pdf_buf.getvalue()
        if pdf_bytes[:4] != b"%PDF":
            raise RuntimeError("xhtml2pdf did not produce a PDF")
        # Page count: count "/Type /Page" markers (not /Pages).
        pages = pdf_bytes.count(b"/Type /Page") - pdf_bytes.count(b"/Type /Pages")
        pages = max(pages, 1)
        if pages > MAX_CERT_PAGES:
            return JSONResponse({"ok": False, "error": "too_many_pages"}, status_code=413)
        return {
            "ok": True,
            "hash": digest,
            "pdf_base64": base64.b64encode(pdf_bytes).decode("ascii"),
            "pages": pages,
            "bytes": len(pdf_bytes),
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"ok": False, "error": "certificate_failed", "detail": str(exc)[:200]},
            status_code=422,
        )


# --- Mem0 extraction (item #28; mem0 library only, never Platform) ---
# Design (memory.ts + hub /api/llm/route): mem0's DEFAULT config needs an
# OpenAI key (gpt-4o-mini + text-embedding-ada-002), so the worker NEVER
# uses the default. Instead the mem0 Memory object's .llm, .embedding_model
# and .vector_store are swapped for adapters that POST to the hub router
# (x-internal-secret) or keep nothing (null store); the hub owns keys,
# BYOK checks, caps and metering, and persists into D1. No key is baked
# into the worker, no secret is ever logged, and mem0 telemetry is off
# (MEM0_TELEMETRY=false). When the router is not configured (or mem0 is
# not installed) the endpoint still answers via a deterministic rule-based
# extractor — engine field says which.

MEM_EXTRACT_SYSTEM = (
    "Extract durable memories from the user's message as a JSON object "
    '{"facts": ["..."]}. Keep only stable facts and preferences (name, '
    "likes, goals, constraints, contact details the user stated). Drop "
    "greetings, one-off questions and anything already implied. Short "
    "strings, one fact per item."
)
# NOTE: mem0 parses json.loads(response)["facts"] and uses each fact as a
# DICT KEY (new_message_embeddings[new_mem]) — facts MUST be plain
# strings, not {content, kind} objects, or add() dies with
# "unhashable type: 'dict'". Kinds are therefore not produced by the
# mem0 path (all memories are kind "fact"); the rule fallback keeps
# its own fact/preference split.
MEM_EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "facts": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["facts"],
}
MEM_ACTIONS_SCHEMA = {
    "type": "object",
    "properties": {
        "memory": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "text": {"type": "string"},
                    "event": {"type": "string"},
                    "old_memory": {"type": "string"},
                },
                "required": ["text", "event"],
            },
        },
    },
    "required": ["memory"],
}


def _router_post(payload: dict, timeout: int = 60) -> dict:
    """POST one call to the hub router. Raises on any failure — the
    caller turns it into an honest error, never a fake extraction."""
    req = urllib.request.Request(
        HUB_LLM_URL + "/api/llm/route",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-internal-secret": INTERNAL_SECRET,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _mem0_router_adapters(tenant_id: str, turn_id: str):
    """Build mem0-compatible adapters backed by the hub router.

    mem0 calls .llm.generate_response(messages, response_format=...) twice
    per add(): (1) fact extraction — user prompt starts with "Input:";
    (2) update-memory actions — prompt mentions "new retrieved facts".
    The response_schema sent to the router matches the call: facts schema
    for (1), actions schema for (2). Embeddings go through kind
    "embeddings". Returns (llm, embedder, vector_store) where the vector
    store is an in-memory null store — the worker stores nothing; the
    hub persists extracted memories into D1 (memory.ts storeMemory).
    """
    from mem0.embeddings.base import EmbeddingBase
    from mem0.llms.base import LLMBase
    from mem0.vector_stores.base import VectorStoreBase

    class RouterLlm(LLMBase):
        def __init__(self):
            super().__init__(config={"model": "hub-router", "api_key": "not-used-hub-router"})

        def generate_response(self, messages, tools=None, tool_choice="auto", **kwargs) -> str:
            # mem0 sends [system, user]; detect the call type from the
            # USER message only (the system prompt precedes it).
            # 1.x: fact extraction user prompt starts with "Input:";
            #      update-memory prompt mentions "new retrieved facts".
            # 2.x (V3 pipeline): ONE additive-extraction call whose user
            #      prompt has "## New Messages" sections; it parses
            #      {"memory": [{"text": ...}]}.
            user_texts = [str(m.get("content", "")) for m in messages if m.get("role") == "user"]
            last_user = user_texts[-1] if user_texts else ""
            if "## New Messages" in last_user:
                schema: dict | None = MEM_ACTIONS_SCHEMA
            elif last_user.lstrip().startswith("Input:"):
                schema = MEM_EXTRACT_SCHEMA
            elif "new retrieved facts are mentioned" in last_user:
                schema = MEM_ACTIONS_SCHEMA
            else:
                schema = None
            payload = {
                "tenant_id": tenant_id,
                "turn_id": turn_id,
                "kind": "doc_extraction",
                "messages": [
                    {"role": m.get("role", "user"), "text": m.get("content", "")}
                    for m in messages
                ],
                "system": MEM_EXTRACT_SYSTEM,
            }
            if schema is not None:
                payload["response_schema"] = schema
            result = _router_post(payload, timeout=120)
            if not result.get("ok"):
                raise RuntimeError("router: " + str(result.get("error", "upstream_error"))[:100])
            text = result.get("text") or ""
            if not text and isinstance(result.get("response"), dict):
                text = json.dumps(result["response"], ensure_ascii=False)
            return text

    class RouterEmbedder(EmbeddingBase):
        def embed(self, text, memory_action=None) -> list:
            result = _router_post(
                {
                    "tenant_id": tenant_id,
                    "turn_id": turn_id,
                    "kind": "embeddings",
                    "messages": [{"role": "user", "text": text}],
                }
            )
            if not result.get("ok") or not result.get("embedding"):
                raise RuntimeError("router embedding: " + str(result.get("error", "failed"))[:100])
            return list(result["embedding"])

    class NullVectorStore(VectorStoreBase):
        """In-memory no-persistence store: search always empty (so every
        fact is an ADD), insert/get keep rows in a dict for the call."""

        def __init__(self):
            self._rows: dict[str, dict] = {}

        def create_col(self, name, vector_size, distance):
            return None

        def insert(self, vectors, payloads=None, ids=None):
            ids = ids or []
            for i, mid in enumerate(ids):
                self._rows[mid] = (payloads or [{}])[i] if payloads else {}
            return ids

        def search(self, query, vectors, limit=5, top_k=None, filters=None, **_kw):
            # mem0 1.x calls search(..., limit=5); 2.x calls
            # search(..., top_k=5). Accept both; always empty (ADD-only).
            return []

        def search_batch(self, queries, vectors_list, top_k=1, filters=None, **_kw):
            return [[] for _ in (queries or [])]

        def delete(self, vector_id):
            self._rows.pop(vector_id, None)

        def update(self, vector_id, vector=None, payload=None):
            if payload is not None:
                self._rows[vector_id] = payload

        def get(self, vector_id):
            payload = self._rows.get(vector_id)
            if payload is None:
                return None

            class _Row:
                pass

            row = _Row()
            row.id = vector_id
            row.payload = payload
            return row

        def list_cols(self):
            return []

        def delete_col(self):
            self._rows.clear()

        def col_info(self):
            return {"name": "null-store", "count": len(self._rows)}

        def reset(self):
            self._rows.clear()

        def list(self, filters=None, limit=100, top_k=None, **_kw):
            return []

    return RouterLlm(), RouterEmbedder(), NullVectorStore()


# Deterministic rule fallback: no LLM, no key, no library. Patterns are
# deliberately narrow (high precision, low recall) — a missed fact is
# honest; a hallucinated one is not.
_RULE_PATTERNS = [
    (re.compile(r"\bmy name is ([A-Z][\w ]{1,60})", re.I), "fact"),
    (re.compile(r"\bi (?:like|love|prefer|enjoy) ([^.;\n]{3,120})", re.I), "preference"),
    (re.compile(r"\bmy (?:favourite|favorite) ([^.;\n]{3,120})", re.I), "preference"),
    (re.compile(r"\bmy ([a-z][a-z ]{1,40}?) is ([^.;\n]{2,120})", re.I), "fact"),
    (re.compile(r"\bi (?:am|live in|work as|work at|study) ([^.;\n]{3,120})", re.I), "fact"),
    (re.compile(r"\bi want (?:to )?([^.;\n]{3,120})", re.I), "preference"),
    (re.compile(r"\bplease (?:remember|note) (?:that )?([^.;\n]{3,160})", re.I), "fact"),
]


def _rule_extract_memories(text: str) -> list[dict]:
    """Rule-based extraction. Returns [{content, kind}] deduped."""
    seen: set[str] = set()
    out: list[dict] = []
    for pattern, kind in _RULE_PATTERNS:
        for m in pattern.finditer(text):
            groups = [g.strip(" .") for g in m.groups() if g]
            # "my name is X" is covered by the dedicated name pattern;
            # skip the generic "my <key> is <value>" duplicate for it.
            if len(groups) == 2 and groups[0].lower() == "name":
                continue
            content = " ".join(groups)
            content = re.sub(r"\s+", " ", content).strip()
            # Skip sentence-fragment captures ("I prefer ..." from the
            # "please remember" pattern) — keep noun-phrase facts only.
            if len(content) < 3 or len(content) > 200 or content.lower().startswith("i "):
                continue
            key = content.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append({"content": content, "kind": kind})
            if len(out) >= MAX_MEMORIES_PER_CALL:
                return out
    return out


def _mem0_extract(text: str, tenant_id: str, turn_id: str, user_id: str,
                  metadata: dict) -> tuple[list[dict], str]:
    """mem0-library extraction via hub-router adapters. Returns
    (memories, engine). Raises RuntimeError on any failure — the caller
    reports it, never silently downgrades a mem0 claim to rules.

    Construction notes (verified against mem0ai 1.0.4 AND 2.2.1 source;
    the adapter works on both — see _mem0_router_adapters):
    - Memory.__init__ builds a real OpenAI LLM/embedder + Qdrant store
      from the config, so dummy placeholders are given — but .llm,
      .embedding_model and .vector_store are ALL swapped before add(),
      so no OpenAI/Qdrant call is ever made and no key exists.
    - The placeholder OpenAI client is constructed by mem0 even though
      it is never called — and its constructor parses the process proxy
      env vars (HTTP_PROXY etc. AND no_proxy) via httpx. Sandbox/egress
      values can hold entries httpx cannot parse (here: IPv6 literals
      in no_proxy → "Invalid port: ':1]'"), so ALL proxy vars are
      scrubbed around from_config only, then restored.
    - Telemetry is OFF (MEM0_TELEMETRY=false set before the import;
      mem0 ships PostHog + a telemetry vector store otherwise).
    - history_db_path points at a temp dir: the worker keeps no state
      (the hub persists into D1); the temp dir is deleted after add().
    - The null vector store makes every fact an ADD (search is empty);
      the hub owns dedup/persistence downstream."""
    import tempfile

    os.environ.setdefault("MEM0_TELEMETRY", "false")
    from mem0 import Memory  # lazy: base worker works without mem0ai

    _PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                   "http_proxy", "https_proxy", "all_proxy", "no_proxy")
    with tempfile.TemporaryDirectory() as td:
        config = {
            "llm": {"provider": "openai", "config": {"model": "gpt-4o-mini", "api_key": "not-used-hub-router"}},
            "embedder": {"provider": "openai", "config": {"model": "text-embedding-3-small", "api_key": "not-used-hub-router"}},
            "vector_store": {"provider": "qdrant", "config": {"collection_name": "unused", "path": td}},
            "history_db_path": os.path.join(td, "history.db"),
        }
        saved_proxies = {k: os.environ.pop(k) for k in _PROXY_VARS if k in os.environ}
        try:
            mem = Memory.from_config(config)
        finally:
            os.environ.update(saved_proxies)
        llm, embedder, store = _mem0_router_adapters(tenant_id, turn_id)
        mem.llm = llm
        mem.embedding_model = embedder
        mem.vector_store = store
        result = mem.add(
            messages=[{"role": "user", "content": text}],
            user_id=user_id,
            metadata={**metadata, "tenant_id": tenant_id},
        )
    memories: list[dict] = []
    # 1.x returns {"results": [{memory, event}]}; 2.x returns the list
    # directly ([{id, memory, event}]). Accept both.
    if isinstance(result, list):
        rows = result
    elif isinstance(result, dict):
        rows = (result or {}).get("results", []) or []
    else:
        rows = []
    for row in rows:
        content = (row or {}).get("memory", "")
        if not content:
            continue
        memories.append({"content": content, "kind": "fact", "event": (row or {}).get("event", "ADD")})
    return memories[:MAX_MEMORIES_PER_CALL], "mem0+hub-router"


@app.post("/mem/extract")
async def mem_extract(request: Request):
    """Text -> extracted memories. Body JSON: {tenant_id, text,
    user_id?, metadata?, turn_id?}. Response: {ok, memories[], engine,
    model, count}. engine is `mem0+hub-router` when the mem0 library
    ran with the hub router, else `rule_fallback` (deterministic, no
    LLM). The worker stores nothing — the hub persists into D1."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "bad_json"}, status_code=400)
    tenant_id = body.get("tenant_id") or ""
    text = body.get("text") or ""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return JSONResponse({"ok": False, "error": "tenant_id_required"}, status_code=400)
    if not isinstance(text, str) or not text.strip():
        return JSONResponse({"ok": False, "error": "text_required"}, status_code=400)
    if len(text) > MAX_MEM_TEXT_CHARS:
        return JSONResponse({"ok": False, "error": "text_too_long"}, status_code=413)
    user_id = body.get("user_id") or tenant_id
    if not isinstance(user_id, str):
        user_id = tenant_id
    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        return JSONResponse({"ok": False, "error": "bad_metadata"}, status_code=400)
    turn_id = body.get("turn_id") or f"mem-{int(time.time())}"
    if not isinstance(turn_id, str):
        turn_id = f"mem-{int(time.time())}"
    router_ready = bool(HUB_LLM_URL and INTERNAL_SECRET)
    if router_ready:
        try:
            memories, engine = _mem0_extract(text, tenant_id.strip(), turn_id, user_id, metadata)
            return {
                "ok": True,
                "memories": memories,
                "engine": engine,
                "model": "hub-router/doc_extraction (+gemini-embedding-001)",
                "count": len(memories),
            }
        except Exception as exc:  # noqa: BLE001 — honest error, no silent fallback
            return JSONResponse(
                {"ok": False, "error": "mem_extract_failed", "detail": str(exc)[:200]},
                status_code=502,
            )
    reason = "router_not_configured" if not router_ready else "mem0_unavailable"
    memories = _rule_extract_memories(text)
    return {
        "ok": True,
        "memories": memories,
        "engine": "rule_fallback",
        "model": "rule_fallback (no LLM call made)",
        "count": len(memories),
        "note": reason + ": extraction ran without mem0/router; hub must set HUB_LLM_URL + INTERNAL_SECRET for the mem0 path",
    }


# --- Docling extraction (item #10) ---
# DECISION: separate endpoint POST /doc/extract-docling, NOT engine=docling
# on /doc/extract. Reasons: (1) /doc/extract is a live hub contract
# (hub.ts:622 forwards PDFs there) — a flag would change its response
# shape/timing for existing callers; (2) docling is a heavy optional
# dep (torch stack) with its own caps and 503-when-absent behaviour;
# (3) the response differs (layout blocks + table cell grids + markdown),
# not just "better text". The hub can route table-heavy PDFs here.

MAX_DOCLING_BYTES = 5 * 1024 * 1024
MAX_DOCLING_PAGES = 20
MAX_DOCLING_SECONDS = 120


import threading as _threading

_DOCLING_CONVERTER = None
# RLock (not Lock): _docling_extract holds it while _docling_converter
# re-acquires it on first creation — a plain Lock deadlocks here.
_DOCLING_LOCK = _threading.RLock()


def _docling_converter():
    """Module-level cached DocumentConverter (lazy singleton).

    Measured 2026-11-22: a FRESH DocumentConverter per call leaks
    ~150 MB/call in-process (current RSS 943 -> 1103 -> 1255 MB over
    3 identical converts; gc.collect() does not reclaim it) AND costs
    ~6 s of model reload per call. The singleton loads models once
    (first call ~20 s warm, ~260 s cold when models download) and
    holds ~1.1 GB steady. _DOCLING_LOCK serialises converts (the
    converter is not safe for concurrent use). Deploy note: Track B
    should warm this converter once during the Docker build so the
    layout/OCR models are baked into the image — otherwise the FIRST
    user call pays the ~260 s model download."""
    global _DOCLING_CONVERTER
    if _DOCLING_CONVERTER is None:
        from docling.document_converter import DocumentConverter

        with _DOCLING_LOCK:
            if _DOCLING_CONVERTER is None:
                _DOCLING_CONVERTER = DocumentConverter()
    return _DOCLING_CONVERTER


def _docling_extract(pdf_bytes: bytes) -> dict:
    """Docling convert (lazy import). Returns {pages, text, markdown,
    tables, timings}. Raises on failure — caller maps to 422/503."""
    import tempfile

    started = time.monotonic()
    with tempfile.TemporaryDirectory() as td:
        import os as _os

        src = _os.path.join(td, "doc.pdf")
        with open(src, "wb") as f:
            f.write(pdf_bytes)
        with _DOCLING_LOCK:
            converter = _docling_converter()
            result = converter.convert(src)
        convert_s = round(time.monotonic() - started, 2)
        doc = result.document
        text = doc.export_to_text()
        try:
            markdown = doc.export_to_markdown()
        except Exception:
            markdown = ""
        tables: list[dict] = []
        for t in doc.tables or []:
            try:
                grid = [[c.text for c in row] for row in t.data.grid]
            except Exception:
                grid = []
            page_no = None
            try:
                prov = getattr(t, "prov", None) or []
                first = prov[0] if prov else None
                if isinstance(first, dict):
                    page_no = first.get("page_no")
                elif first is not None:
                    page_no = getattr(first, "page_no", None)
            except Exception:
                page_no = None
            tables.append({"page": page_no, "rows": grid})
        pages = len(doc.pages) if getattr(doc, "pages", None) else 0
    total_s = round(time.monotonic() - started, 2)
    return {
        "pages": pages,
        "text": text,
        "markdown": markdown,
        "tables": tables,
        "timings": {"convert_s": convert_s, "total_s": total_s},
    }


@app.post("/doc/extract-docling")
async def doc_extract_docling(file: UploadFile = File(...)):
    """PDF -> Docling layout+tables. Caps: 5 MB, 20 pages, 120s.
    Response: {ok, engine, pages, text, markdown, tables, timings}.
    503 docling_not_available when the lib is not installed."""
    data = await file.read()
    if len(data) > MAX_DOCLING_BYTES:
        return JSONResponse({"ok": False, "error": "pdf_too_large"}, status_code=413)
    try:
        result = _docling_extract(data)
    except ImportError:
        return JSONResponse({"ok": False, "error": "docling_not_available"}, status_code=503)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(
            {"ok": False, "error": "docling_failed", "detail": str(exc)[:200]},
            status_code=422,
        )
    return {"ok": True, "engine": "docling", **result}


# --- AST static scan (3d skill registry reuses this; deterministic, no LLM) ---

DANGEROUS_CALLS = {
    "os.system": "os.system shell execution",
    "os.popen": "os.popen shell execution",
    "os.execv": "os.exec* process replacement",
    "os.execl": "os.exec* process replacement",
    "os.execve": "os.exec* process replacement",
    "os.execvp": "os.exec* process replacement",
    "subprocess.call": "subprocess shell/process spawn",
    "subprocess.Popen": "subprocess shell/process spawn",
    "subprocess.run": "subprocess shell/process spawn",
    "subprocess.check_output": "subprocess shell/process spawn",
    "eval": "eval dynamic code execution",
    "exec": "exec dynamic code execution",
    "__import__": "__import__ dynamic import",
    "compile": "compile dynamic code execution",
    "socket.socket": "raw socket (exfil channel)",
    "requests.get": "requests network call (exfil channel)",
    "requests.post": "requests network call (exfil channel)",
    "requests.put": "requests network call (exfil channel)",
    "requests.delete": "requests network call (exfil channel)",
    "urllib.request.urlopen": "urllib network call (exfil channel)",
    "open": "file open (checked for writes outside sandbox)",
}

WRITE_FUNCS = {"open", "os.open", "pathlib.Path.write_text", "pathlib.Path.write_bytes"}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted(node.value) + "." + node.attr
    return ""


def scan_source(source: str) -> list[dict]:
    """Deterministic AST scan. Returns findings [{line, pattern, detail}]."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [{"line": exc.lineno or 0, "pattern": "syntax_error", "detail": str(exc)[:200]}]
    findings: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in DANGEROUS_CALLS:
                # `open` alone is only a finding when it writes.
                if name == "open":
                    mode = ""
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                        mode = str(node.args[1].value)
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                            mode = str(kw.value.value)
                    if not any(c in mode for c in ("w", "a", "x", "+")):
                        continue
                    path = node.args[0] if node.args else None
                    detail = "file write (open, mode %s)" % (mode or "?")
                    if isinstance(path, ast.Constant) and isinstance(path.value, str):
                        if path.value.startswith(("/tmp/", "sandbox/")) or not path.value.startswith("/"):
                            continue  # inside sandbox / relative — allowed
                        detail += f": {path.value}"
                    findings.append(
                        {"line": node.lineno, "pattern": "file_write_outside_sandbox", "detail": detail}
                    )
                    continue
                findings.append(
                    {"line": node.lineno, "pattern": name, "detail": DANGEROUS_CALLS[name]}
                )
            elif name in WRITE_FUNCS:
                findings.append(
                    {"line": node.lineno, "pattern": name, "detail": "file write (checked for sandbox escape)"}
                )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("socket", "subprocess", "os"):
                    findings.append(
                        {"line": node.lineno, "pattern": f"import {alias.name}",
                         "detail": f"imports {alias.name} (dangerous-call surface)"}
                    )
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "") in ("socket", "subprocess"):
                findings.append(
                    {"line": node.lineno, "pattern": f"from {node.module} import",
                     "detail": f"imports from {node.module} (dangerous-call surface)"}
                )
    return findings


# --- Bandit scan (item #36, Apache 2.0) — alongside the AST scan ---
# In-process BanditManager (lazy import; ~0.8s import, ~0s scan on
# small files). Source is written to a temp file because Bandit works
# on file paths; the temp dir is deleted after the run. Any failure
# (lib missing, crash) -> bandit_available=false and the AST findings
# still answer — never a fake clean, never a crash of /doc/scan.

def _bandit_scan(source: str) -> tuple[bool, list[dict], str | None]:
    """Returns (available, findings, error). Findings are
    [{line, test_id, severity, confidence, detail, cwe}]."""
    try:
        import tempfile

        from bandit.core import config as bandit_config
        from bandit.core import manager as bandit_manager
    except ImportError:
        return False, [], "bandit_not_installed"
    try:
        with tempfile.TemporaryDirectory() as td:
            import os as _os

            path = _os.path.join(td, "skill.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(source)
            mgr = bandit_manager.BanditManager(bandit_config.BanditConfig(), "file")
            mgr.discover_files([path])
            mgr.run_tests()
            findings = []
            for issue in mgr.get_issue_list():
                cwe = None
                try:
                    cwe = issue.cwe.id if issue.cwe else None
                except Exception:
                    cwe = None
                findings.append({
                    "line": issue.lineno,
                    "test_id": issue.test_id,
                    "severity": str(issue.severity),
                    "confidence": str(issue.confidence),
                    "detail": issue.text[:300],
                    "cwe": cwe,
                })
        return True, findings, None
    except Exception as exc:  # noqa: BLE001 — Bandit crash must not kill the scan
        return False, [], str(exc)[:200]


# --- Browser-Use agent run (item #18) — see BROWSER_USE.md ---
# Gated: BROWSER_USE_ENABLED=1 + non-empty BROWSER_ALLOWLIST, else 503.
# LLM is a browser-use 0.7 chat model backed by the hub router (kind
# agent_plan) — the worker holds no key. One run at a time (lock);
# login/captcha -> status needs_human, never auto-solved (D3 rule).

_browse_lock = None  # created lazily (asyncio.Lock needs a loop)


def _browse_lock_get():
    global _browse_lock
    if _browse_lock is None:
        import asyncio

        _browse_lock = asyncio.Lock()
    return _browse_lock


def _bu_message_text(m) -> str:
    """Extract plain text from a browser-use message (content may be a
    string or a list of content parts; image parts are dropped — the
    agent runs with use_vision=False, see _run_browser_agent)."""
    text = getattr(m, "text", None)
    if isinstance(text, str) and text:
        return text
    content = getattr(m, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, str):
                parts.append(p)
            elif isinstance(getattr(p, "text", None), str):
                parts.append(p.text)
            elif isinstance(p, dict) and isinstance(p.get("text"), str):
                parts.append(p["text"])
        return "\n".join(parts)
    return str(content or "")


class _RouterChatModel:
    """Factory for a browser-use 0.7 chat model backed by the hub router.

    browser-use 0.7 defines its OWN BaseChatModel Protocol (NOT
    langchain): `model`, `provider`, `name` + async
    `ainvoke(messages, output_format=None) -> ChatInvokeCompletion`.
    The agent ALWAYS calls ainvoke with output_format=AgentOutput, so
    the adapter derives a JSON schema from that pydantic model, sends
    it as the router response_schema, and validates the returned JSON
    back into the model. Built lazily so the base worker never imports
    browser-use. The router call is synchronous (urllib) run in a
    thread; the agent runs with use_vision=False (text DOM only)."""

    @staticmethod
    def build(tenant_id: str, turn_id: str):
        from browser_use.llm.views import ChatInvokeCompletion

        class RouterChat:
            model = "hub-router"
            provider = "omnijarvis-hub-router"

            @property
            def name(self) -> str:
                return "hub-router/agent_plan"

            async def ainvoke(self, messages, output_format=None):
                import asyncio

                def _call() -> str:
                    payload = {
                        "tenant_id": tenant_id,
                        "turn_id": turn_id,
                        "kind": "agent_plan",
                        "messages": [
                            {"role": getattr(m, "role", "user"), "text": _bu_message_text(m)}
                            for m in messages
                        ],
                    }
                    if output_format is not None:
                        try:
                            payload["response_schema"] = output_format.model_json_schema()
                        except Exception:
                            pass
                    result = _router_post(payload, timeout=120)
                    if not result.get("ok"):
                        raise RuntimeError(
                            "router: " + str(result.get("error", "upstream_error"))[:100]
                        )
                    text = result.get("text") or ""
                    if not text and isinstance(result.get("response"), dict):
                        text = json.dumps(result["response"], ensure_ascii=False)
                    return text

                text = await asyncio.to_thread(_call)
                if output_format is None:
                    return ChatInvokeCompletion(completion=text, usage=None)
                cleaned = text.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.strip("`").strip()
                    if cleaned.lower().startswith("json"):
                        cleaned = cleaned[4:].strip()
                try:
                    parsed = output_format.model_validate_json(cleaned)
                except Exception as exc:
                    raise RuntimeError(f"router reply did not match {output_format.__name__}: {exc}") from exc
                return ChatInvokeCompletion(completion=parsed, usage=None)

        return RouterChat()


def _browse_url_allowed(url: str) -> bool:
    """Allowlist check on the URL host (exact host or subdomain)."""
    from urllib.parse import urlparse

    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return any(host == h or host.endswith("." + h) for h in BROWSER_ALLOWLIST)


async def _run_browser_agent(task: str, url: str | None, max_steps: int,
                             tenant_id: str, turn_id: str) -> dict:
    """Run browser-use Agent. Returns a plain-dict result. Raises on
    missing libs / agent failure — caller maps to honest errors."""
    # browser-use ships anonymized (PostHog) telemetry ON by default;
    # the worker sends no telemetry anywhere.
    os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
    try:
        from browser_use import Agent
    except ImportError as exc:
        raise RuntimeError("browser_use_not_installed") from exc
    llm = _RouterChatModel.build(tenant_id, turn_id)
    full_task = task if not url else f"{task}\nStart at this URL: {url}"
    # 0.7.x API (BrowserSession) with fallback to pre-0.7 (Browser).
    try:
        from browser_use import BrowserSession

        session = BrowserSession(headless=True)
        # use_vision=False: the hub router is text-only (no image parts
        # in its messages); the agent steers from the DOM snapshot.
        agent = Agent(task=full_task, llm=llm, browser_session=session, use_vision=False)
    except ImportError:
        from browser_use import Browser

        agent = Agent(task=full_task, llm=llm, browser=Browser(headless=True), use_vision=False)
    import asyncio

    history = await asyncio.wait_for(agent.run(max_steps=max_steps), timeout=300)
    final = ""
    urls: list[str] = []
    try:
        final = history.final_result() or ""
    except Exception:
        final = ""
    try:
        urls = [str(u) for u in (history.urls() or [])]
    except Exception:
        urls = []
    blocked = [u for u in urls if not _browse_url_allowed(u)]
    status = "done"
    if blocked:
        status = "needs_human"
        final = (final + " [stopped: navigation left the allowlist]").strip()
    return {"status": status, "final_text": final, "urls_visited": urls,
            "steps": len(urls)}


@app.post("/browse/run")
async def browse_run(request: Request):
    """Gated Browser-Use run. Body JSON: {tenant_id, task, url?,
    max_steps?}. Response: {ok, status, steps, final_text,
    urls_visited}. status: done | needs_human | error. 503 when
    disabled or libs missing; 403 on non-allowlisted URL; 429 when a
    run is already in progress."""
    if not BROWSER_USE_ENABLED:
        return JSONResponse({"ok": False, "error": "browser_disabled"}, status_code=503)
    if not BROWSER_ALLOWLIST:
        return JSONResponse({"ok": False, "error": "browser_allowlist_empty"}, status_code=503)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"ok": False, "error": "bad_json"}, status_code=400)
    tenant_id = body.get("tenant_id") or ""
    task = body.get("task") or ""
    url = body.get("url") or None
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        return JSONResponse({"ok": False, "error": "tenant_id_required"}, status_code=400)
    if not isinstance(task, str) or not task.strip():
        return JSONResponse({"ok": False, "error": "task_required"}, status_code=400)
    if len(task) > MAX_BROWSE_TASK_CHARS:
        return JSONResponse({"ok": False, "error": "task_too_long"}, status_code=413)
    if url is not None:
        if not isinstance(url, str) or not _browse_url_allowed(url):
            return JSONResponse({"ok": False, "error": "url_not_allowed"}, status_code=403)
    max_steps = body.get("max_steps", 10)
    if not isinstance(max_steps, int) or max_steps < 1 or max_steps > MAX_BROWSE_STEPS:
        return JSONResponse({"ok": False, "error": "bad_max_steps"}, status_code=400)
    if not (HUB_LLM_URL and INTERNAL_SECRET):
        return JSONResponse({"ok": False, "error": "router_not_configured"}, status_code=503)
    lock = _browse_lock_get()
    if lock.locked():
        return JSONResponse({"ok": False, "error": "browser_busy"}, status_code=429)
    turn_id = f"browse-{int(time.time())}"
    async with lock:
        try:
            result = await _run_browser_agent(
                task.strip(), url, max_steps, tenant_id.strip(), turn_id
            )
        except RuntimeError as exc:
            msg = str(exc)
            if "browser_use_not_installed" in msg or "langchain" in msg.lower():
                return JSONResponse({"ok": False, "error": "browser_not_available"}, status_code=503)
            return JSONResponse(
                {"ok": False, "error": "agent_failed", "detail": msg[:200]}, status_code=502
            )
        except Exception as exc:  # noqa: BLE001
            return JSONResponse(
                {"ok": False, "error": "agent_failed", "detail": str(exc)[:200]}, status_code=502
            )
    return {"ok": True, **result}


@app.post("/doc/scan")
async def doc_scan(file: UploadFile = File(...)):
    """Python source -> AST static scan. Response: {ok, findings[]}.
    Deterministic — no LLM. Cap: 512 KB source."""
    data = await file.read()
    if len(data) > MAX_SCAN_BYTES:
        return JSONResponse({"ok": False, "error": "source_too_large"}, status_code=413)
    try:
        source = data.decode("utf-8")
    except Exception:
        return JSONResponse({"ok": False, "error": "not_utf8"}, status_code=400)
    findings = scan_source(source)
    bandit_available, bandit_findings, bandit_error = _bandit_scan(source)
    response: dict = {
        "ok": True,
        "findings": findings,
        "bandit_available": bandit_available,
        "bandit_findings": bandit_findings,
    }
    if bandit_error:
        response["bandit_error"] = bandit_error
    return response
