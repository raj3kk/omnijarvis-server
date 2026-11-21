"""OmniJarvis Render light worker (Phase 3, stage 3b) — doc pipeline.

Endpoints:
- GET /health -> {"ok": true, ...}
- POST /smoke/pdf -> pdfplumber sample/upload extract (2a-5, untouched).
- POST /doc/ocr -> Tesseract OCR (image PNG/JPG, or PDF page-by-page).
  Caps: 5 MB, 10 pages, 30s. Response: {ok, pages, text, confidence}
  (per-page mean word confidence; empty page -> confidence 0, text "").
- POST /doc/extract -> PDF -> pdfplumber text + tables, max 20 pages.
  Response: {ok, pages, text, tables}.
- POST /doc/certificate -> HTML -> WeasyPrint PDF (300 DPI, A4) + segno
  QR (verification URL + SHA-256 hash of canonical payload).
  Caps: 2 MB HTML, 10 pages. Response: {ok, hash, pdf_base64, pages}.
- POST /doc/scan -> Python source -> AST static scan (deterministic,
  no LLM): dangerous patterns -> {ok, findings[]}.

RAM discipline (free tier 512 MB): one page / one doc at a time, no
model loads (Tesseract binary + tessdata ~50 MB). No state on Render
(ephemeral filesystem, 15-min sleep — demo/smoke + doc jobs only).
"""

import ast
import base64
import hashlib
import io
import json
import time

import pdfplumber
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(title="omnijarvis-render")
SERVICE = "omnijarvis-render"
VERSION = "3b"
MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PAGES = 20
MAX_OCR_BYTES = 5 * 1024 * 1024
MAX_OCR_PAGES = 10
MAX_OCR_SECONDS = 30
MAX_HTML_BYTES = 2 * 1024 * 1024
MAX_CERT_PAGES = 10
MAX_SCAN_BYTES = 512 * 1024


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


def _ocr_image_bytes(img_bytes: bytes) -> tuple[str, float]:
    """OCR one image (bytes) -> (text, mean word confidence 0-100).
    Words with conf -1 (no text) are excluded; empty image -> ("", 0)."""
    import pytesseract
    from PIL import Image

    img = Image.open(io.BytesIO(img_bytes))
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    # Hindi+English mix docs: try eng+hin first (needs tesseract-ocr-hin
    # + a Devanagari font — CI + Render apt lines install both); fall
    # back to eng when hin tessdata is absent (local dev without apt).
    try:
        data = pytesseract.image_to_data(img, lang="eng+hin", output_type=pytesseract.Output.DICT)
        text = pytesseract.image_to_string(img, lang="eng+hin") or ""
    except Exception:
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        text = pytesseract.image_to_string(img) or ""
    confs = [float(c) for c in data.get("conf", []) if float(c) >= 0]
    mean_conf = sum(confs) / len(confs) if confs else 0.0
    return text, round(mean_conf, 2)


def _ocr_pdf_page_with_pdftoppm(pdf_bytes: bytes, page_index: int) -> tuple[str, float] | None:
    """Render one PDF page to PNG with poppler `pdftoppm` (apt) and OCR it.
    Returns None when pdftoppm is unavailable — caller falls back to the
    embedded text layer (honest `source` field in the response)."""
    import os
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("pdftoppm"):
        return None
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "doc.pdf")
        with open(src, "wb") as f:
            f.write(pdf_bytes)
        prefix = os.path.join(td, "page")
        try:
            subprocess.run(
                ["pdftoppm", "-png", "-r", "200", "-f", str(page_index + 1),
                 "-l", str(page_index + 1), src, prefix],
                check=True, timeout=20, capture_output=True,
            )
        except Exception:
            return None
        pngs = sorted(p for p in os.listdir(td) if p.endswith(".png"))
        if not pngs:
            return None
        with open(os.path.join(td, pngs[0]), "rb") as f:
            return _ocr_image_bytes(f.read())
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
    """Tesseract OCR: image (PNG/JPG) upload, or PDF (page-by-page).
    Caps: 5 MB, 10 pages, 30s wall-clock.
    Response: {ok, pages, text, confidence, per_page}."""
    started = time.monotonic()
    data = await file.read()
    if len(data) > MAX_OCR_BYTES:
        return JSONResponse({"ok": False, "error": "file_too_large"}, status_code=413)
    name = (file.filename or "").lower()
    try:
        if name.endswith(".pdf") or data[:4] == b"%PDF":
            # PDF: one page at a time — pdftoppm render + real Tesseract
            # OCR; pdftoppm missing ho to embedded text layer (source
            # field me saaf likha — silent empty text kabhi nahi).
            with pdfplumber.open(io.BytesIO(data)) as pdf:
                pages = pdf.pages[:MAX_OCR_PAGES]
                texts: list[str] = []
                per_page: list[dict] = []
                for idx, p in enumerate(pages):
                    if time.monotonic() - started > MAX_OCR_SECONDS:
                        return JSONResponse(
                            {"ok": False, "error": "ocr_timeout"}, status_code=504
                        )
                    rendered = _ocr_pdf_page_with_pdftoppm(data, idx)
                    if rendered is not None:
                        t, c = rendered
                        texts.append(t)
                        per_page.append(
                            {"page": idx + 1, "confidence": c, "source": "tesseract"}
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
        # Image path: real Tesseract.
        text, conf = _ocr_image_bytes(data)
        if time.monotonic() - started > MAX_OCR_SECONDS:
            return JSONResponse({"ok": False, "error": "ocr_timeout"}, status_code=504)
        return {
            "ok": True,
            "pages": 1,
            "text": text,
            "confidence": conf,
            "per_page": [{"page": 1, "confidence": conf, "source": "tesseract"}],
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


@app.post("/doc/certificate")
async def doc_certificate(
    html: str = Form(...),
    payload: str = Form(default="{}"),
    verify_url: str = Form(default=""),
):
    """HTML -> WeasyPrint PDF (300 DPI, A4) + segno QR.
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
        from weasyprint import HTML

        qr_target = f"{verify_url}?hash={digest}" if verify_url else digest
        qr = segno.make(qr_target, error="m")
        qr_svg = io.BytesIO()
        qr.save(qr_svg, kind="svg", scale=4)
        qr_b64 = base64.b64encode(qr_svg.getvalue()).decode("ascii")
        html_with_qr = html.replace(
            "{{QR}}",
            f'<img src="data:image/svg+xml;base64,{qr_b64}" alt="verification QR" />',
        )
        pdf_bytes = HTML(string=html_with_qr).write_pdf()
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
    return {"ok": True, "findings": findings}
