"""OmniJarvis Render light worker (Phase 2, stage 2a-5) — health + /smoke/pdf ONLY.

No state on Render (free tier: 512 MB RAM, 0.1 CPU, 750 hrs/mo, 15-min
sleep, ephemeral filesystem — demo/smoke only, never for state or uptime).
Phase 3 adds the light doc stack here (pdfplumber + Tesseract + WeasyPrint
+ Mem0-library-only — the only combo that fits 512 MB, audit V2).

Endpoints:
- GET /health -> {"ok": true, ...}
- POST /smoke/pdf -> extracts text with pdfplumber. No file uploaded?
  parses an in-memory generated sample PDF ("Hello OmniJarvis") — proves
  the pdfplumber path end-to-end with a plain curl, no upload needed.
  Upload caps: 5 MB, 20 pages (smoke only — no real doc jobs here).
"""

import io

import pdfplumber
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse

app = FastAPI(title="omnijarvis-render")
SERVICE = "omnijarvis-render"
VERSION = "2a-5"
MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_PAGES = 20


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
