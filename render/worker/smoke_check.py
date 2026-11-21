"""Render worker smoke check (CI render-smoke job + local).

Usage: python smoke_check.py [base_url] [worker_pid]
Starts nothing itself — CI starts uvicorn first, then runs this.
Checks: /health, /smoke/pdf, /doc/extract, /doc/ocr (generated PNG),
/doc/certificate (WeasyPrint + QR hash), /doc/scan (clean + dirty).
Also reads the worker's peak RSS (VmHWM) and asserts < 512 MB (free tier).
Exits non-zero on any failure; prints RSS_MB=... for the audit.
"""
import base64
import hashlib
import io
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
PID = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("RENDER_PID", "")

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" :: {detail}" if detail else ""))
    if not cond:
        failures.append(name)


def http_json(path: str, method: str = "GET", body: bytes | None = None,
              content_type: str | None = None) -> dict:
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        # Print the error body before re-raising — the CI log is the
        # only diagnosis for a 4xx/5xx (a bare 422 hid the real cause).
        try:
            print(f"HTTP {e.code} on {path}: {e.read().decode('utf-8', 'replace')[:500]}")
        except Exception:
            pass
        raise


def http_multipart(path: str, fields: dict[str, tuple[str, bytes, str]]) -> dict:
    boundary = "----smoke-boundary-3b"
    out = bytearray()
    for name, (filename, data, ctype) in fields.items():
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return http_json(path, "POST", bytes(out),
                     f"multipart/form-data; boundary={boundary}")


def http_form(path: str, fields: dict[str, str]) -> dict:
    body = urllib.parse.urlencode(fields).encode()
    return http_json(path, "POST", body, "application/x-www-form-urlencoded")


def make_ocr_png(text: str = "INVOICE Total 1250") -> bytes:
    from PIL import Image, ImageDraw, ImageFont
    font = None
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        try:
            font = ImageFont.truetype(p, 48)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()
    img = Image.new("RGB", (900, 200), "white")
    d = ImageDraw.Draw(img)
    d.text((20, 60), text, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main() -> int:
    health = http_json("/health")
    check("health ok + version 3b", health.get("ok") is True
          and health.get("version") == "3b", str(health))

    smoke = http_json("/smoke/pdf", "POST")
    check("smoke/pdf sample", smoke.get("ok") is True
          and "Hello OmniJarvis" in smoke.get("text_preview", ""), str(smoke)[:200])

    # /doc/extract on the worker's own sample PDF (import main for bytes).
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import main as worker_main
    sample = worker_main.sample_pdf_bytes()
    ext = http_multipart("/doc/extract", {"file": ("sample.pdf", sample, "application/pdf")})
    check("doc/extract sample", ext.get("ok") is True and ext.get("pages") == 1
          and "Hello OmniJarvis" in ext.get("text", ""), str(ext)[:200])
    check("doc/extract tables shape", isinstance(ext.get("tables"), list)
          and ext["tables"][0]["page"] == 1, "")

    # /doc/ocr on a generated image (real Tesseract path).
    png = make_ocr_png()
    ocr = http_multipart("/doc/ocr", {"file": ("invoice.png", png, "image/png")})
    check("doc/ocr image", ocr.get("ok") is True and ocr.get("pages") == 1
          and ocr.get("confidence", 0) >= 0, str(ocr)[:300])
    check("doc/ocr reads text", "INVOICE" in ocr.get("text", "").upper(),
          repr(ocr.get("text", ""))[:200])

    # /doc/ocr on a PDF (pdftoppm + Tesseract, or text-layer fallback).
    ocr_pdf = http_multipart("/doc/ocr", {"file": ("sample.pdf", sample, "application/pdf")})
    check("doc/ocr pdf", ocr_pdf.get("ok") is True and ocr_pdf.get("pages") == 1
          and "Hello OmniJarvis" in ocr_pdf.get("text", ""), str(ocr_pdf)[:300])

    # /doc/certificate: WeasyPrint + segno QR hash.
    cert = http_form("/doc/certificate", {
        "html": "<html><body><h1>Certificate</h1><p>Test Person</p>{{QR}}</body></html>",
        "payload": json.dumps({"name": "Test Person", "course": "Demo"}),
        "verify_url": "https://omnijarvis-hub.rajraj3kk.workers.dev/api/docs/verify",
    })
    check("doc/certificate ok", cert.get("ok") is True
          and len(cert.get("hash", "")) == 64, str(cert)[:200])
    pdf = base64.b64decode(cert.get("pdf_base64", ""))
    check("doc/certificate pdf bytes", pdf[:4] == b"%PDF" and cert.get("pages", 0) >= 1,
          f"bytes={cert.get('bytes')} pages={cert.get('pages')}")
    expect_hash = hashlib.sha256(
        json.dumps({"course": "Demo", "name": "Test Person"},
                   sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    check("doc/certificate hash = sha256(canonical payload)",
          cert.get("hash") == expect_hash, cert.get("hash", ""))

    # /doc/scan: clean source -> no findings; dirty -> findings.
    clean = http_multipart("/doc/scan", {"file": ("s.py", b"x = 1\nprint(x)\n", "text/x-python")})
    check("doc/scan clean", clean.get("ok") is True and clean.get("findings") == [],
          str(clean)[:200])
    dirty = http_multipart("/doc/scan", {
        "file": ("s.py", b"import os\nos.system('rm -rf /')\n", "text/x-python")})
    check("doc/scan dirty flags os.system", dirty.get("ok") is True
          and any(f.get("pattern") == "os.system" for f in dirty.get("findings", [])),
          str(dirty)[:300])
    evil_eval = http_multipart("/doc/scan", {
        "file": ("s.py", b"eval(user_input)\n", "text/x-python")})
    check("doc/scan flags eval", any(f.get("pattern") == "eval"
          for f in evil_eval.get("findings", [])), str(evil_eval)[:200])

    # Caps: oversize PDF -> 413.
    try:
        big = http_multipart("/doc/extract",
                             {"file": ("big.pdf", b"%PDF" + b"0" * (6 * 1024 * 1024),
                                      "application/pdf")})
        check("doc/extract oversize -> 413", False, f"got {str(big)[:100]}")
    except urllib.error.HTTPError as e:
        check("doc/extract oversize -> 413", e.code == 413, f"http {e.code}")

    # RSS: peak resident set of the worker process (VmHWM).
    rss_mb = None
    if PID:
        try:
            with open(f"/proc/{PID}/status") as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        rss_mb = int(line.split()[1]) / 1024
                        break
        except Exception as exc:  # noqa: BLE001
            print(f"RSS read failed: {exc}")
    if rss_mb is not None:
        print(f"RSS_PEAK_MB={rss_mb:.1f}")
        check("worker peak RSS < 512 MB (free tier)", rss_mb < 512, f"{rss_mb:.1f} MB")
    else:
        print("RSS_PEAK_MB=unknown (no pid given)")

    if failures:
        print(f"SMOKE FAILURES: {failures}")
        return 1
    print("SMOKE ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
