#!/usr/bin/env python3
"""Live verification for the OmniJarvis worker Space (Track B).

Usage:
    python3 verify.py <base_url> [--fixtures DIR] [--timeout SECONDS]

Checks (stdlib urllib only — no third-party deps):
  1. GET  /health            -> ok:true, service omnijarvis-render, version 3b
  2. POST /smoke/pdf         -> built-in sample, "Hello OmniJarvis"
  3. POST /doc/extract       -> fixtures/doc01.pdf, contains INV-2026-0142
  4. POST /doc/ocr           -> fixtures/doc01.png, contains INV-2026-0142,
                                confidence > 50, source tesseract
  5. POST /doc/certificate   -> inline HTML, 64-hex SHA-256 hash, PDF bytes
  6. POST /doc/scan          -> clean source: 0 findings; dirty source:
                                os.system finding present

Checks 3-4 need --fixtures (default: ../render/worker/fixtures relative
to this file). When the fixtures dir is absent they are SKIPped, not
failed — the rest still proves the Space is up and the routes work.

/health is retried (cold start: a sleeping Space takes 60-120 s to wake;
the hub retries once after 5 s and reports render_warming_up).

Exit 0 = all checks PASS (SKIPs allowed); 1 = any FAIL.
Prints no secrets. Safe to run against any worker base URL.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

FAILURES: list[str] = []
SKIPS: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" :: {detail}" if detail else ""))
    if not cond:
        FAILURES.append(name)


def skip(name: str, reason: str) -> None:
    print(f"SKIP {name} :: {reason}")
    SKIPS.append(name)


def http_json(base: str, path: str, method: str = "GET",
              body: bytes | None = None, content_type: str | None = None,
              timeout: float = 120) -> tuple[int, dict]:
    req = urllib.request.Request(base.rstrip("/") + path, data=body, method=method)
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def http_multipart(base: str, path: str,
                   fields: dict[str, tuple[str, bytes, str]],
                   timeout: float = 120) -> tuple[int, dict]:
    boundary = "----omnijarvis-verify-3b"
    out = bytearray()
    for name, (filename, data, ctype) in fields.items():
        out += f"--{boundary}\r\n".encode()
        out += (f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n').encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return http_json(base, path, "POST", bytes(out),
                     f"multipart/form-data; boundary={boundary}", timeout)


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the OmniJarvis worker live.")
    ap.add_argument("base_url", help="Worker base URL, e.g. https://<ns>-omnijarvis-render.hf.space")
    ap.add_argument("--fixtures", default=None,
                    help="Dir with doc01.png/doc01.pdf (default: ../render/worker/fixtures)")
    ap.add_argument("--timeout", type=float, default=120,
                    help="Per-request timeout in seconds (default 120)")
    ap.add_argument("--health-retries", type=int, default=12,
                    help="Health polls before giving up (default 12 x 10s)")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    fixtures = args.fixtures or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "render", "worker", "fixtures")
    fixtures = os.path.normpath(fixtures)

    # 1. /health (cold-start aware)
    health = None
    for attempt in range(1, args.health_retries + 1):
        try:
            status, health = http_json(base, "/health", timeout=15)
            if status == 200 and health.get("ok") is True:
                break
            health = None
        except Exception as exc:  # noqa: BLE001 — still waking up
            print(f"... health poll {attempt}/{args.health_retries}: {type(exc).__name__}")
        time.sleep(10)
    check("health", bool(health) and health.get("service") == "omnijarvis-render"
          and health.get("version") == "3b",
          json.dumps(health)[:200] if health else "no response after retries")

    # 2. /smoke/pdf (built-in sample, no file)
    try:
        status, body = http_json(base, "/smoke/pdf", "POST", b"",
                                 "application/octet-stream", args.timeout)
        check("smoke/pdf", status == 200 and body.get("ok") is True
              and "Hello OmniJarvis" in (body.get("text_preview") or ""),
              json.dumps(body)[:200])
    except Exception as exc:  # noqa: BLE001
        check("smoke/pdf", False, f"{type(exc).__name__}: {exc}")

    # 3. /doc/extract (fixture PDF)
    pdf_path = os.path.join(fixtures, "doc01.pdf")
    if os.path.exists(pdf_path):
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
        try:
            status, body = http_multipart(
                base, "/doc/extract",
                {"file": ("doc01.pdf", pdf_bytes, "application/pdf")}, args.timeout)
            check("doc/extract", status == 200 and body.get("ok") is True
                  and "INV-2026-0142" in (body.get("text") or ""),
                  f"pages={body.get('pages')} chars={len(body.get('text') or '')}")
        except Exception as exc:  # noqa: BLE001
            check("doc/extract", False, f"{type(exc).__name__}: {exc}")
    else:
        skip("doc/extract", f"fixture not found: {pdf_path}")

    # 4. /doc/ocr (fixture PNG — the real Tesseract path)
    png_path = os.path.join(fixtures, "doc01.png")
    if os.path.exists(png_path):
        with open(png_path, "rb") as f:
            png_bytes = f.read()
        try:
            status, body = http_multipart(
                base, "/doc/ocr",
                {"file": ("doc01.png", png_bytes, "image/png")}, args.timeout)
            per_page = body.get("per_page") or [{}]
            check("doc/ocr", status == 200 and body.get("ok") is True
                  and "INV-2026-0142" in (body.get("text") or "")
                  and float(body.get("confidence") or 0) > 50
                  and per_page[0].get("source") == "tesseract",
                  f"confidence={body.get('confidence')} "
                  f"source={per_page[0].get('source')}")
        except Exception as exc:  # noqa: BLE001
            check("doc/ocr", False, f"{type(exc).__name__}: {exc}")
    else:
        skip("doc/ocr", f"fixture not found: {png_path}")

    # 5. /doc/certificate (inline HTML + QR placeholder)
    try:
        form = urllib.parse.urlencode({
            "html": "<h1>Test Certificate</h1><p>{{QR}}</p>",
            "payload": "{}",
            "verify_url": base + "/api/docs/verify",
        }).encode()
        status, body = http_json(base, "/doc/certificate", "POST", form,
                                 "application/x-www-form-urlencoded", args.timeout)
        pdf_b64 = body.get("pdf_base64") or ""
        import base64 as _b64
        pdf_ok = False
        try:
            pdf_ok = _b64.b64decode(pdf_b64)[:5] == b"%PDF-"
        except Exception:
            pdf_ok = False
        check("doc/certificate", status == 200 and body.get("ok") is True
              and len(body.get("hash") or "") == 64 and pdf_ok,
              f"hash={(body.get('hash') or '')[:12]}... pages={body.get('pages')}")
    except Exception as exc:  # noqa: BLE001
        check("doc/certificate", False, f"{type(exc).__name__}: {exc}")

    # 6. /doc/scan (clean + dirty)
    try:
        status, body = http_multipart(
            base, "/doc/scan",
            {"file": ("clean.py", b"x = 1\nprint(x)\n", "text/x-python")}, args.timeout)
        check("doc/scan clean", status == 200 and body.get("ok") is True
              and body.get("findings") == [], json.dumps(body)[:200])
        status, body = http_multipart(
            base, "/doc/scan",
            {"file": ("dirty.py", b'import os\nos.system("id")\n', "text/x-python")},
            args.timeout)
        patterns = {(f.get("pattern") or "") for f in (body.get("findings") or [])}
        check("doc/scan dirty", status == 200 and body.get("ok") is True
              and "os.system" in patterns, f"patterns={sorted(patterns)}")
    except Exception as exc:  # noqa: BLE001
        check("doc/scan", False, f"{type(exc).__name__}: {exc}")

    print(f"\n{len(FAILURES)} FAIL, {len(SKIPS)} SKIP")
    if FAILURES:
        print("FAILED: " + ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED" + (" (some skipped)" if SKIPS else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
