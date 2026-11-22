"""Track D checks (2026-11-22): new worker endpoints.

Usage: python trackd_check.py [base_url]
Env knobs (set on the WORKER process, not here):
  HUB_LLM_URL + INTERNAL_SECRET -> mem0 path; else rule fallback.
  BROWSER_USE_ENABLED=1 + BROWSER_ALLOWLIST -> browse gating tests.
Expects the worker to be already running (uvicorn main:app).
Checks are written so they PASS in both configurations where the
expected behaviour differs — the assertion names the configuration.
Exit non-zero on any failure.
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8123"
failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    print(("PASS " if cond else "FAIL ") + name + (f" :: {detail}" if detail else ""))
    if not cond:
        failures.append(name)


def http_json(path: str, body: dict | None = None, method: str = "GET") -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def http_multipart(path: str, fields: dict[str, tuple[str, bytes, str]]) -> tuple[int, dict]:
    boundary = "----trackd-boundary"
    out = bytearray()
    for name, (filename, data, ctype) in fields.items():
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        out += f"Content-Type: {ctype}\r\n\r\n".encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(BASE + path, data=bytes(out), method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}


def main() -> int:
    # --- /mem/extract: validation ---
    s, r = http_json("/mem/extract", {}, "POST")
    check("mem/extract {} -> 400 tenant_id_required", s == 400 and r.get("error") == "tenant_id_required", f"{s} {r}")
    s, r = http_json("/mem/extract", {"tenant_id": "t1", "text": "  "}, "POST")
    check("mem/extract empty text -> 400 text_required", s == 400 and r.get("error") == "text_required", f"{s} {r}")
    s, r = http_json("/mem/extract", {"tenant_id": "t1", "text": "x" * 8001}, "POST")
    check("mem/extract oversize -> 413 text_too_long", s == 413 and r.get("error") == "text_too_long", f"{s} {r}")

    # --- /mem/extract: happy path (engine depends on worker env) ---
    text = "My name is Arjun Mehta. I like strong chai. My city is Patna. Please remember that I prefer morning calls."
    s, r = http_json("/mem/extract", {"tenant_id": "t1", "text": text, "metadata": {"source": "trackd"}}, "POST")
    check("mem/extract ok", s == 200 and r.get("ok") is True, f"{s} {str(r)[:300]}")
    engine = r.get("engine", "")
    mems = r.get("memories", [])
    check("mem/extract memories list", isinstance(mems, list) and len(mems) >= 1, str(mems)[:300])
    joined = " ".join(m.get("content", "") for m in mems).lower()
    if engine == "rule_fallback":
        check("mem/extract rule_fallback finds name/city",
              "arjun mehta" in joined and "patna" in joined, joined[:300])
        check("mem/extract rule_fallback model tag",
              r.get("model", "").startswith("rule_fallback"), str(r.get("model")))
    elif engine == "mem0+hub-router":
        check("mem/extract mem0 engine tag", True, engine)
        check("mem/extract mem0 memories have content",
              all(m.get("content") for m in mems), str(mems)[:300])
    else:
        check("mem/extract engine is known", False, f"engine={engine!r}")

    # --- /doc/extract-docling: absent lib -> honest 503; present -> real run ---
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import main as worker_main
    sample = worker_main.sample_pdf_bytes()
    s, r = http_multipart("/doc/extract-docling", {"file": ("sample.pdf", sample, "application/pdf")})
    if s == 503:
        check("docling absent -> 503 docling_not_available", r.get("error") == "docling_not_available", f"{s} {r}")
    else:
        check("docling present -> ok + Hello OmniJarvis", s == 200 and r.get("ok") is True
              and "Hello OmniJarvis" in r.get("text", ""), f"{s} {str(r)[:300]}")
        check("docling response has timings+tables", "timings" in r and isinstance(r.get("tables"), list), str(r)[:200])

    # --- /doc/scan: AST contract unchanged + Bandit additive fields ---
    s, r = http_multipart("/doc/scan", {"file": ("s.py", b"x = 1\nprint(x)\n", "text/x-python")})
    check("doc/scan clean findings==[]", s == 200 and r.get("findings") == [], f"{s} {str(r)[:200]}")
    check("doc/scan has bandit_available bool", isinstance(r.get("bandit_available"), bool), str(r)[:200])
    check("doc/scan has bandit_findings list", isinstance(r.get("bandit_findings"), list), str(r)[:200])
    dirty = b"import os\nos.system('rm -rf /')\neval(user_input)\n"
    s, r = http_multipart("/doc/scan", {"file": ("s.py", dirty, "text/x-python")})
    check("doc/scan dirty flags os.system (AST)", any(f.get("pattern") == "os.system" for f in r.get("findings", [])), str(r)[:300])
    if r.get("bandit_available") is True:
        ids = [f.get("test_id") for f in r.get("bandit_findings", [])]
        check("doc/scan bandit flags B605+B307", "B605" in ids and "B307" in ids, str(ids))
        sev = {f.get("test_id"): f.get("severity") for f in r.get("bandit_findings", [])}
        check("doc/scan bandit B307 severity MEDIUM", sev.get("B307") == "MEDIUM", str(sev))
    else:
        check("doc/scan bandit unavailable honest", r.get("bandit_error") == "bandit_not_installed", str(r)[:200])

    # --- /browse/run: gating (disabled by default) ---
    s, r = http_json("/browse/run", {"tenant_id": "t1", "task": "read the docs page"}, "POST")
    if os.environ.get("TRACKD_BROWSE_ENABLED") == "1":
        # Worker was started with BROWSER_USE_ENABLED=1 + allowlist.
        # URL gating is exercised by browse_gate_check.py with env-set worker.
        check("browse enabled: task reaches a gated outcome",
              s in (403, 429, 502, 503), f"{s} {str(r)[:200]}")
    else:
        check("browse disabled -> 503 browser_disabled", s == 503 and r.get("error") == "browser_disabled", f"{s} {r}")

    if failures:
        print(f"TRACKD FAILURES: {failures}")
        return 1
    print("TRACKD ALL PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
