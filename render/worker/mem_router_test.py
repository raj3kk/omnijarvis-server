"""Direct-router test for POST /mem/extract (no mem0 library).

Starts a fake hub router on 127.0.0.1:18099, then starts the worker
twice — once WITHOUT HUB_LLM_URL/INTERNAL_SECRET and once WITH them —
and asserts the three /mem/extract cases:

  1. Router unconfigured -> 200, engine rule_fallback (natural prose
     gives 0 memories; preference-shaped text gives >= 1).
  2. Router configured + hub mocked -> 200, engine llm/router, the
     mocked facts returned, exactly ONE doc_extraction call, ZERO
     embeddings calls, and the payload carries kind doc_extraction +
     the worker's MEM_EXTRACT_SYSTEM + MEM_EXTRACT_SCHEMA.
  3. Router configured + hub error -> 502 mem_extract_failed, NO
     silent rule fallback. Two hub failure shapes: (a) HTTP 200 with
     {"ok": false, "error": "byok_required"} and (b) HTTP 500 with
     {"error": "upstream_error"} — both must surface the hub code in
     the detail.

Usage: python mem_router_test.py  (run from render/worker/)
  WORKER_PY=/path/to/python python mem_router_test.py
The python used must have the light worker deps (fastapi, uvicorn,
pdfplumber, ...). Default is the python running this test
(sys.executable) — that is what CI uses.
Exit non-zero on any failure. No real LLM, no real key, no network.
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import main as worker_main  # noqa: E402 — for MEM_EXTRACT_* constants

WORKER_PY = os.environ.get("WORKER_PY") or sys.executable
PORT_ROUTER = 18099
PORT_WORKER = 8124
SECRET = "test-secret"

NATURAL = (
    "I usually stay up late working on my shop after dinner, and I "
    "always keep a notebook beside my bed for ideas that come at night."
)
FACTS = [
    "User usually stays up late working on their shop after dinner",
    "User keeps a notebook beside their bed for ideas that come at night",
]
PREFERENCE = "My name is Arjun Mehta. I like strong chai."

MODE = {"mode": "ok"}  # ok | error_ok_false | error_http500
CALLS: list[dict] = []


class RouterHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/api/llm/route":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("x-internal-secret") != SECRET:
            self.send_response(401)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        CALLS.append(body)
        mode = MODE["mode"]
        if mode == "error_ok_false":
            data = json.dumps({
                "ok": False, "error": "byok_required",
                "detail": "Server AI ke liye apni Gemini key jodo",
            }).encode()
            self.send_response(200)
        elif mode == "error_http500":
            data = json.dumps({"error": "upstream_error", "detail": "boom"}).encode()
            self.send_response(500)
        elif body.get("kind") == "embeddings":
            data = json.dumps({"ok": True, "embedding": [0.01] * 16}).encode()
            self.send_response(200)
        elif body.get("kind") == "doc_extraction":
            data = json.dumps({"ok": True, "text": json.dumps({"facts": FACTS})}).encode()
            self.send_response(200)
        else:
            data = json.dumps({"ok": False, "error": "mock: unknown kind"}).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def wait_health(port: int, timeout: int = 60) -> bool:
    for _ in range(timeout * 2):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def post_extract(text: str, tenant_id: str = "t-mock") -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT_WORKER}/mem/extract",
        data=json.dumps({
            "tenant_id": tenant_id, "text": text,
            "metadata": {"source": "mem-router-test"},
        }).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def start_worker(with_router: bool) -> subprocess.Popen:
    env = dict(os.environ)
    env.pop("HUB_LLM_URL", None)
    env.pop("INTERNAL_SECRET", None)
    if with_router:
        env["HUB_LLM_URL"] = f"http://127.0.0.1:{PORT_ROUTER}"
        env["INTERNAL_SECRET"] = SECRET
    worker = subprocess.Popen(
        [WORKER_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(PORT_WORKER)],
        cwd=HERE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return worker


def stop_worker(worker: subprocess.Popen) -> None:
    worker.terminate()
    try:
        worker.wait(timeout=10)
    except Exception:
        worker.kill()


def main() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(("PASS " if cond else "FAIL ") + name + (f" :: {detail}" if detail else ""))
        if not cond:
            failures.append(name)

    if wait_health(PORT_WORKER, timeout=2):
        print(f"FAIL stale worker already listening on {PORT_WORKER} — kill it and re-run")
        return 1
    server = ThreadingHTTPServer(("127.0.0.1", PORT_ROUTER), RouterHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        # --- Case 1: router unconfigured -> rule fallback ---
        worker = start_worker(with_router=False)
        try:
            if not wait_health(PORT_WORKER):
                print("FAIL worker (no router) did not start")
                print(worker.stdout.read() if worker.stdout else "")
                return 1
            s, r = post_extract(NATURAL)
            check("1a unconfigured natural prose -> 200 rule_fallback 0",
                  s == 200 and r.get("ok") is True and r.get("engine") == "rule_fallback"
                  and r.get("count") == 0 and r.get("memories") == [],
                  f"{s} {json.dumps(r)[:300]}")
            check("1b unconfigured note names router_not_configured",
                  "router_not_configured" in str(r.get("note", "")), str(r.get("note", "")))
            s, r = post_extract(PREFERENCE)
            joined = " ".join(m.get("content", "") for m in r.get("memories", [])).lower()
            check("1c unconfigured preference text -> rule_fallback >=1",
                  s == 200 and r.get("engine") == "rule_fallback"
                  and len(r.get("memories", [])) >= 1 and "arjun mehta" in joined,
                  f"{s} {json.dumps(r)[:300]}")
            check("1d unconfigured made no router calls", len(CALLS) == 0, str(len(CALLS)))
        finally:
            stop_worker(worker)

        # --- Case 2: router configured + hub mocked -> llm/router ---
        CALLS.clear()
        MODE["mode"] = "ok"
        worker = start_worker(with_router=True)
        try:
            if not wait_health(PORT_WORKER):
                print("FAIL worker (router) did not start")
                print(worker.stdout.read() if worker.stdout else "")
                return 1
            s, r = post_extract(NATURAL)
            check("2a configured natural prose -> 200 llm/router",
                  s == 200 and r.get("ok") is True and r.get("engine") == "llm/router",
                  f"{s} {json.dumps(r)[:300]}")
            got = sorted(m.get("content", "") for m in r.get("memories", []))
            check("2b configured returns the mocked facts",
                  got == sorted(FACTS), str(got))
            check("2c configured count > 0", r.get("count", 0) == len(FACTS),
                  f"count={r.get('count')}")
            check("2d configured model tag is hub-router/doc_extraction",
                  r.get("model") == "hub-router/doc_extraction", str(r.get("model")))
            kinds = [c.get("kind") for c in CALLS]
            check("2e exactly one doc_extraction call, zero embeddings",
                  kinds.count("doc_extraction") == 1 and kinds.count("embeddings") == 0,
                  str(kinds))
            body = CALLS[0] if CALLS else {}
            check("2f router payload: system + schema + user text",
                  body.get("system") == worker_main.MEM_EXTRACT_SYSTEM
                  and body.get("response_schema") == worker_main.MEM_EXTRACT_SCHEMA
                  and body.get("messages") == [{"role": "user", "text": NATURAL}]
                  and body.get("tenant_id") == "t-mock",
                  json.dumps(body)[:400])

            # --- Case 3: router configured + hub error -> 502, no fallback ---
            MODE["mode"] = "error_ok_false"
            s, r = post_extract(NATURAL)
            check("3a hub ok:false -> 502 mem_extract_failed, no memories",
                  s == 502 and r.get("ok") is False
                  and r.get("error") == "mem_extract_failed"
                  and "memories" not in r,
                  f"{s} {json.dumps(r)[:300]}")
            check("3b hub error code surfaces in detail",
                  "byok_required" in str(r.get("detail", "")), str(r.get("detail", "")))
            MODE["mode"] = "error_http500"
            s, r = post_extract(NATURAL)
            check("3c hub HTTP 500 -> 502 mem_extract_failed, no memories",
                  s == 502 and r.get("ok") is False
                  and r.get("error") == "mem_extract_failed"
                  and "memories" not in r,
                  f"{s} {json.dumps(r)[:300]}")
            check("3d HTTP 500 error code surfaces in detail",
                  "upstream_error" in str(r.get("detail", "")), str(r.get("detail", "")))
        finally:
            stop_worker(worker)
    finally:
        server.shutdown()

    print("MEM ROUTER TEST " + ("PASS" if not failures else f"FAIL ({len(failures)} failed)"))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
