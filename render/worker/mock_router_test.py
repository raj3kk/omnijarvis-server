"""Mock-hub test for POST /mem/extract (mem0 library path).

Starts a fake hub router on 127.0.0.1:18099 that answers the exact
calls mem0 makes (2x doc_extraction LLM + embeddings), then starts the
worker with HUB_LLM_URL + INTERNAL_SECRET + mem0ai on PYTHONPATH and
asserts engine == mem0+hub-router with the canned facts returned.

Usage: python mock_router_test.py  (run from render/worker/)
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
TD = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SITE = os.environ.get("MEM0_SITE") or os.path.join(TD, ".venv-test", "lib", "python3.12", "site-packages")
VENV_PY = "/home/hatch/workspace/omnijarvis-implementation/phase-3/3b/venv/bin/python"
PORT_ROUTER = 18099
PORT_WORKER = 8124
SECRET = "test-secret"

CALLS: list[dict] = []

FACTS = {"facts": ["Arjun Mehta is the user's name", "User likes strong chai"]}
ACTIONS = {"memory": [
    {"id": "0", "text": "Arjun Mehta is the user's name", "event": "ADD"},
    {"id": "1", "text": "User likes strong chai", "event": "ADD"},
]}


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
        CALLS.append({"kind": body.get("kind")})
        kind = body.get("kind")
        if kind == "embeddings":
            payload = {"ok": True, "embedding": [0.01] * 16}
        elif kind == "doc_extraction":
            user_texts = [m.get("text", "") for m in body.get("messages", []) if m.get("role") == "user"]
            last_user = user_texts[-1] if user_texts else ""
            if "## New Messages" in last_user:
                # mem0 2.x additive extraction: {"memory": [{text, event}]}
                payload = {"ok": True, "text": json.dumps(ACTIONS)}
            elif last_user.lstrip().startswith("Input:"):
                payload = {"ok": True, "text": json.dumps(FACTS)}
            elif "new retrieved facts are mentioned" in last_user:
                payload = {"ok": True, "text": json.dumps(ACTIONS)}
            else:
                payload = {"ok": False, "error": "mock: unknown extraction call"}
        else:
            payload = {"ok": False, "error": "mock: unknown kind"}
        data = json.dumps(payload).encode()
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


def main() -> int:
    # Fail fast if a stale worker still holds the port (a previous run
    # killed mid-flight can leave one behind; its old code would answer
    # with 404s and confuse the assertions below).
    if wait_health(PORT_WORKER, timeout=2):
        print(f"FAIL stale worker already listening on {PORT_WORKER} — kill it and re-run")
        return 1
    server = ThreadingHTTPServer(("127.0.0.1", PORT_ROUTER), RouterHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ)
    env["HUB_LLM_URL"] = f"http://127.0.0.1:{PORT_ROUTER}"
    env["INTERNAL_SECRET"] = SECRET
    env["PYTHONPATH"] = SITE + ":" + env.get("PYTHONPATH", "")
    worker = subprocess.Popen(
        [VENV_PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(PORT_WORKER)],
        cwd=HERE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_health(PORT_WORKER):
            print("FAIL worker did not start")
            print(worker.stdout.read() if worker.stdout else "")
            return 1
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT_WORKER}/mem/extract",
            data=json.dumps({
                "tenant_id": "t-mock",
                "text": "My name is Arjun Mehta. I like strong chai.",
                "metadata": {"source": "mock-router-test"},
            }).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                status, result = resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            status, result = e.code, json.loads(e.read().decode())
        print(f"status={status} result={json.dumps(result)[:500]}")
        print(f"router calls: {CALLS}")
        ok = True
        if status != 200 or result.get("ok") is not True:
            print("FAIL mem/extract not ok")
            ok = False
        if result.get("engine") != "mem0+hub-router":
            print(f"FAIL engine={result.get('engine')!r} (want mem0+hub-router)")
            ok = False
        got = sorted(m.get("content", "") for m in result.get("memories", []))
        want = sorted(["Arjun Mehta is the user's name", "User likes strong chai"])
        if got != want:
            print(f"FAIL memories={got} (want {want})")
            ok = False
        kinds = [c["kind"] for c in CALLS]
        # 1.x makes 2 doc_extraction calls (facts + actions); 2.x makes 1
        # (additive extraction). Either is fine — assert at least one of
        # each kind happened.
        if kinds.count("doc_extraction") < 1:
            print(f"FAIL expected >=1 doc_extraction call, got {kinds}")
            ok = False
        if kinds.count("embeddings") < 1:
            print(f"FAIL expected >=1 embeddings call, got {kinds}")
            ok = False
        print("MOCK ROUTER TEST " + ("PASS" if ok else "FAIL"))
        return 0 if ok else 1
    finally:
        worker.terminate()
        try:
            worker.wait(timeout=10)
        except Exception:
            worker.kill()
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
