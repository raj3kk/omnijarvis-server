"""Adapter test for the Browser-Use router chat model (Track D, #18).

No Chromium, no hub, no network beyond localhost: starts a mock hub
router, builds main._RouterChatModel, and asserts:
  1. ainvoke() with no output_format returns ChatInvokeCompletion[str].
  2. ainvoke() with a pydantic output_format sends its JSON schema and
     returns a validated instance.
  3. Agent(task, llm, browser_session, use_vision=False) constructs.
  4. _bu_message_text extracts text from browser-use messages.
Run with the 3b venv python + PYTHONPATH including the .venv-test
site-packages (browser-use lives there):
  PYTHONPATH=<track-d>/.venv-test/lib/python3.12/site-packages \
    <3b venv>/bin/python browse_adapter_test.py
"""
import asyncio
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import main as worker_main  # noqa: E402

PORT = 18098
SECRET = "test-secret"
SEEN: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        SEEN.append(body)
        if body.get("kind") == "agent_plan":
            schema = body.get("response_schema") or {}
            props = (schema.get("properties") or {})
            if "evaluation_previous_goal" in props or "action" in props:
                # AgentOutput-shaped request: return a minimal valid action.
                payload = {"ok": True, "text": json.dumps({
                    "current_state": {"evaluation_previous_goal": "ok", "memory": "", "next_goal": "done"},
                    "action": [{"done": {"text": "finished", "success": True}}],
                })}
            else:
                payload = {"ok": True, "text": "hello from mock router"}
        else:
            payload = {"ok": False, "error": "mock: unknown kind"}
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


async def main_async() -> int:
    worker_main.HUB_LLM_URL = f"http://127.0.0.1:{PORT}"
    worker_main.INTERNAL_SECRET = SECRET
    from browser_use.llm.messages import SystemMessage, UserMessage
    from pydantic import BaseModel

    # 4. message text extraction
    assert worker_main._bu_message_text(UserMessage(content="do the thing")) == "do the thing"
    assert worker_main._bu_message_text(SystemMessage(content="sys")) == "sys"
    print("PASS _bu_message_text")

    llm = worker_main._RouterChatModel.build("t1", "turn-1")
    # 1. plain text call
    res = await llm.ainvoke([SystemMessage(content="sys"), UserMessage(content="hi")])
    assert res.completion == "hello from mock router", res.completion
    assert SEEN[-1]["kind"] == "agent_plan" and "response_schema" not in SEEN[-1]
    print("PASS ainvoke plain text -> ChatInvokeCompletion[str]")

    # 2. structured call with a pydantic model
    class Tiny(BaseModel):
        evaluation_previous_goal: str = ""
        answer: str = ""

    res2 = await llm.ainvoke([UserMessage(content="answer me")], output_format=Tiny)
    assert isinstance(res2.completion, Tiny), type(res2.completion)
    assert "response_schema" in SEEN[-1], "schema was not sent to router"
    print("PASS ainvoke structured -> validated pydantic instance, schema sent")

    # 3. Agent constructs with the router LLM (no browser launch yet)
    from browser_use import Agent, BrowserSession

    agent = Agent(task="Say hello", llm=llm, browser_session=BrowserSession(headless=True),
                  use_vision=False)
    assert agent.task == "Say hello"
    print("PASS Agent constructs with router LLM + BrowserSession(headless=True)")
    return 0


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        return asyncio.run(main_async())
    finally:
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
