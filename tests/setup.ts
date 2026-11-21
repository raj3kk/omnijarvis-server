/**
 * Vitest setup — Workers-only globals stubbed BEFORE test modules load.
 * (JarvisHub's `extends DurableObject` evaluates at import time, so
 * these must live here, not in a test file.)
 */
import { FakeWebSocket } from "./fake-do";

// WebSocketPair: the DO uses pair[1] (server side); pair[0] goes to the
// client Response.
class FakeWebSocketPair {
  0: FakeWebSocket;
  1: FakeWebSocket;
  constructor() {
    this[0] = new FakeWebSocket();
    this[1] = new FakeWebSocket();
  }
}
(globalThis as unknown as { WebSocketPair: typeof FakeWebSocketPair }).WebSocketPair =
  FakeWebSocketPair;

// Node's Response rejects status 101 — the DO's WS upgrade returns one.
// Shim it: build a 200 Response, then shadow `status` with 101 and keep
// the webSocket on the instance (test-only, Workers behaviour unchanged).
const NativeResponse = Response;
class TestResponse extends NativeResponse {
  declare webSocket: WebSocket | null;
  constructor(
    body: BodyInit | null,
    init?: ResponseInit & { webSocket?: unknown },
  ) {
    if (init?.status === 101) {
      super(body, { status: 200, headers: init.headers });
      this.webSocket = init.webSocket as WebSocket | null;
      Object.defineProperty(this, "status", { value: 101 });
    } else {
      super(body, init);
    }
  }
}
(globalThis as unknown as { Response: typeof TestResponse }).Response = TestResponse;

// DurableObject base class comes from the "cloudflare:workers" module
// (aliased to a stub in vitest) — no global stub needed here.
