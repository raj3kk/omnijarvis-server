/**
 * JarvisHub — Durable Object, one per device (id = device:<device_id>).
 *
 * Stage 2a-1 skeleton: WebSocket hibernation handlers only.
 * Presence / sessions table / pending_steps / dispatch land in 2a-2.
 *
 * Hibernation API ONLY — state.acceptWebSocket() + webSocketMessage /
 * webSocketClose / webSocketError handlers. Plain accept() + manual
 * listeners KABHI NAHI (poora connected time duration charge hota hai).
 */
import type { Env } from "../hub";

export class JarvisHub {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const text = typeof message === "string" ? message : "";
    ws.send(JSON.stringify({ type: "PONG", echo: text.slice(0, 100) }));
  }

  async webSocketClose(
    _ws: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ): Promise<void> {
    // 2a-2: sessions table se hatao + last_seen update karo.
  }

  async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
    try {
      ws.close(1011, "error");
    } catch {
      // already closed
    }
  }
}
