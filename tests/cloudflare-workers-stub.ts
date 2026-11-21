/**
 * Test stub for the `cloudflare:workers` runtime module.
 * Vitest aliases "cloudflare:workers" -> this file (vitest.config.ts).
 * Mirrors the real base class: constructor stores state (as `ctx` in
 * the real class; the stub also exposes `state` for the DO code).
 */
export class DurableObject {
  ctx: unknown;
  state: unknown;
  env: unknown;
  constructor(state: unknown, env: unknown) {
    this.ctx = state;
    this.state = state;
    this.env = env;
  }
}
