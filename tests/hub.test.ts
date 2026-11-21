import { describe, expect, it } from "vitest";
import { route } from "../src/hub";

describe("hub routing (2a-1 skeleton)", () => {
  it("GET /health -> 200 ok:true", async () => {
    const res = route("/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.ok).toBe(true);
    expect(body.service).toBe("omnijarvis-hub");
    expect(body.version).toBe("2a-1");
  });

  it("GET / -> 200", () => {
    expect(route("/").status).toBe(200);
  });

  it("unknown path -> 404 not_found", async () => {
    const res = route("/nope");
    expect(res.status).toBe(404);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.error).toBe("not_found");
  });
});
