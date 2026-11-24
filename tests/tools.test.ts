import { describe, expect, it } from "vitest";
import {
  getMainTool,
  invokeTool,
  listMainTools,
  summarizeToolArgs,
  validateToolArgs,
  type ToolDefinition,
} from "../src/tools";

describe("ToolRegistry (§5.2 #3): every loop tool is one entry", () => {
  it("lists the 7 tools with name, description, args schema, gate", () => {
    const tools = listMainTools();
    expect(tools).toHaveLength(7);
    expect(tools.map((t) => t.name).sort()).toEqual(
      ["ci_poll", "commit_patches", "create_pr", "edit_file", "read_file", "repo_map", "scan_edit"].sort(),
    );
    for (const t of tools) {
      expect(t.description.length).toBeGreaterThan(10);
      expect(Object.keys(t.args).length).toBeGreaterThan(0);
      expect(["read", "llm", "write", "external"]).toContain(t.gate);
      for (const arg of Object.values(t.args)) {
        expect(["string", "number", "boolean", "string[]"]).toContain(arg.type);
        expect(arg.description.length).toBeGreaterThan(0);
      }
    }
    // Write tools are the gate that matters: only the two GitHub writes.
    expect(tools.filter((t) => t.gate === "write").map((t) => t.name).sort()).toEqual([
      "commit_patches",
      "create_pr",
    ]);
    expect(getMainTool("scan_edit")?.gate).toBe("external");
    expect(getMainTool("repo_map")?.gate).toBe("read");
    expect(getMainTool("nope")).toBeUndefined();
  });

  it("validateToolArgs: missing required / wrong type fail; optional may be absent", () => {
    const def = getMainTool("commit_patches") as ToolDefinition;
    expect(validateToolArgs(def, { files: ["a.ts"], message: "x" }).ok).toBe(true);
    const missing = validateToolArgs(def, { files: ["a.ts"] });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toContain("message");
    const wrongType = validateToolArgs(def, { files: "a.ts", message: "x" });
    expect(wrongType.ok).toBe(false);
    if (!wrongType.ok) expect(wrongType.error).toContain("string[]");
    const badItem = validateToolArgs(def, { files: ["a.ts", 3], message: "x" });
    expect(badItem.ok).toBe(false);
    // Unknown fields are ignored (forward compatibility).
    expect(validateToolArgs(def, { files: [], message: "x", future: true }).ok).toBe(true);
  });

  it("invokeTool: validates before the handler, converts throws to failed outcomes", async () => {
    const def = getMainTool("read_file") as ToolDefinition;
    let called = false;
    const ok = await invokeTool(def, { path: "src/x.ts" }, async () => {
      called = true;
      return { ok: true, data: "content", summary: "1 B" };
    });
    expect(called).toBe(true);
    expect(ok).toEqual({ ok: true, data: "content", summary: "1 B" });

    called = false;
    const bad = await invokeTool(def, {}, async () => {
      called = true;
      return { ok: true, data: "x", summary: "x" };
    });
    expect(called).toBe(false);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.error).toBe("invalid_tool_args");

    const threw = await invokeTool(def, { path: "src/x.ts" }, async () => {
      throw new Error("boom");
    });
    expect(threw.ok).toBe(false);
    if (!threw.ok) expect(threw.error).toBe("tool_failed");
  });

  it("summarizeToolArgs: names + short values only, arrays capped", () => {
    expect(summarizeToolArgs({ path: "src/x.ts" })).toBe("path=src/x.ts");
    expect(summarizeToolArgs({ files: ["a", "b", "c", "d", "e", "f"] })).toBe(
      "files=[a, b, c, d, e, …]",
    );
    expect(summarizeToolArgs({ title: "x".repeat(200) }).length).toBeLessThan(100);
  });
});
