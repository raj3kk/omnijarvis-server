/**
 * Anthropic Skills format tests (completeness #9).
 * SKILL.md frontmatter (name/description/allowed-tools) is accepted
 * alongside the v1 JSON manifest; malformed input is rejected.
 */
import { describe, expect, it } from "vitest";
import { parseAnthropicSkillMd, validateSkillManifest } from "../src/skills";

const VALID_MD = `---
name: pdf-extract
description: Extract text and tables from PDF files.
allowed-tools: Read, Grep, Bash
---

# PDF Extract

Follow these steps to extract text from a PDF file.
`;

const VALID_MD_LIST_TOOLS = `---
name: code-review
description: Review code for bugs.
allowed-tools:
  - Read
  - Grep
---

# Code Review

Review the code.
`;

describe("parseAnthropicSkillMd — valid documents", () => {
  it("comma-separated allowed-tools -> normalised v1 manifest with defaults", () => {
    const r = parseAnthropicSkillMd(VALID_MD);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.manifest.format).toBe("anthropic");
    expect(r.manifest.name).toBe("pdf-extract");
    expect(r.manifest.description).toBe("Extract text and tables from PDF files.");
    expect(r.manifest.version).toBe("1.0.0");
    expect(r.manifest.trigger).toBe("pdf-extract");
    expect(r.manifest.steps).toEqual([{ action: "follow-skill-instructions" }]);
    expect(r.manifest.allowed_tools).toEqual(["Read", "Grep", "Bash"]);
    expect(r.manifest.instructions).toContain("# PDF Extract");
    expect(r.manifest.instructions).toContain("extract text from a PDF file");
  });

  it("YAML-list allowed-tools -> same normalisation; quoted values unquoted", () => {
    const r = parseAnthropicSkillMd(VALID_MD_LIST_TOOLS);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.manifest.allowed_tools).toEqual(["Read", "Grep"]);
  });

  it("no allowed-tools -> empty array (optional field)", () => {
    const md = `---\nname: plain-skill\ndescription: Does a thing.\n---\n\n# Plain\n\nDo it.\n`;
    const r = parseAnthropicSkillMd(md);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.manifest.allowed_tools).toEqual([]);
  });
});

describe("parseAnthropicSkillMd — malformed input rejected", () => {
  it.each([
    ["no frontmatter at all", "# Just markdown\n\nNo frontmatter here.\n", "frontmatter"],
    ["unclosed frontmatter", "---\nname: x\ndescription: y\n", "not closed"],
    ["missing name", "---\ndescription: Only a description.\n---\n\n# Body\n", "name"],
    ["missing description", "---\nname: x\n---\n\n# Body\n", "description"],
    ["empty name", "---\nname: \ndescription: y\n---\n\n# Body\n", "name"],
    ["empty body", "---\nname: x\ndescription: y\n---\n", "body"],
    ["empty file", "", "empty"],
    ["bad frontmatter line (no colon)", "---\nname: x\ndescription: y\njust some words\n---\n\n# Body\n", "key: value"],
    ["duplicate key", "---\nname: x\nname: y\ndescription: z\n---\n\n# Body\n", "duplicate"],
    ["allowed-tools empty entry", "---\nname: x\ndescription: y\nallowed-tools: Read,, Grep\n---\n\n# Body\n", "allowed-tools"],
  ])("%s -> error mentioning the field", (_label, md, needle) => {
    const r = parseAnthropicSkillMd(md);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain(needle);
  });
});

describe("validateSkillManifest — Anthropic shapes via the same gate", () => {
  it("raw SKILL.md string validates through validateSkillManifest", () => {
    const r = validateSkillManifest(VALID_MD);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.manifest.name).toBe("pdf-extract");
  });

  it("object with format:anthropic validates; hyphen key normalises; explicit version/trigger kept", () => {
    const r = validateSkillManifest({
      format: "anthropic",
      name: "my-skill",
      description: "Does things.",
      "allowed-tools": "Read, Bash",
      version: "2.3.0",
      trigger: "review this",
      instructions: "# My Skill\n\nDo it.",
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.manifest.version).toBe("2.3.0");
    expect(r.manifest.trigger).toBe("review this");
    expect(r.manifest.allowed_tools).toEqual(["Read", "Bash"]);
    expect("allowed-tools" in r.manifest).toBe(false);
  });

  it("anthropic object missing description / bad allowed_tools rejected", () => {
    expect(validateSkillManifest({ format: "anthropic", name: "x" })).toMatchObject({ ok: false });
    expect(
      validateSkillManifest({ format: "anthropic", name: "x", description: "y", allowed_tools: ["Read", ""] }),
    ).toMatchObject({ ok: false });
    expect(
      validateSkillManifest({ format: "anthropic", name: "x", description: "y", allowed_tools: "not-an-array-or-string-ok" }),
    ).toMatchObject({ ok: true }); // a plain string is a valid comma list
  });

  it("v1 manifest rules unchanged (regression)", () => {
    const v1 = {
      name: "v1-skill",
      version: "1.0.0",
      trigger: "run it",
      steps: [{ action: "do-thing" }],
      description: "v1 skill",
    };
    expect(validateSkillManifest(v1)).toMatchObject({ ok: true });
    expect(validateSkillManifest({ ...v1, version: "" })).toMatchObject({ ok: false });
    expect(validateSkillManifest({ ...v1, steps: [] })).toMatchObject({ ok: false });
  });
});
