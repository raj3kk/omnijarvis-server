/**
 * ToolRegistry for the Main Executor (mainexec-robustness, §5.2 #3).
 *
 * The R1 loop is fixed-phase (localize → edit → validate → PR) and the
 * model never chose a tool: there was no registry, no args schema, no
 * gate level, and no per-tool trajectory entry. This module is the
 * registry + routing groundwork for that item:
 *
 * - Every tool the loop uses is one entry: name, description, args
 *   schema, gate level (R2 shape: "har tool ek entry (name,
 *   description, args schema, gate level)").
 * - `invokeTool` is the single choke point: it validates args against
 *   the schema BEFORE the handler runs, and the caller (main.ts)
 *   records every invocation in the job transcript (mini-swe
 *   trajectory shape) — args are paths/names only, never file
 *   contents, so no secret or patch content lands in the trajectory.
 * - Gates are enforced where the tool runs, not here: "write" tools
 *   (commit_patches, create_pr) go through the existing isWriteRepo +
 *   token checks in github.ts / main.ts; this registry documents the
 *   gate so a future caller can check it before invoking.
 *
 * What this does NOT do (R2 follow-on, per the plan itself §5.2 #3):
 * model-chosen tool sequencing — the architect emitting tool calls
 * instead of a fixed plan. That is a loop redesign, not a registry,
 * and the plan assigns it to R2. The `edit_file` tool is defined here
 * (gate "llm") but invoked via the existing editor LLM path
 * (callMainLlm), which already logs `llm:editor` trajectory entries —
 * routing it through invokeTool as well would double-log the same
 * call, so it stays on the LLM path until R2 reworks the loop.
 */

export type ToolGate = "read" | "llm" | "write" | "external";

export type ToolArgType = "string" | "number" | "boolean" | "string[]";

export interface ToolArgSchema {
  type: ToolArgType;
  required?: boolean;
  description: string;
}

export interface ToolDefinition {
  name: string;
  description: string;
  gate: ToolGate;
  args: Record<string, ToolArgSchema>;
}

/**
 * The Main Executor's tool surface. Each entry is the contract a
 * caller (today: the fixed-phase step machine; R2: the model) must
 * satisfy before the tool runs.
 */
export const MAIN_TOOLS: ToolDefinition[] = [
  {
    name: "repo_map",
    description: "Build a keyword-ranked symbol map of a repo (line-based v1, ~4,000-token cap) so the architect can plan without dumping whole files.",
    gate: "read",
    args: {
      repo: { type: "string", required: true, description: "owner/name slug" },
      ref: { type: "string", required: true, description: "branch or commit SHA the map is built from" },
    },
  },
  {
    name: "read_file",
    description: "Read one file's current content (snapshot first, else the branch) so the editor has the exact text to rewrite.",
    gate: "read",
    args: {
      path: { type: "string", required: true, description: "repo-relative file path" },
    },
  },
  {
    name: "edit_file",
    description: "Rewrite one file completely via the editor LLM (one planned step, one file). Gate llm: one LLM call per invocation, job LLM budget applies.",
    gate: "llm",
    args: {
      path: { type: "string", required: true, description: "repo-relative file path" },
      action: { type: "string", required: true, description: "what to change, in plain words" },
    },
  },
  {
    name: "scan_edit",
    description: "Scan a proposed file content before commit: forbidden path + secret-shaped values + Python AST scan via the render worker. Blocked findings must go back to the editor as feedback, never silently dropped.",
    gate: "external",
    args: {
      path: { type: "string", required: true, description: "repo-relative file path of the proposed content" },
    },
  },
  {
    name: "commit_patches",
    description: "Commit one or more file contents on the job branch (auto-commit per change). Gate write: allowlisted repos + admin token only; never touches main directly.",
    gate: "write",
    args: {
      files: { type: "string[]", required: true, description: "repo-relative paths being committed" },
      message: { type: "string", required: true, description: "commit headline" },
    },
  },
  {
    name: "ci_poll",
    description: "Poll CI check-runs for a branch ref and return the verdict (pending / success / failure / unknown) with failing-check output for the fix loop.",
    gate: "read",
    args: {
      repo: { type: "string", required: true, description: "owner/name slug" },
      ref: { type: "string", required: true, description: "branch name or commit SHA to check" },
    },
  },
  {
    name: "create_pr",
    description: "Open a pull request with the evidence bundle as its body. Gate write: allowlisted repos + admin token only; the Main Executor never merges — the user merges, always.",
    gate: "write",
    args: {
      title: { type: "string", required: true, description: "PR title" },
      head: { type: "string", required: true, description: "job branch name" },
      base: { type: "string", required: true, description: "base branch (usually main)" },
    },
  },
];

export function getMainTool(name: string): ToolDefinition | undefined {
  return MAIN_TOOLS.find((t) => t.name === name);
}

export function listMainTools(): ToolDefinition[] {
  return [...MAIN_TOOLS];
}

export type ToolArgs = Record<string, unknown>;

function argTypeMatches(type: ToolArgType, value: unknown): boolean {
  if (type === "string") return typeof value === "string";
  if (type === "number") return typeof value === "number";
  if (type === "boolean") return typeof value === "boolean";
  if (type === "string[]") return Array.isArray(value) && value.every((v) => typeof v === "string");
  return false;
}

/**
 * Validate args against the tool's schema. Required fields must be
 * present and of the declared type; optional fields, when present,
 * must match their type. Unknown fields are ignored (forward
 * compatibility — a newer caller may pass more than this version
 * checks).
 */
export function validateToolArgs(
  def: ToolDefinition,
  args: ToolArgs,
): { ok: true } | { ok: false; error: string } {
  for (const [key, schema] of Object.entries(def.args)) {
    const value = args[key];
    if (value === undefined || value === null) {
      if (schema.required) return { ok: false, error: `missing required arg: ${key}` };
      continue;
    }
    if (!argTypeMatches(schema.type, value)) {
      return { ok: false, error: `arg ${key} must be ${schema.type}` };
    }
  }
  return { ok: true };
}

export interface ToolCallOutcome<T> {
  ok: boolean;
  data?: T;
  error?: string;
  /** One short line for the trajectory (no file contents, no secrets). */
  summary: string;
}

export type ToolHandler<T> = (args: ToolArgs) => Promise<ToolCallOutcome<T>>;

/**
 * Single choke point for a tool invocation: schema validation first
 * (the handler never runs on bad args), then the handler, with any
 * throw converted to a failed outcome — a tool failure is a record,
 * never a crash of the step machine.
 */
export async function invokeTool<T>(
  def: ToolDefinition,
  args: ToolArgs,
  handler: ToolHandler<T>,
): Promise<ToolCallOutcome<T>> {
  const valid = validateToolArgs(def, args);
  if (!valid.ok) {
    return { ok: false, error: "invalid_tool_args", summary: valid.error };
  }
  try {
    return await handler(args);
  } catch {
    return { ok: false, error: "tool_failed", summary: "tool threw — see retry note" };
  }
}

/**
 * One-line args summary for the trajectory: names + short values only.
 * File contents are never passed as tool args (the handlers close over
 * them), so this can never leak patch content into the transcript.
 */
export function summarizeToolArgs(args: ToolArgs): string {
  return Object.entries(args)
    .map(([k, v]) => {
      if (Array.isArray(v)) return `${k}=[${v.slice(0, 5).join(", ")}${v.length > 5 ? ", …" : ""}]`;
      return `${k}=${String(v).slice(0, 80)}`;
    })
    .join(", ");
}
