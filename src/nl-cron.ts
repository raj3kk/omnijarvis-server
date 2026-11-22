/**
 * nl-cron.ts — M-I-30: in-app cron, natural-language → cron expression.
 *
 * Two stages, deterministic first:
 *   1. `parseNaturalCron` — pure, deterministic patterns for the common
 *      Hinglish/English shapes ("har subah 8 baje", "every Monday 9am",
 *      "har 15 minute", "har mahine ki 1 tarikh subah 9 baje"). No LLM,
 *      no network, no cost. Times are the USER'S LOCAL time; the caller
 *      passes `utcOffsetMinutes` (IST = +330) and the parser converts to
 *      UTC — cron itself is UTC-canonical server-side (cron.ts).
 *      Conversion is done by anchoring: the NEXT local occurrence of the
 *      requested day/time is computed, then its UTC fields become the
 *      expression (so a Sunday 00:30 IST job correctly becomes Saturday
 *      19:00 UTC). Interval expressions (har 15 minute) are
 *      timezone-independent and need no conversion.
 *   2. LLM fallback — the hub route calls routeLlm (kind quick_command)
 *      with a strict output contract ("reply with ONLY the cron
 *      expression, or NO_TIME"); `llmParseCronText` extracts + validates
 *      the reply. An unvalidated expression is NEVER emitted: every
 *      candidate, deterministic or LLM, must pass nextCronRun() (the same
 *      5-field parser the tick uses) or the parse fails as `unparseable`.
 */
import { nextCronRun } from "./cron";

export interface ParsedCron {
  cron_expr: string;
  source: "deterministic" | "llm";
  next_run_at: number;
}

export interface ParseOpts {
  /** User's local offset from UTC in minutes (IST = +330). Default 0 (UTC). */
  utcOffsetMinutes?: number;
  nowMs?: number;
}

const WEEKDAYS: Record<string, number> = {
  sunday: 0, ravivar: 0, sun: 0,
  monday: 1, somvar: 1, mon: 1,
  tuesday: 2, mangalvar: 2, tue: 2,
  wednesday: 3, budhvar: 3, wed: 3,
  thursday: 4, guruvar: 4, guruwar: 4, thu: 4,
  friday: 5, shukravar: 5, fri: 5,
  saturday: 6, shanivar: 6, sat: 6,
};

function normalize(text: string): string {
  return text
    .toLowerCase()
    .replace(/[।.,;!?]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Find a weekday name in the text (longest match wins: "monday" over "mon"). */
function findWeekday(text: string): number | null {
  let found: number | null = null;
  let foundLen = 0;
  for (const [name, dow] of Object.entries(WEEKDAYS)) {
    const m = text.match(new RegExp(`\\b${name}\\b`));
    if (m && name.length > foundLen) {
      found = dow;
      foundLen = name.length;
    }
  }
  return found;
}

/** Parse a time-of-day out of the text. Returns local {hour, minute} or null.
 * Dayparts: subah/morning -> am, dopahar/afternoon/shaam/evening/raat/night -> pm.
 * "baje" is a neutral marker. Bare "8" with no marker = 8:00 as written.
 * A marker time (9 baje / 9am / 9:30) always wins over a bare number —
 * otherwise "har mahine ki 1 tarikh subah 9 baje" would read hour=1 from
 * the date. Callers with competing numbers (monthly) pass requireMarker. */
function findTime(text: string, requireMarker = false): { hour: number; minute: number } | null {
  const daypartPm = /\b(dopahar|afternoon|shaam|evening|raat|night)\b/.test(text);
  const night = /\b(raat|night)\b/.test(text);
  const daypartAm = /\b(subah|morning)\b/.test(text);
  const marked = text.match(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm|baje)\b/);
  const m = marked ?? (requireMarker ? null : text.match(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b/));
  if (!m) return null;
  let hour = Number(m[1]);
  const minute = m[2] ? Number(m[2]) : 0;
  // "baje" is a neutral marker, not am/pm — only am/pm convert.
  const ampm = m[3] === "am" || m[3] === "pm" ? (m[3] as "am" | "pm") : undefined;
  if (minute > 59) return null;
  if (ampm === "pm" && hour < 12) hour += 12;
  else if (ampm === "am" && hour === 12) hour = 0;
  else if (!ampm && daypartPm && hour === 12 && night) hour = 0; // "raat 12 baje" = midnight, not noon
  else if (!ampm && daypartPm && hour < 12) hour += 12;
  else if (!ampm && daypartAm && hour === 12) hour = 0;
  if (hour < 0 || hour > 23) return null;
  return { hour, minute };
}

/**
 * Next local occurrence (ms, true UTC epoch) of the requested local
 * day/time AFTER nowMs. `local` is the now instant shifted into the
 * user's frame (nowMs + offset), so its UTC getters read LOCAL fields.
 * kind: daily (any day), weekly (dow), monthly (dom).
 */
function nextLocalOccurrence(
  nowMs: number,
  offsetMs: number,
  hour: number,
  minute: number,
  kind: { type: "daily" } | { type: "weekly"; dow: number } | { type: "monthly"; dom: number },
): number {
  const local = new Date(nowMs + offsetMs);
  const at = (y: number, mo: number, d: number): number => {
    // ms (in the shifted frame) of local y-mo-d at hour:minute.
    return Date.UTC(y, mo, d, hour, minute) - offsetMs;
  };
  const y = local.getUTCFullYear();
  const mo = local.getUTCMonth();
  const d = local.getUTCDate();
  if (kind.type === "daily") {
    let c = at(y, mo, d);
    if (c <= nowMs) c = at(y, mo, d + 1);
    return c;
  }
  if (kind.type === "weekly") {
    const todayDow = local.getUTCDay();
    let delta = (kind.dow - todayDow + 7) % 7;
    let c = at(y, mo, d + delta);
    if (c <= nowMs) c = at(y, mo, d + delta + 7);
    return c;
  }
  // monthly: this month's dom, else next month's (Date.UTC normalises
  // overflow, e.g. Feb 31 -> Mar 3 — the UTC fields of the result are
  // what the expression uses, so it stays valid).
  let c = at(y, mo, kind.dom);
  if (c <= nowMs) c = at(y, mo + 1, kind.dom);
  return c;
}

/** Build + validate the expression from a UTC instant's fields. */
function exprFromUtcInstant(
  instantMs: number,
  dom: string,
  dow: string,
  nowMs: number,
  source: ParsedCron["source"],
): ParsedCron | null {
  const u = new Date(instantMs);
  const expr = `${u.getUTCMinutes()} ${u.getUTCHours()} ${dom} * ${dow}`;
  const next = nextCronRun(expr, nowMs);
  if (next === null) return null;
  return { cron_expr: expr, source, next_run_at: next };
}

function validInterval(n: number, max: number): boolean {
  return Number.isInteger(n) && n >= 1 && n <= max;
}

export function parseNaturalCron(text: string, opts: ParseOpts = {}): ParsedCron | null {
  const nowMs = opts.nowMs ?? Date.now();
  const offsetMs = (opts.utcOffsetMinutes ?? 0) * 60_000;
  const t = normalize(text);
  if (!t) return null;

  // --- Interval shapes (timezone-independent, no anchor needed) ---
  const minMatch = t.match(/\b(?:har|every)\s+(\d+)\s*(?:minute|minutes|min|mint)\b/);
  if (minMatch) {
    const n = Number(minMatch[1]);
    if (!validInterval(n, 59)) return null;
    const expr = `*/${n} * * * *`;
    const next = nextCronRun(expr, nowMs);
    return next === null ? null : { cron_expr: expr, source: "deterministic", next_run_at: next };
  }
  const hourMatch = t.match(/\b(?:har|every)\s+(\d+)\s*(?:ghante|ghanta|hour|hours)\b/);
  if (hourMatch) {
    const n = Number(hourMatch[1]);
    if (!validInterval(n, 23)) return null;
    const expr = `0 */${n} * * *`;
    const next = nextCronRun(expr, nowMs);
    return next === null ? null : { cron_expr: expr, source: "deterministic", next_run_at: next };
  }
  if (/\b(?:har ghante|every hour)\b/.test(t)) {
    const time = findTime(t);
    const minute = time ? time.minute : 0;
    const expr = `${minute} * * * *`;
    const next = nextCronRun(expr, nowMs);
    return next === null ? null : { cron_expr: expr, source: "deterministic", next_run_at: next };
  }

  // --- Absolute-time shapes (need a time; default 09:00 when the text
  // names a day but no time, e.g. "har Somvar" alone) ---
  const time = findTime(t);
  const weekday = findWeekday(t);
  const isWeekdays = /\b(?:weekdays|somvar se shukravar|monday to friday)\b/.test(t);
  const isWeekend = /\bweekend\b/.test(t);
  const domMatch = t.match(/\b(?:har mahine|every month)(?:\s+(?:ki|on|of)?\s*(\d{1,2})(?:st|nd|rd|th)?\s*(?:tarikh|date|day)?)?/);

  if (domMatch) {
    const dom = domMatch[1] ? Number(domMatch[1]) : 1;
    if (dom < 1 || dom > 31) return null;
    // requireMarker: "1 tarikh" is a date, not a time — without a real
    // time marker the job runs at the 09:00 default.
    const tm = findTime(t, true) ?? { hour: 9, minute: 0 };
    const next = nextLocalOccurrence(nowMs, offsetMs, tm.hour, tm.minute, { type: "monthly", dom });
    return exprFromUtcInstant(next, String(new Date(next).getUTCDate()), "*", nowMs, "deterministic");
  }
  if (weekday !== null) {
    const tm = time ?? { hour: 9, minute: 0 };
    const next = nextLocalOccurrence(nowMs, offsetMs, tm.hour, tm.minute, { type: "weekly", dow: weekday });
    return exprFromUtcInstant(next, "*", String(new Date(next).getUTCDay()), nowMs, "deterministic");
  }
  if (isWeekdays || isWeekend) {
    const tm = time ?? { hour: 9, minute: 0 };
    const next = nextLocalOccurrence(nowMs, offsetMs, tm.hour, tm.minute, { type: "daily" });
    return exprFromUtcInstant(next, "*", isWeekdays ? "1-5" : "0,6", nowMs, "deterministic");
  }
  // Daily: "har din / roz / daily / every day / har subah / har raat ..."
  // or a bare time ("8 baje" alone = daily at 8:00).
  if (
    /\b(?:har din|roz|daily|every day|har subah|har raat|har dopahar|har shaam|har roz|every morning|every night)\b/.test(t) ||
    time !== null
  ) {
    if (!time) return null;
    const next = nextLocalOccurrence(nowMs, offsetMs, time.hour, time.minute, { type: "daily" });
    return exprFromUtcInstant(next, "*", "*", nowMs, "deterministic");
  }
  return null;
}

/**
 * LLM fallback: extract + validate the model's reply. Strict contract —
 * the reply must be ONLY a 5-field cron expression, or NO_TIME. Anything
 * else (prose, a 6-field expr, an invalid expr) is unparseable; the
 * caller returns 422 and NEVER emits the text. The first cron-shaped
 * token in the reply wins (models sometimes add a word around it).
 */
export function llmParseCronText(replyText: string, nowMs: number, source: ParsedCron["source"] = "llm"): ParsedCron | null {
  const text = (replyText ?? "").trim();
  if (!text || /^no_time$/i.test(text)) return null;
  const m = text.match(/((?:\*|[0-9,\-\/]+)\s+){4}(?:\*|[0-9,\-\/]+)/);
  if (!m) return null;
  const expr = m[0].trim().replace(/\s+/g, " ");
  if (expr.split(" ").length !== 5) return null;
  const next = nextCronRun(expr, nowMs);
  if (next === null) return null;
  return { cron_expr: expr, source, next_run_at: next };
}

/** System prompt for the LLM fallback (routeLlm kind quick_command). */
export function cronLlmSystemPrompt(utcOffsetMinutes: number): string {
  const sign = utcOffsetMinutes >= 0 ? "+" : "-";
  const abs = Math.abs(utcOffsetMinutes);
  const hh = Math.floor(abs / 60);
  const mm = abs % 60;
  const off = `UTC${sign}${hh}:${String(mm).padStart(2, "0")}`;
  return (
    "You convert a scheduling request into a 5-field cron expression " +
    "(minute hour day-of-month month day-of-week, in UTC). " +
    `The user's local time is ${off}; convert local times to UTC. ` +
    "Reply with ONLY the cron expression, nothing else. " +
    "If the request has no clear time or frequency, reply with exactly: NO_TIME"
  );
}
