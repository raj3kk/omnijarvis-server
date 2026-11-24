/**
 * skills-catalog.ts — server-side skill LIBRARY (GAP-FILL: skills library).
 *
 * RE doc §2.4: Muse has 40+ skills (playbooks). Jarvis had only local
 * skill manifests + self-extension submit (quarantine + scan + approval).
 * There was no LIBRARY — nothing to browse, no catalog, no starter
 * skills. R1 added the plumbing (/api/skills/sync + /api/skills/approve
 * + FCM skill_approved + the submit cap) but the library itself stayed
 * empty: /api/skills/library lists only approved USER-SUBMITTED skills
 * from global_skills.
 *
 * This file is the other half: a curated, server-authored catalog
 * (D1 `skill_catalog`, migration 0018) + per-tenant installs
 * (`skill_catalog_installs`). The app browse/install UI lands on top
 * of these handlers (separate app-side piece).
 *
 * Design rules (locked pricing, MUSE_SELF_INTERROGATION §2.4 + D2):
 *  - Free = 1 skill. Pro/Business = the library (planLimits().skills:
 *    free 1, pro/business MAX_SAFE_INTEGER).
 *  - Each catalog row carries a minimum `tier` (free/pro/business).
 *    The list is tier-filtered: a tenant sees only rows its plan
 *    reaches. The install enforces BOTH the tier AND the cap.
 *  - Catalog skills are SERVER-AUTHORED content (seeded by migration
 *    0018), not user submissions: they never pass through the
 *    quarantine flow (global_skills) and never need a scan or a
 *    signature. Their manifests are validated at authoring time by
 *    validateSkillManifest (tests assert every seed manifest passes).
 *  - Manifest format is the SAME v1 JSON the app already parses from
 *    /api/skills/sync: name/version/trigger/steps + description +
 *    Anthropic normal form (format "anthropic", allowed_tools,
 *    instructions). Two extra keys ride on every catalog manifest:
 *    `args` (the skill's input schema) and `gate` (the execution gate
 *    the phone must clear before running it: "none" | "confirm" |
 *    "approval"). Extra keys are allowed by the frozen schema.
 *  - Install is idempotent (a repeat install of the same skill is
 *    ok:true + deduped:true) and traced (skill_catalog_install).
 *
 * Hub routes live in hub.ts (pages coordinator owns the route table);
 * the exact registration snippet is in BUILD_NOTES.md (work/
 * skills-library). Routes: GET /api/skills/catalog (list) and POST
 * /api/skills/catalog/install. Both are device-signed
 * (authorizeDocsRequest, frozen payloads `catalog:<tenant_id>` and
 * `catalog-install:<tenant_id>:<skill_id>`) or x-internal-secret.
 */
import type { D1Like } from "./db";
import { insertTrace } from "./db";
import { planLimits } from "./router";
import { type SkillManifest, validateSkillManifest } from "./skills";

/** Minimum plan tier that may see/install a catalog skill. */
export type CatalogTier = "free" | "pro" | "business";

/** Tier rank: higher sees everything lower reaches. */
export const CATALOG_TIER_RANK: Record<string, number> = {
	free: 0,
	pro: 1,
	business: 2,
};

/** Unknown tier strings rank as free (planLimits() fallback precedent). */
export function catalogTierRank(tier: string): number {
	return CATALOG_TIER_RANK[tier] ?? 0;
}

/** Execution gate a skill needs before the phone runs it. */
export type SkillGate = "none" | "confirm" | "approval";

/**
 * One starter skill: the catalog row + its manifest. `created_at` is
 * derived, not stored here: seedCreatedAt(index) = CATALOG_SEED_EPOCH
 * + index * 1000, so the migration SQL and the code seed agree exactly
 * (tests/skills-catalog.test.ts asserts the SQL rows match this list).
 */
export interface StarterSkill {
	id: string;
	name: string;
	description: string;
	category: string;
	tier: CatalogTier;
	manifest: SkillManifest;
}

/** Seed epoch: 2026-11-24T00:00:00Z (migration 0018 generation date). */
export const CATALOG_SEED_EPOCH = Date.UTC(2026, 10, 24);

export function seedCreatedAt(index: number): number {
	return CATALOG_SEED_EPOCH + index * 1000;
}

/**
 * The 12 starter skills (Muse's most-used skills, mapped to Jarvis).
 * Every manifest is a REAL Anthropic-normal-form v1 manifest: name,
 * description, version, trigger, steps (single follow-skill-instructions
 * pointer), allowed_tools, instructions (the playbook body), args (the
 * input schema) and gate. No placeholders: instructions reference only
 * Jarvis-real capabilities (hub routes /api/google/*, /api/docs/*,
 * the WebView browser, the hub LLM router, on-device speech
 * recognition). Where Jarvis cannot do something (WhatsApp/SMS,
 * auto-purchase, live Places API), the instructions say so plainly.
 *
 * Tier split: Free sees 3 (the daily drivers — email, scheduling,
 * web research) and may install 1 of them; the other 9 are Pro, i.e.
 * the library is the Pro selling point per the locked pricing.
 */
export const STARTER_SKILLS: StarterSkill[] = [
	{
		id: "cat-email-management",
		name: "email-management",
		description:
			"Read, search, draft and send email on the connected Gmail account. Use when the user asks about an email, wants a reply drafted, or wants mail sent.",
		category: "communication",
		tier: "free",
		manifest: {
			format: "anthropic",
			name: "email-management",
			description:
				"Read, search, draft and send email on the connected Gmail account. Use when the user asks about an email, wants a reply drafted, or wants mail sent.",
			version: "1.0.0",
			trigger: "email",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["gmail-messages", "gmail-send"],
			instructions:
				"Email management for the user's connected Gmail account (hub routes /api/google/gmail/messages and /api/google/gmail/send).\n\nWhen to use: finding an email, drafting a reply, sending mail the user asked for, summarising a thread.\n\nSteps:\n1. Read the request literally. A search needs only a query. A draft needs recipient, subject and the points to cover. A send needs all three plus the user's explicit yes on the exact text.\n2. Search first with the messages route. Read the newest matching messages and quote the sender, date and subject back to the user before acting on any of them.\n3. Drafts are shown to the user first and sent only after they approve the exact text. Never send a draft the user has not seen.\n4. Summaries keep numbers, dates, links and action items verbatim and say which message each fact came from.\n\nLimits: Gmail only, the connected account only. No other mailbox. Attachments are listed, never silently downloaded. If Gmail is not connected, say so and stop.",
			args: {
				type: "object",
				properties: {
					action: {
						type: "string",
						enum: ["search", "draft", "send", "summarize"],
					},
					query: {
						type: "string",
						description: "Search text for finding mail",
					},
					to: { type: "string", description: "Recipient email address" },
					subject: { type: "string" },
					body: { type: "string", description: "Draft or message text" },
					max_results: { type: "integer", default: 10 },
				},
				required: ["action"],
			},
			gate: "approval",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-scheduling",
		name: "scheduling",
		description:
			"Check the calendar and create or cancel events on the connected Google Calendar. Use when the user asks what is free, or wants an event made.",
		category: "productivity",
		tier: "free",
		manifest: {
			format: "anthropic",
			name: "scheduling",
			description:
				"Check the calendar and create or cancel events on the connected Google Calendar. Use when the user asks what is free, or wants an event made.",
			version: "1.0.0",
			trigger: "schedule",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["calendar-events"],
			instructions:
				"Calendar scheduling through the hub routes /api/google/calendar/events (GET to list, POST to create).\n\nWhen to use: checking what is free, creating an event, cancelling one the user named.\n\nSteps:\n1. Ask for what is missing before creating anything: title, start, end and who is invited. Never guess a time.\n2. List events for the requested day first so a new event never double-books silently. If it overlaps, say so and ask.\n3. Create the event, then read it back and confirm the title, time and attendees to the user.\n4. Cancel only the exact event the user named. Read the event back before cancelling and confirm after.\n\nLimits: Google Calendar only, the connected account only. Times are the user's local timezone unless they say otherwise. No recurring-series edits in v1, one event at a time.",
			args: {
				type: "object",
				properties: {
					action: { type: "string", enum: ["list", "create", "cancel"] },
					title: { type: "string" },
					start: { type: "string", description: "Start time, ISO 8601" },
					end: { type: "string", description: "End time, ISO 8601" },
					attendees: { type: "array", items: { type: "string" } },
					description: { type: "string" },
				},
				required: ["action"],
			},
			gate: "confirm",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-web-research",
		name: "web-research",
		description:
			"Answer questions that need current facts from the web, with a source and a date for every claim. Use when the user asks something that needs live information.",
		category: "research",
		tier: "free",
		manifest: {
			format: "anthropic",
			name: "web-research",
			description:
				"Answer questions that need current facts from the web, with a source and a date for every claim. Use when the user asks something that needs live information.",
			version: "1.0.0",
			trigger: "research",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["web-search", "webview-browser"],
			instructions:
				"Web research using the hub LLM router (BYOK Gemini or Groq) plus the in-app WebView browser for live pages.\n\nWhen to use: any question that needs current facts, comparisons, or sources from the web.\n\nSteps:\n1. Break the question into the smallest checkable claims.\n2. Search each claim and open the source page. Prefer the primary source over an aggregator that republishes it.\n3. Report each fact with its source and date. If two sources disagree, show both and say which one is primary.\n4. A fact with no source is labelled as unverified, never stated as true.\n\nLimits: no paywalled source is ever claimed as read. Dates on republished listings are not trusted on their own, read the internal dates on the page.",
			args: {
				type: "object",
				properties: {
					query: { type: "string" },
					depth: { type: "string", enum: ["quick", "deep"], default: "quick" },
					max_sources: { type: "integer", default: 5 },
				},
				required: ["query"],
			},
			gate: "none",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-documents",
		name: "documents",
		description:
			"Write documents, pull structured fields out of them, and make shareable certificate links. Use when the user wants a report, a note, or fields extracted from a file.",
		category: "productivity",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "documents",
			description:
				"Write documents, pull structured fields out of them, and make shareable certificate links. Use when the user wants a report, a note, or fields extracted from a file.",
			version: "1.0.0",
			trigger: "document",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["docs-ingest", "docs-extract", "docs-certificate"],
			instructions:
				"Documents through the hub docs routes: /api/docs/ingest to store text, /api/docs/extract for structured fields, /api/docs/certificate for a shareable certificate link.\n\nWhen to use: writing a report or note, pulling fields out of a document, making a document shareable.\n\nSteps:\n1. Ask what the document is for and who will read it before writing. Keep the user's words where they gave them.\n2. Draft in full, then show the draft. Edit only after the user approves the shape.\n3. Extraction returns the fields the user asked for with the source page or line for each one. A field that is not in the document is reported as missing, never guessed.\n4. A certificate link is created only when the user asks to share. Say who can open it before creating it.\n\nLimits: text documents only in v1. Spreadsheets and slides are out of scope and must be refused plainly.",
			args: {
				type: "object",
				properties: {
					action: {
						type: "string",
						enum: ["create", "read", "extract", "certificate"],
					},
					title: { type: "string" },
					text: {
						type: "string",
						description: "Document text to store or draft",
					},
					fields: {
						type: "array",
						items: { type: "string" },
						description: "Fields to extract",
					},
				},
				required: ["action"],
			},
			gate: "confirm",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-place-discovery",
		name: "place-discovery",
		description:
			"Find and compare places to go, restaurants, cafes, shops, parks and services, with a Maps link each. Use when the user asks where to go or what is nearby.",
		category: "research",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "place-discovery",
			description:
				"Find and compare places to go, restaurants, cafes, shops, parks and services, with a Maps link each. Use when the user asks where to go or what is nearby.",
			version: "1.0.0",
			trigger: "place",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["web-search", "maps-link"],
			instructions:
				"Finding places (restaurants, cafes, shops, parks, attractions, services) by web research plus a Maps link.\n\nWhen to use: the user asks where to go, what is nearby, or which place is best for a need.\n\nSteps:\n1. Ask for the area and the need (cuisine, budget, timing) when the user did not give them.\n2. Search the web for candidates and verify each one on its own site or Maps listing: address, hours and phone.\n3. Compare at most five places on the same points: distance, hours, price signal and what people say about it.\n4. Give the shortlist with a Maps link per place. Hours and prices are stated as last-checked, with the date.\n\nLimits: Jarvis has no live Places API in v1, so hours and prices are verified from the web, never from memory. A place that cannot be verified is marked unverified.",
			args: {
				type: "object",
				properties: {
					query: { type: "string" },
					location: { type: "string", description: "Area or city" },
					kind: {
						type: "string",
						enum: [
							"restaurant",
							"cafe",
							"shop",
							"park",
							"attraction",
							"service",
						],
					},
				},
				required: ["query"],
			},
			gate: "none",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-trip-planning",
		name: "trip-planning",
		description:
			"Plan a trip, compare transport and stays by total price, and lay out the itinerary. Use when the user wants a trip planned. It never books or pays.",
		category: "travel",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "trip-planning",
			description:
				"Plan a trip, compare transport and stays by total price, and lay out the itinerary. Use when the user wants a trip planned. It never books or pays.",
			version: "1.0.0",
			trigger: "trip",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["web-search", "calendar-events"],
			instructions:
				"Trip planning by web research plus the calendar. It plans and compares. It never books or pays anything on its own.\n\nWhen to use: the user wants a trip planned, a route compared, or a stay shortlisted.\n\nSteps:\n1. Collect destination, dates, travellers, budget and interests. Plan nothing until the dates and budget are known.\n2. Research transport and stays from live sources and compare like for like: total price, time, location and terms.\n3. Present one itinerary with options per leg and per night, each with its price and its source.\n4. Booking is a link the user opens. Payment is always the user's own explicit step, never the agent's.\n\nLimits: no auto-booking, no payment, no saved cards. Prices are last-checked with the date, never promised.",
			args: {
				type: "object",
				properties: {
					destination: { type: "string" },
					start_date: { type: "string", description: "Trip start, YYYY-MM-DD" },
					end_date: { type: "string", description: "Trip end, YYYY-MM-DD" },
					budget: { type: "string" },
					travelers: { type: "integer", default: 1 },
					interests: { type: "array", items: { type: "string" } },
				},
				required: ["destination"],
			},
			gate: "approval",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-shopping",
		name: "shopping",
		description:
			"Find a product and compare merchant offers by delivered total, then hand over the checkout link. Use when the user wants to buy or price-check something. It never buys.",
		category: "commerce",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "shopping",
			description:
				"Find a product and compare merchant offers by delivered total, then hand over the checkout link. Use when the user wants to buy or price-check something. It never buys.",
			version: "1.0.0",
			trigger: "shop",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["web-search"],
			instructions:
				"Shopping research: find a product, compare offers by delivered total, and hand the user the checkout link. It never buys anything.\n\nWhen to use: the user wants to buy something, compare prices, or check whether an offer is genuine.\n\nSteps:\n1. Pin down the exact product: model, variant, size and colour. A vague name gets a clarifying question first.\n2. Search several merchants and compare the delivered total: price plus shipping, taxes and fees. The cheapest headline price is not the answer.\n3. Check the seller and the return terms before recommending. A deal with no return path is flagged, not recommended.\n4. Hand over the checkout link for the chosen offer. The user pays. The agent never enters a card or completes a purchase.\n\nLimits: no purchase, no payment, no card handling. Prices are last-checked with the date. Used-marketplace listings are compared on condition and seller history, not price alone.",
			args: {
				type: "object",
				properties: {
					query: {
						type: "string",
						description: "Exact product, model and variant",
					},
					max_price: { type: "number" },
					category: { type: "string" },
				},
				required: ["query"],
			},
			gate: "approval",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-messaging",
		name: "messaging",
		description:
			"Draft and send messages in the Jarvis in-app chat. Use when the user wants a message written or sent. WhatsApp and SMS are not available in v1.",
		category: "communication",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "messaging",
			description:
				"Draft and send messages in the Jarvis in-app chat. Use when the user wants a message written or sent. WhatsApp and SMS are not available in v1.",
			version: "1.0.0",
			trigger: "message",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["in-app-chat", "fcm-push"],
			instructions:
				"Messaging in Jarvis means the in-app chat and FCM push. There is no WhatsApp or SMS sending in v1.\n\nWhen to use: drafting a message the user wants to send, or sending an in-app message or reminder to someone the user names.\n\nSteps:\n1. Draft the exact text first and show it to the user. Nothing is sent unseen.\n2. Send only after the user's yes, only to the person they named, only the text they approved.\n3. After sending, report what was sent, to whom, and when.\n4. A request to message someone on WhatsApp or SMS is refused plainly with the reason: Jarvis has no WhatsApp number or SMS sender in v1.\n\nLimits: in-app chat and FCM only. No message is ever sent without the approved text. Group messages are one recipient list the user confirms.",
			args: {
				type: "object",
				properties: {
					action: { type: "string", enum: ["draft", "send"] },
					recipient: { type: "string" },
					text: { type: "string" },
				},
				required: ["action", "text"],
			},
			gate: "approval",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-meeting-follow-up",
		name: "meeting-follow-up",
		description:
			"Turn meeting notes or a transcript into decisions, owners, action items and a sendable recap. Use after a meeting when the user shares notes or a transcript.",
		category: "communication",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "meeting-follow-up",
			description:
				"Turn meeting notes or a transcript into decisions, owners, action items and a sendable recap. Use after a meeting when the user shares notes or a transcript.",
			version: "1.0.0",
			trigger: "meeting",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["gmail-send", "drive-upload"],
			instructions:
				"Meeting follow-up from a transcript or notes: decisions, owners, action items and a recap the user can send.\n\nWhen to use: after a meeting, when the user shares notes or a transcript and wants the follow-up written.\n\nSteps:\n1. Read the transcript or notes fully. A decision is recorded only when the text states it. A guess is labelled as a guess.\n2. List every action item with its owner and its due date. An item with no owner is flagged, not assigned.\n3. Write the recap: decisions first, then action items, then open questions. Keep it short enough to send.\n4. Sending the recap (email or in-app message) needs the user's yes on the exact text and the exact recipients.\n\nLimits: no transcript, no follow-up. The agent never invents attendees, decisions or dates. A recording is transcribed only from the audio the user provided.",
			args: {
				type: "object",
				properties: {
					transcript: {
						type: "string",
						description: "Meeting notes or transcript text",
					},
					attendees: { type: "array", items: { type: "string" } },
					meeting_title: { type: "string" },
					date: { type: "string", description: "Meeting date, YYYY-MM-DD" },
				},
				required: ["transcript"],
			},
			gate: "approval",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-knowledge-organization",
		name: "knowledge-organization",
		description:
			"Save notes and documents to Drive, find them again, and keep the user's own folders and tags. Use when the user wants something saved, found, or filed.",
		category: "productivity",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "knowledge-organization",
			description:
				"Save notes and documents to Drive, find them again, and keep the user's own folders and tags. Use when the user wants something saved, found, or filed.",
			version: "1.0.0",
			trigger: "organize",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["drive-files", "drive-upload"],
			instructions:
				"Knowledge organization: save notes and documents to Drive, find them again, and keep the structure the user already uses.\n\nWhen to use: the user wants something saved for later, found again, or filed under a topic.\n\nSteps:\n1. Save with a clear title, the date and the tags the user gave. A note with no title gets one from its first line.\n2. Finding starts with the user's own words. Search Drive and the saved notes before searching the web.\n3. When filing, use the folders and tags that already exist. A new folder is created only when the user asks for it.\n4. Report where it was saved or found, with the exact title, so the user can open it.\n\nLimits: Drive only, the connected account only. Nothing is deleted or moved without the user naming it. Private notes are never shared.",
			args: {
				type: "object",
				properties: {
					action: { type: "string", enum: ["save", "find", "organize"] },
					title: { type: "string" },
					content: { type: "string" },
					tags: { type: "array", items: { type: "string" } },
				},
				required: ["action"],
			},
			gate: "confirm",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-live-page-checks",
		name: "live-page-checks",
		description:
			"Read a live product page and report its current price, stock or availability with the check time. Use when the user asks what something costs or whether it is in stock right now.",
		category: "research",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "live-page-checks",
			description:
				"Read a live product page and report its current price, stock or availability with the check time. Use when the user asks what something costs or whether it is in stock right now.",
			version: "1.0.0",
			trigger: "check page",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["webview-browser"],
			instructions:
				"Live page checks: read a current product page through the WebView browser and report price, stock or availability as of now.\n\nWhen to use: the user asks whether something is in stock, what it costs right now, or whether a page changed.\n\nSteps:\n1. Open the exact URL the user gave. A search result is not a page check.\n2. Read the price, stock state and any delivery note directly from the page. Quote the text you read.\n3. Say when you checked it. A check from an hour ago is stale and is labelled as such.\n4. If the page will not load, say so plainly and stop. Never report a price from memory or from another site.\n\nLimits: one URL per check. Login-walled pages are reported as unreadable, never bypassed. No purchase follows a check without a separate user step.",
			args: {
				type: "object",
				properties: {
					url: { type: "string", description: "Exact product page URL" },
					check: { type: "string", enum: ["price", "stock", "availability"] },
					target_price: {
						type: "number",
						description: "Alert when the price drops to this",
					},
				},
				required: ["url", "check"],
			},
			gate: "none",
			origin: "catalog",
		} as SkillManifest,
	},
	{
		id: "cat-transcription",
		name: "transcription",
		description:
			"Turn audio the user provides into text with speaker labels and a summary, using on-device speech recognition. Use when the user shares a recording and wants the words as text.",
		category: "productivity",
		tier: "pro",
		manifest: {
			format: "anthropic",
			name: "transcription",
			description:
				"Turn audio the user provides into text with speaker labels and a summary, using on-device speech recognition. Use when the user shares a recording and wants the words as text.",
			version: "1.0.0",
			trigger: "transcribe",
			steps: [{ action: "follow-skill-instructions" }],
			allowed_tools: ["speech-to-text"],
			instructions:
				"Transcription of audio the user provides, using the phone's on-device speech recognition, returned as text with speaker labels and a short summary.\n\nWhen to use: the user shares a recording or voice note and wants the words as text.\n\nSteps:\n1. Take the audio the user provided. No audio, no transcript.\n2. Transcribe in bounded chunks and keep going where the last chunk ended. A chunk that fails is retried once, then reported as untranscribed.\n3. Mark uncertain words as uncertain. Mark speaker changes where they are clear. Never smooth a sentence into words the speaker did not say.\n4. Return the full text plus a short summary: the points made and any numbers, dates or names spoken.\n\nLimits: on-device speech recognition only in v1. A language the recognizer does not support is refused plainly. No transcript is ever invented for silent or unclear audio.",
			args: {
				type: "object",
				properties: {
					audio_ref: {
						type: "string",
						description: "Reference to the user-provided audio",
					},
					language: { type: "string", default: "hi-IN" },
					speakers: { type: "boolean", default: true },
				},
				required: ["audio_ref"],
			},
			gate: "none",
			origin: "catalog",
		} as SkillManifest,
	},
];

// --- D1 helpers (skill_catalog is 0018; installs track per-tenant use) ---

export interface CatalogSkillRow {
	id: string;
	name: string;
	description: string;
	manifest: string;
	category: string;
	tier: string;
	created_at: number;
}

export interface CatalogSkillItem {
	id: string;
	name: string;
	description: string;
	manifest: SkillManifest;
	category: string;
	tier: string;
	created_at: number;
	installed: boolean;
}

/** Parse a stored manifest; null when the row is corrupt (caller skips + traces). */
export function parseCatalogManifest(
	row: CatalogSkillRow,
): SkillManifest | null {
	try {
		return JSON.parse(row.manifest) as SkillManifest;
	} catch {
		return null;
	}
}

/** Insert one catalog row. Idempotent on id (re-seed is a no-op). */
export async function insertCatalogSkill(
	db: D1Like,
	row: {
		id: string;
		name: string;
		description: string;
		manifest: string;
		category: string;
		tier: string;
		created_at: number;
	},
): Promise<void> {
	await db
		.prepare(
			"INSERT INTO skill_catalog (id, name, description, manifest, category, tier, created_at) " +
				"VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
		)
		.bind(
			row.id,
			row.name,
			row.description,
			row.manifest,
			row.category,
			row.tier,
			row.created_at,
		)
		.run();
}

/**
 * Seed the catalog from STARTER_SKILLS (the code-side seed; the live
 * D1 seed is migration 0018, generated from this same list — the test
 * asserts the SQL rows match it exactly). Safe to run twice.
 */
export async function seedCatalogSkills(
	db: D1Like,
): Promise<{ count: number }> {
	for (let i = 0; i < STARTER_SKILLS.length; i++) {
		const s = STARTER_SKILLS[i];
		await insertCatalogSkill(db, {
			id: s.id,
			name: s.name,
			description: s.description,
			manifest: JSON.stringify(s.manifest),
			category: s.category,
			tier: s.tier,
			created_at: seedCreatedAt(i),
		});
	}
	return { count: STARTER_SKILLS.length };
}

export async function getCatalogSkill(
	db: D1Like,
	skillId: string,
): Promise<CatalogSkillRow | null> {
	return await db
		.prepare(
			"SELECT id, name, description, manifest, category, tier, created_at FROM skill_catalog WHERE id = ?",
		)
		.bind(skillId)
		.first<CatalogSkillRow>();
}

/** Installed skill ids for one tenant (the Free=1 cap counts these). */
export async function listInstalledCatalogSkillIds(
	db: D1Like,
	tenantId: string,
): Promise<string[]> {
	const res = await db
		.prepare("SELECT skill_id FROM skill_catalog_installs WHERE tenant_id = ?")
		.bind(tenantId)
		.all<{ skill_id: string }>();
	return (res.results ?? []).map((r) => r.skill_id);
}

export async function countInstalledCatalogSkills(
	db: D1Like,
	tenantId: string,
): Promise<number> {
	const row = await db
		.prepare(
			"SELECT COUNT(*) AS n FROM skill_catalog_installs WHERE tenant_id = ?",
		)
		.bind(tenantId)
		.first<{ n: number }>();
	return row?.n ?? 0;
}

export async function isCatalogSkillInstalled(
	db: D1Like,
	tenantId: string,
	skillId: string,
): Promise<boolean> {
	const row = await db
		.prepare(
			"SELECT skill_id FROM skill_catalog_installs WHERE tenant_id = ? AND skill_id = ?",
		)
		.bind(tenantId, skillId)
		.first<{ skill_id: string }>();
	return row !== null;
}

// --- Handlers (hub.ts routes call these; vitest tests them directly) ---

/**
 * List the catalog for a tenant (tier-filtered).
 * The caller (hub route) resolves the tenant + plan tier first
 * (getTenant → 404 tenant_not_found) and device-signs the request.
 * A corrupt manifest row is skipped + traced, never returned.
 */
export async function listCatalogSkills(
	db: D1Like,
	opts: { tenantId: string; planTier: string },
): Promise<{ skills: CatalogSkillItem[]; count: number; plan_tier: string }> {
	const res = await db
		.prepare(
			"SELECT id, name, description, manifest, category, tier, created_at FROM skill_catalog ORDER BY created_at ASC",
		)
		.all<CatalogSkillRow>();
	const installed = new Set(
		await listInstalledCatalogSkillIds(db, opts.tenantId),
	);
	const rank = catalogTierRank(opts.planTier);
	const skills: CatalogSkillItem[] = [];
	for (const row of res.results ?? []) {
		if (catalogTierRank(row.tier) > rank) continue;
		const manifest = parseCatalogManifest(row);
		if (!manifest) {
			await insertTrace(db, opts.tenantId, "", "skill_catalog_skip", {
				skill_id: row.id,
			});
			continue;
		}
		skills.push({
			id: row.id,
			name: row.name,
			description: row.description,
			manifest,
			category: row.category,
			tier: row.tier,
			created_at: row.created_at,
			installed: installed.has(row.id),
		});
	}
	return { skills, count: skills.length, plan_tier: opts.planTier };
}

export type InstallCatalogResult =
	| { ok: true; deduped: boolean; skill: CatalogSkillItem }
	| { ok: false; error: "skill_not_found" }
	| {
			ok: false;
			error: "skill_tier_required";
			required_tier: string;
			plan_tier: string;
	  }
	| {
			ok: false;
			error: "skills_install_cap";
			plan_tier: string;
			installed: number;
			cap: number;
	  };

/**
 * Install a catalog skill for a tenant.
 * Order (fail-closed, cheapest check first): skill exists → tenant's
 * plan reaches the skill's tier → install cap (planLimits().skills:
 * Free 1, Pro/Business uncapped) → idempotent insert + trace.
 * Returns the manifest JSON so the phone can store the skill locally.
 */
export async function installCatalogSkill(
	db: D1Like,
	opts: {
		tenantId: string;
		planTier: string;
		skillId: string;
		deviceId?: string;
		nowMs?: number;
	},
): Promise<InstallCatalogResult> {
	const row = await getCatalogSkill(db, opts.skillId);
	if (!row) return { ok: false, error: "skill_not_found" };
	if (catalogTierRank(row.tier) > catalogTierRank(opts.planTier)) {
		return {
			ok: false,
			error: "skill_tier_required",
			required_tier: row.tier,
			plan_tier: opts.planTier,
		};
	}
	const manifest = parseCatalogManifest(row);
	if (!manifest) return { ok: false, error: "skill_not_found" };
	const item: CatalogSkillItem = {
		id: row.id,
		name: row.name,
		description: row.description,
		manifest,
		category: row.category,
		tier: row.tier,
		created_at: row.created_at,
		installed: true,
	};
	if (await isCatalogSkillInstalled(db, opts.tenantId, opts.skillId)) {
		return { ok: true, deduped: true, skill: item };
	}
	const installed = await countInstalledCatalogSkills(db, opts.tenantId);
	const cap = planLimits(opts.planTier).skills;
	if (installed >= cap) {
		return {
			ok: false,
			error: "skills_install_cap",
			plan_tier: opts.planTier,
			installed,
			cap,
		};
	}
	await db
		.prepare(
			"INSERT INTO skill_catalog_installs (tenant_id, skill_id, installed_at) VALUES (?, ?, ?)",
		)
		.bind(opts.tenantId, opts.skillId, opts.nowMs ?? Date.now())
		.run();
	await insertTrace(
		db,
		opts.tenantId,
		opts.deviceId ?? "",
		"skill_catalog_install",
		{
			skill_id: opts.skillId,
			plan_tier: opts.planTier,
		},
	);
	return { ok: true, deduped: false, skill: item };
}

/**
 * Validate every starter manifest against the frozen schema. Used by
 * tests (and by any future admin seed path): a catalog skill that does
 * not validate must never ship.
 */
export function validateStarterSkills(): Array<{ id: string; error: string }> {
	const bad: Array<{ id: string; error: string }> = [];
	const seen = new Set<string>();
	for (const s of STARTER_SKILLS) {
		if (seen.has(s.id)) bad.push({ id: s.id, error: "duplicate id" });
		seen.add(s.id);
		if (s.id !== `cat-${s.name}`)
			bad.push({ id: s.id, error: "id must be cat-<name>" });
		const v = validateSkillManifest(s.manifest);
		if (!v.ok) bad.push({ id: s.id, error: v.error });
		if ((s.manifest as Record<string, unknown>).origin !== "catalog") {
			bad.push({ id: s.id, error: "manifest.origin must be catalog" });
		}
		const gate = (s.manifest as Record<string, unknown>).gate;
		if (gate !== "none" && gate !== "confirm" && gate !== "approval") {
			bad.push({
				id: s.id,
				error: "manifest.gate must be none|confirm|approval",
			});
		}
		if (typeof (s.manifest as Record<string, unknown>).args !== "object") {
			bad.push({ id: s.id, error: "manifest.args is required" });
		}
	}
	return bad;
}
