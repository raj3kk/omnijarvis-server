/**
 * Skills catalog tests (GAP-FILL: skills library) — C-T1–C-T6.
 *
 * C-T1 every starter manifest validates (frozen schema) + carries
 * args + gate + origin catalog · C-T2 seed + tier-filtered list
 * (Free 3, Pro/Business 12) · C-T3 install happy path returns the
 * manifest · C-T4 Free=1 cap (second install 403 skills_install_cap)
 * + Pro uncapped · C-T5 tier gate (Free cannot install a Pro skill)
 * + skill_not_found + idempotent re-install · C-T6 migration 0018 SQL
 * rows match STARTER_SKILLS exactly (single source of truth).
 *
 * The handlers are tested directly (FakeD1, no hub.ts) — the hub
 * routes are the pages coordinator's piece (see BUILD_NOTES.md).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
	CATALOG_SEED_EPOCH,
	STARTER_SKILLS,
	catalogTierRank,
	countInstalledCatalogSkills,
	installCatalogSkill,
	listCatalogSkills,
	seedCatalogSkills,
	seedCreatedAt,
	validateStarterSkills,
} from "../src/skills-catalog";
import { FakeD1 } from "./fake-d1";

const FIXED_NOW = Date.UTC(2026, 10, 24, 1, 0, 0);

async function seedTenant(
	db: FakeD1,
	opts: { id: string; plan?: string },
): Promise<void> {
	await db
		.prepare(
			"INSERT INTO tenants (id, owner_email, plan_tier, billing_mode, gemini_key_enc, pii_consent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		)
		.bind(
			opts.id,
			`${opts.id}@example.com`,
			opts.plan ?? "pro",
			"byok",
			null,
			0,
			FIXED_NOW,
		)
		.run();
}

describe("C-T1 starter manifests are real (validate + args + gate)", () => {
	it("all 12 validate against the frozen manifest schema", () => {
		expect(STARTER_SKILLS).toHaveLength(12);
		expect(validateStarterSkills()).toEqual([]);
	});

	it("ids are unique cat-<name>, tiers are free/pro, gates are set", () => {
		const ids = STARTER_SKILLS.map((s) => s.id);
		expect(new Set(ids).size).toBe(12);
		for (const s of STARTER_SKILLS) {
			expect(s.id).toBe(`cat-${s.name}`);
			expect(["free", "pro", "business"]).toContain(s.tier);
			const m = s.manifest as Record<string, unknown>;
			expect(["none", "confirm", "approval"]).toContain(m.gate);
			expect(m.origin).toBe("catalog");
			expect(typeof m.args).toBe("object");
			expect(typeof m.instructions).toBe("string");
			expect((m.instructions as string).length).toBeGreaterThan(200);
			expect(Array.isArray(m.allowed_tools)).toBe(true);
		}
	});

	it("Free sees 3 starters, Pro sees the other 9", () => {
		expect(
			STARTER_SKILLS.filter((s) => s.tier === "free").map((s) => s.name),
		).toEqual(["email-management", "scheduling", "web-research"]);
		expect(STARTER_SKILLS.filter((s) => s.tier === "pro")).toHaveLength(9);
	});

	it("unknown tiers rank as free", () => {
		expect(catalogTierRank("free")).toBe(0);
		expect(catalogTierRank("pro")).toBe(1);
		expect(catalogTierRank("business")).toBe(2);
		expect(catalogTierRank("nonsense")).toBe(0);
	});
});

describe("C-T2 seed + tier-filtered list", () => {
	it("seeds 12 rows and lists them tier-filtered with installed flags", async () => {
		const db = new FakeD1();
		await seedTenant(db, { id: "t-free", plan: "free" });
		await seedTenant(db, { id: "t-pro", plan: "pro" });
		expect(await seedCatalogSkills(db)).toEqual({ count: 12 });
		// Re-seed is a no-op (ON CONFLICT DO NOTHING).
		expect(await seedCatalogSkills(db)).toEqual({ count: 12 });

		const freeList = await listCatalogSkills(db, {
			tenantId: "t-free",
			planTier: "free",
		});
		expect(freeList.count).toBe(3);
		expect(freeList.plan_tier).toBe("free");
		expect(freeList.skills.map((s) => s.name)).toEqual([
			"email-management",
			"scheduling",
			"web-research",
		]);
		expect(freeList.skills.every((s) => s.installed === false)).toBe(true);

		const proList = await listCatalogSkills(db, {
			tenantId: "t-pro",
			planTier: "pro",
		});
		expect(proList.count).toBe(12);
		expect(proList.skills.map((s) => s.name)).toEqual(
			STARTER_SKILLS.map((s) => s.name),
		);
		// Manifests come back parsed, in the same format the app parses.
		expect(proList.skills[0].manifest.name).toBe("email-management");
		expect(proList.skills[0].manifest.format).toBe("anthropic");
		expect(proList.skills[0].created_at).toBe(CATALOG_SEED_EPOCH);
	});

	it("list skips a corrupt manifest row (traced, never returned)", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		await db
			.prepare(
				"INSERT INTO skill_catalog (id, name, description, manifest, category, tier, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			)
			.bind(
				"cat-broken",
				"broken",
				"corrupt row",
				"not-json{",
				"research",
				"free",
				1,
			)
			.run();
		const list = await listCatalogSkills(db, {
			tenantId: "t-free",
			planTier: "free",
		});
		expect(list.skills.map((s) => s.id)).not.toContain("cat-broken");
		expect(list.count).toBe(3);
		const traces = await db
			.prepare("SELECT kind, detail FROM traces WHERE kind = ?")
			.bind("skill_catalog_skip")
			.all<{ kind: string; detail: string }>();
		expect(traces.results).toHaveLength(1);
		expect(traces.results[0].detail).toContain("cat-broken");
	});
});

describe("C-T3 install happy path", () => {
	it("installs and returns the manifest; list then flags it installed", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		const res = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-email-management",
			deviceId: "dev-1",
			nowMs: FIXED_NOW,
		});
		expect(res.ok).toBe(true);
		if (!res.ok) return;
		expect(res.deduped).toBe(false);
		expect(res.skill.id).toBe("cat-email-management");
		expect(res.skill.manifest.name).toBe("email-management");
		expect(res.skill.installed).toBe(true);
		expect(await countInstalledCatalogSkills(db, "t-free")).toBe(1);
		const list = await listCatalogSkills(db, {
			tenantId: "t-free",
			planTier: "free",
		});
		expect(
			list.skills.find((s) => s.id === "cat-email-management")?.installed,
		).toBe(true);
		expect(list.skills.find((s) => s.id === "cat-scheduling")?.installed).toBe(
			false,
		);
	});
});

describe("C-T4 Free=1 cap, Pro uncapped", () => {
	it("a Free tenant's second install is refused with skills_install_cap", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		const first = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-email-management",
			nowMs: FIXED_NOW,
		});
		expect(first.ok).toBe(true);
		const second = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-scheduling",
			nowMs: FIXED_NOW,
		});
		expect(second).toEqual({
			ok: false,
			error: "skills_install_cap",
			plan_tier: "free",
			installed: 1,
			cap: 1,
		});
		expect(await countInstalledCatalogSkills(db, "t-free")).toBe(1);
	});

	it("a Pro tenant installs the whole library", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		for (const s of STARTER_SKILLS) {
			const res = await installCatalogSkill(db, {
				tenantId: "t-pro",
				planTier: "pro",
				skillId: s.id,
				nowMs: FIXED_NOW,
			});
			expect(res.ok).toBe(true);
		}
		expect(await countInstalledCatalogSkills(db, "t-pro")).toBe(12);
	});
});

describe("C-T5 tier gate, not-found, idempotency", () => {
	it("a Free tenant cannot install a Pro skill", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		const res = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-shopping",
			nowMs: FIXED_NOW,
		});
		expect(res).toEqual({
			ok: false,
			error: "skill_tier_required",
			required_tier: "pro",
			plan_tier: "free",
		});
		expect(await countInstalledCatalogSkills(db, "t-free")).toBe(0);
	});

	it("unknown skill id is skill_not_found (and a corrupt manifest too)", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		expect(
			await installCatalogSkill(db, {
				tenantId: "t-pro",
				planTier: "pro",
				skillId: "cat-nope",
				nowMs: FIXED_NOW,
			}),
		).toEqual({ ok: false, error: "skill_not_found" });
		await db
			.prepare(
				"INSERT INTO skill_catalog (id, name, description, manifest, category, tier, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			)
			.bind(
				"cat-broken",
				"broken",
				"corrupt row",
				"not-json{",
				"research",
				"pro",
				1,
			)
			.run();
		expect(
			await installCatalogSkill(db, {
				tenantId: "t-pro",
				planTier: "pro",
				skillId: "cat-broken",
				nowMs: FIXED_NOW,
			}),
		).toEqual({ ok: false, error: "skill_not_found" });
	});

	it("re-install is idempotent and does not consume the cap", async () => {
		const db = new FakeD1();
		await seedCatalogSkills(db);
		const first = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-scheduling",
			nowMs: FIXED_NOW,
		});
		expect(first.ok).toBe(true);
		const again = await installCatalogSkill(db, {
			tenantId: "t-free",
			planTier: "free",
			skillId: "cat-scheduling",
			nowMs: FIXED_NOW,
		});
		expect(again.ok).toBe(true);
		if (!again.ok) return;
		expect(again.deduped).toBe(true);
		expect(await countInstalledCatalogSkills(db, "t-free")).toBe(1);
	});
});

describe("C-T6 migration 0018 SQL matches STARTER_SKILLS exactly", () => {
	const SQL18 = readFileSync(
		new URL("../d1/migrations/0018_skills_catalog.sql", import.meta.url),
		"utf8",
	);

	function parseSqlRows(): Array<Record<string, unknown>> {
		const rows: Array<Record<string, unknown>> = [];
		const re =
			/^INSERT INTO skill_catalog \(id, name, description, manifest, category, tier, created_at\) VALUES \('((?:[^']|'')*)', '((?:[^']|'')*)', '((?:[^']|'')*)', '((?:[^']|'')*)', '((?:[^']|'')*)', '((?:[^']|'')*)', (\d+)\) ON CONFLICT\(id\) DO NOTHING;$/;
		for (const line of SQL18.split("\n")) {
			const m = re.exec(line);
			if (!m) continue;
			const unesc = (s: string) => s.replaceAll("''", "'");
			rows.push({
				id: unesc(m[1]),
				name: unesc(m[2]),
				description: unesc(m[3]),
				manifest: JSON.parse(unesc(m[4])) as Record<string, unknown>,
				category: unesc(m[5]),
				tier: unesc(m[6]),
				created_at: Number(m[7]),
			});
		}
		return rows;
	}

	it("creates both tables + indexes and records itself in d1_migrations", () => {
		expect(SQL18).toContain("CREATE TABLE IF NOT EXISTS skill_catalog (");
		expect(SQL18).toContain("id TEXT PRIMARY KEY");
		expect(SQL18).toContain("manifest TEXT NOT NULL");
		expect(SQL18).toContain("CHECK (tier IN ('free', 'pro', 'business'))");
		expect(SQL18).toContain(
			"CREATE TABLE IF NOT EXISTS skill_catalog_installs (",
		);
		expect(SQL18).toContain("PRIMARY KEY (tenant_id, skill_id)");
		expect(SQL18).toContain("idx_skill_catalog_tier");
		expect(SQL18).toContain("idx_skill_catalog_installs_tenant");
		expect(SQL18).toContain(
			"INSERT OR IGNORE INTO d1_migrations (name, applied_at) VALUES ('0018_skills_catalog.sql'",
		);
	});

	it("is non-destructive: no DROP TABLE / TRUNCATE / DELETE FROM", () => {
		const code = SQL18.replace(/--[^\n]*/g, "");
		expect(code).not.toMatch(/DROP\s+TABLE/i);
		expect(code).not.toMatch(/TRUNCATE/i);
		expect(code).not.toMatch(/DELETE\s+FROM/i);
	});

	it("the 12 SQL seed rows equal STARTER_SKILLS field for field", () => {
		const rows = parseSqlRows();
		expect(rows).toHaveLength(12);
		expect(rows.map((r) => r.id)).toEqual(STARTER_SKILLS.map((s) => s.id));
		rows.forEach((row, i) => {
			const s = STARTER_SKILLS[i];
			expect(row.name).toBe(s.name);
			expect(row.description).toBe(s.description);
			expect(row.category).toBe(s.category);
			expect(row.tier).toBe(s.tier);
			expect(row.created_at).toBe(seedCreatedAt(i));
			expect(row.manifest).toEqual(JSON.parse(JSON.stringify(s.manifest)));
		});
	});
});
