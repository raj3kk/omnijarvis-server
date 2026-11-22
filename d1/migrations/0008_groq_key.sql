-- OmniJarvis D1 migration 0008 — Groq BYOK key (R3, 2026-11-22).
-- tenants.groq_key_enc: per-tenant Groq API key, AES-GCM envelope
-- (KEY_ENC_SECRET), same envelope as gemini_key_enc (0003).
-- Optional: a tenant without a Groq key simply skips the Groq fallback
-- leg (router traces router_groq_skipped) — Gemini-only behaviour is
-- unchanged. No founder key is needed: Groq free tier is $0.
-- D1: omnijarvis-db (37a7ff24-9fd2-40f9-b122-82cdaea7e79d).
-- Non-destructive: ALTER TABLE ADD COLUMN only.
ALTER TABLE tenants ADD COLUMN groq_key_enc TEXT;
