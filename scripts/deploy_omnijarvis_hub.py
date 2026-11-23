"""Deploy the omnijarvis-hub Worker (Phase 2, stage 2a-2).

Flow (secrets NEVER printed):
  1. Bundle src/hub.ts with esbuild (local node_modules) -> dist/worker.js.
  2. Generate INTERNAL_SECRET + CRON_SECRET + HUB_SIGN_SECRET +
     SKILL_SIGN_SECRET (+ SKILL_SIGN_PUBLIC_KEY, derived) if not
     already saved, and store them in a 0600 env file for reuse.
     HUB_SIGN_SECRET (M-4) and SKILL_SIGN_SECRET (3d) are Ed25519 PKCS8
     base64 keypairs generated via Node WebCrypto (Python `cryptography`
     is not installed here); generation self-checks sign->verify before
     returning, and only the PUBLIC keys are ever printed. The two
     keypairs are DIFFERENT keys (hub-step signing vs skill signing).
  3. Upload worker.js via Cloudflare Scripts API (stored
     custom.cloudflare credential, rajraj3kk account) with metadata:
     DO binding JARVIS_HUB (JarvisHub, migration v1 new_sqlite_classes)
     + D1 binding DB (omnijarvis-db).
  4. Set Worker secrets: INTERNAL_SECRET, CRON_SECRET, HUB_SIGN_SECRET,
     SKILL_SIGN_SECRET, SKILL_SIGN_PUBLIC_KEY.
     (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are DELETED here — D1
     migration 2026-11-21 removed Supabase; the stale secrets are
     removed via the Secrets API on every deploy, 404 = already gone.)
     NOTE (M-4): the spec said `wrangler secret put` for HUB_SIGN_SECRET,
     but wrangler has no non-interactive auth in this environment
     (whoami prompts for OAuth), so the secret is set through the same
     Cloudflare Scripts API PUT this script already uses for the other
     secrets — the same endpoint wrangler itself calls; the value travels
     only in the HTTPS request body, from memory, never printed.
  5. Print ONLY non-secret results (script name, workers.dev URL,
     secret names set, HTTP statuses, hub PUBLIC key).

Usage: python3 deploy_omnijarvis_hub.py
"""
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

CF_ACCOUNT_ID = "c661e8baf013aa17fbf205cd8df81745"
SCRIPT_NAME = "omnijarvis-hub"
SERVER_DIR = os.path.expanduser("~/workspace/omnijarvis-server")
WORKER_FILE = os.path.join(SERVER_DIR, "dist", "worker.js")
SECRETS_FILE = os.path.expanduser(
    "~/workspace/omnijarvis-implementation/.secrets/omnijarvis-hub.env"
)
# M-I-28: the licence Worker's own secret file — the hub's
# LICENCE_ADMIN_TOKEN must be the SAME value the licence Worker was
# deployed with (its generate/release auth). Never generated here.
LICENCE_WORKER_SECRETS_FILE = os.path.expanduser(
    "~/workspace/omnijarvis-implementation/.secrets/jarvis-licence-worker.env"
)
D1_ID = "37a7ff24-9fd2-40f9-b122-82cdaea7e79d"
# D1 is THE store (D12 reframed 2026-11-21 — Supabase removed, no URL/key).
# M4 deploy precondition (Phase B plan §5): the local server tree must be
# IDENTICAL to the GitHub main tip before any deploy step runs.
# check_server_tip.py compares git blob SHAs for the whole tree;
# exit 0 = identical, 1 = drift. A proposal-branch tree is never
# identical to main (it has the fix), so it can never be deployed.
# The checker lives next to this script in the server repo (scripts/),
# or two levels up in the local workspace (phase-2/2a-2/ ->
# omnijarvis-implementation/). Prefer the sibling; fall back to the
# workspace path. (The script was local-only before the M4 PR versioned
# it under scripts/ alongside the checker.)
_HERE = os.path.dirname(os.path.abspath(__file__))
_TIP_CHECKER_CANDIDATES = (
    os.path.join(_HERE, "check_server_tip.py"),
    os.path.normpath(os.path.join(_HERE, "..", "..", "check_server_tip.py")),
)
TIP_CHECKER = next(
    (p for p in _TIP_CHECKER_CANDIDATES if os.path.exists(p)),
    _TIP_CHECKER_CANDIDATES[0],
)


def cf_request(method, path, data=None, content_type="application/json"):
    url = "https://api.cloudflare.com/client/v4" + path
    body = data
    if isinstance(data, dict):
        body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", content_type)
    add_surrogate_to_request(req, "custom.cloudflare", allowed_hosts=["api.cloudflare.com"])
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return read_json_response(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:800]
        raise RuntimeError(f"Cloudflare {method} {path} -> HTTP {e.code}: {detail}")


def do_class_exists() -> bool:
    """True if the JarvisHub DO namespace already exists (migration v1
    applied on a previous deploy). Re-applying a new_sqlite_classes
    migration for an existing class fails with CF error 10074, so the
    migration is sent ONLY on first deploy."""
    res = cf_request(
        "GET", f"/accounts/{CF_ACCOUNT_ID}/workers/durable_objects/namespaces"
    )
    if not res.get("success"):
        print("WARN: could not list DO namespaces; assuming first deploy")
        return False
    return any(
        (ns.get("class") == "JarvisHub" and ns.get("script") == SCRIPT_NAME)
        for ns in res.get("result", [])
    )


def multipart_upload(script_bytes):
    boundary = uuid.uuid4().hex
    metadata: dict = {
        "main_module": "worker.js",
        "compatibility_date": "2026-11-21",
        "bindings": [
            {
                "type": "durable_object_namespace",
                "name": "JARVIS_HUB",
                "class_name": "JarvisHub",
            },
            {"type": "d1", "name": "DB", "id": D1_ID},
            # M-I-28: service binding to jarvis-licence — Worker ->
            # workers.dev subrequests 1042 on this setup (proven
            # 2026-11-22 with a diag Worker), so the hub calls the
            # licence Worker through this binding, not its public URL.
            {"type": "service", "name": "LICENCE_WORKER", "service": "jarvis-licence"},
        ],
    }
    if not do_class_exists():
        metadata["migrations"] = {"tag": "v1", "new_sqlite_classes": ["JarvisHub"]}
        print("DO migration: v1 new_sqlite_classes (first deploy)")
    else:
        print("DO migration: skipped (JarvisHub namespace already exists)")
    parts = []
    parts.append(b"--" + boundary.encode())
    parts.append(b'Content-Disposition: form-data; name="metadata"')
    parts.append(b"Content-Type: application/json")
    parts.append(b"")
    parts.append(json.dumps(metadata).encode("utf-8"))
    parts.append(b"--" + boundary.encode())
    parts.append(b'Content-Disposition: form-data; name="worker.js"; filename="worker.js"')
    parts.append(b"Content-Type: application/javascript+module")
    parts.append(b"")
    parts.append(script_bytes)
    parts.append(b"--" + boundary.encode() + b"--")
    parts.append(b"")
    body = b"\r\n".join(parts)
    return cf_request(
        "PUT",
        f"/accounts/{CF_ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}",
        data=body,
        content_type=f"multipart/form-data; boundary={boundary}",
    )


def generate_hub_sign_secret():
    """Generate an Ed25519 keypair (M-4) via Node WebCrypto.

    Returns (private_pkcs8_b64, public_raw_b64). The private value lives
    in memory only — it is NEVER printed (not here, not by the caller).
    Node self-checks sign->verify before returning; a failed check raises.
    The private value is captured from stdout via capture_output (never
    written to disk, never to the terminal).
    """
    js = (
        "const kp = await crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign','verify']);"
        "const priv = Buffer.from(await crypto.subtle.exportKey('pkcs8', kp.privateKey)).toString('base64');"
        "const pub = Buffer.from(await crypto.subtle.exportKey('raw', kp.publicKey)).toString('base64');"
        "const msg = new TextEncoder().encode('m4-keygen-check');"
        "const sig = await crypto.subtle.sign({name:'Ed25519'}, kp.privateKey, msg);"
        "const ok = await crypto.subtle.verify({name:'Ed25519'}, kp.publicKey, sig, msg);"
        "console.log(JSON.stringify({private_b64: priv, public_b64: pub, verified: ok}));"
    )
    r = subprocess.run(
        ["node", "--input-type=module", "-e", js],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        raise RuntimeError("node Ed25519 keygen failed: " + r.stderr[-500:])
    data = json.loads(r.stdout.strip())
    if not data.get("verified"):
        raise RuntimeError("node Ed25519 keygen self-check (sign->verify) failed")
    import base64 as _b64

    if len(_b64.b64decode(data["public_b64"])) != 32:
        raise RuntimeError("node Ed25519 keygen: public key is not 32 bytes")
    return data["private_b64"], data["public_b64"]


def derive_hub_public_key(private_b64):
    """Derive the raw 32-byte public key (base64) from a PKCS8 base64
    private key, via Node WebCrypto JWK export. The private value is
    passed on STDIN (never as an argv — that would show in ps). The
    returned public value is safe to print."""
    js = (
        "const b64 = (await new Promise((res) => { let d='';"
        "process.stdin.on('data', (c) => { d += c; });"
        "process.stdin.on('end', () => res(d)); })).trim();"
        "const raw = Buffer.from(b64, 'base64');"
        "const priv = await crypto.subtle.importKey('pkcs8', raw, {name:'Ed25519'}, true, ['sign']);"
        "const jwk = await crypto.subtle.exportKey('jwk', priv);"
        "const x = jwk.x.replace(/-/g, '+').replace(/_/g, '/');"
        "console.log(x + '='.repeat((4 - (x.length % 4)) % 4));"
    )
    r = subprocess.run(
        ["node", "--input-type=module", "-e", js],
        input=private_b64, capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        raise RuntimeError("hub public key derive failed: " + r.stderr[-300:])
    return r.stdout.strip()


def load_or_generate_secrets():
    existing = {}
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    existing[k.strip()] = v.strip()
    changed = False
    for name in ("INTERNAL_SECRET", "CRON_SECRET", "LLM_ADMIN_TOKEN"):
        if not existing.get(name):
            existing[name] = secrets.token_urlsafe(32)
            changed = True
    # KEY_ENC_SECRET: 32-byte AES-GCM master key (base64) for tenant BYOK keys.
    if not existing.get("KEY_ENC_SECRET"):
        import base64

        existing["KEY_ENC_SECRET"] = base64.b64encode(secrets.token_bytes(32)).decode()
        changed = True
    # HUB_SIGN_SECRET (M-4): Ed25519 PKCS8 base64 — hub signs EXECUTE_STEP.
    # Generate-if-absent ONLY; an existing value is reused, NEVER overwritten.
    hub_pub = None
    if not existing.get("HUB_SIGN_SECRET"):
        priv_b64, hub_pub = generate_hub_sign_secret()
        existing["HUB_SIGN_SECRET"] = priv_b64
        changed = True
    # SKILL_SIGN_SECRET (3d): Ed25519 PKCS8 base64 — hub signs approved
    # skills. Same generate-if-absent rule as HUB_SIGN_SECRET (a DIFFERENT
    # keypair — hub-step signing and skill signing never share a key).
    # SKILL_SIGN_PUBLIC_KEY is the derived public key (clients verify).
    skill_pub = None
    if not existing.get("SKILL_SIGN_SECRET"):
        priv_b64, skill_pub = generate_hub_sign_secret()
        existing["SKILL_SIGN_SECRET"] = priv_b64
        existing["SKILL_SIGN_PUBLIC_KEY"] = skill_pub
        changed = True
    if not existing.get("SKILL_SIGN_PUBLIC_KEY") and existing.get("SKILL_SIGN_SECRET"):
        try:
            existing["SKILL_SIGN_PUBLIC_KEY"] = derive_hub_public_key(existing["SKILL_SIGN_SECRET"])
            changed = True
        except Exception:  # noqa: BLE001 — derive failure leaves the key absent; deploy still proceeds
            pass
    if changed:
        os.makedirs(os.path.dirname(SECRETS_FILE), exist_ok=True)
        with open(SECRETS_FILE, "w", encoding="utf-8") as fh:
            for k in ("INTERNAL_SECRET", "CRON_SECRET", "KEY_ENC_SECRET", "LLM_ADMIN_TOKEN", "HUB_SIGN_SECRET", "SKILL_SIGN_SECRET", "SKILL_SIGN_PUBLIC_KEY"):
                fh.write(f"{k}={existing[k]}\n")
        os.chmod(SECRETS_FILE, 0o600)
        print(f"Secrets generated + saved to {SECRETS_FILE} (0600)")
    else:
        print(f"Secrets reused from {SECRETS_FILE} (0600)")
    # Log ONLY the hub PUBLIC key (public value, safe to print).
    try:
        hub_pub = hub_pub or derive_hub_public_key(existing["HUB_SIGN_SECRET"])
        print(f"HUB_SIGN_SECRET: set (hub public key {hub_pub})")
    except Exception as e:  # noqa: BLE001 — public-key derive is best-effort logging
        print(f"WARN: could not derive hub public key: {e}")
    # Log ONLY the skill PUBLIC key (public value, safe to print).
    try:
        skill_pub = skill_pub or existing.get("SKILL_SIGN_PUBLIC_KEY") or derive_hub_public_key(existing["SKILL_SIGN_SECRET"])
        print(f"SKILL_SIGN_SECRET: set (skill public key {skill_pub})")
    except Exception as e:  # noqa: BLE001 — public-key derive is best-effort logging
        print(f"WARN: could not derive skill public key: {e}")
    return existing


def read_licence_admin_token():
    """M-I-28: read LICENCE_ADMIN_TOKEN from the licence Worker's own
    secret file. It must match the value the licence Worker runs with —
    generating a fresh one here would desync generate/release auth, so
    a missing value FAILS the deploy instead of inventing one."""
    if not os.path.exists(LICENCE_WORKER_SECRETS_FILE):
        raise RuntimeError(
            f"LICENCE_ADMIN_TOKEN missing: {LICENCE_WORKER_SECRETS_FILE} not found"
        )
    with open(LICENCE_WORKER_SECRETS_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("LICENCE_ADMIN_TOKEN="):
                value = line.split("=", 1)[1].strip()
                if value:
                    return value
    raise RuntimeError(
        "LICENCE_ADMIN_TOKEN missing in jarvis-licence-worker.env — deploy refused"
    )


def check_server_tip_identical(checker=TIP_CHECKER):
    """Run check_server_tip.py; True only if it exits 0 (IDENTICAL).

    The checker's own output flows through to stdout so a failure shows
    exactly which files drifted. A non-zero exit (drift, or the checker
    itself failing) is a refusal, never a warning. The optional `checker`
    arg exists only so the gate is unit-testable with a stub.
    """
    r = subprocess.run([sys.executable, checker], timeout=180)
    return r.returncode == 0


def main():
    # 0. M4 deploy precondition (Phase B plan §5): the local server tree
    # must be IDENTICAL to the GitHub main tip BEFORE any deploy step
    # (bundle, secrets, upload). A proposal-branch tree is never
    # identical to main, so it can never be deployed.
    if not check_server_tip_identical():
        print("M4 REFUSED: server tree is NOT IDENTICAL to the GitHub main tip — deploy aborted before any deploy step (see check_server_tip.py output above)")
        return 1

    # 1. Bundle with esbuild.
    os.makedirs(os.path.join(SERVER_DIR, "dist"), exist_ok=True)
    r = subprocess.run(
        [
            "npx",
            "esbuild",
            "src/hub.ts",
            "--bundle",
            "--format=esm",
            "--external:cloudflare:workers",
            "--outfile=dist/worker.js",
        ],
        cwd=SERVER_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if r.returncode != 0:
        print("esbuild FAILED:\n", r.stdout[-2000:], r.stderr[-2000:])
        return 1
    with open(WORKER_FILE, "rb") as fh:
        script_bytes = fh.read()
    print(f"Bundled {SCRIPT_NAME}: {len(script_bytes)} bytes")

    # 2. Secrets (generated once, reused after).
    sec = load_or_generate_secrets()

    # 2b. M-I-28: hub-side copy of the licence Worker's admin token.
    licence_admin_token = read_licence_admin_token()

    # 3. Upload Worker script.
    print(f"Uploading {SCRIPT_NAME}...")
    res = multipart_upload(script_bytes)
    if not res.get("success"):
        print("ERROR: Worker upload failed:", json.dumps(res)[:800])
        return 1
    print("Worker upload OK:", res.get("result", {}).get("id"))

    # 3b. Enable the workers.dev route. Raw Scripts API uploads leave
    # the route DISABLED (every request then 404 "error code: 1042" —
    # found 2026-11-21; docs: 1042 = "workers.dev URL with no Worker
    # serving it, such as a Worker with its workers.dev route disabled").
    # Redeploys can disable it again, so this runs on EVERY deploy.
    sub = cf_request(
        "POST",
        f"/accounts/{CF_ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/subdomain",
        data={"enabled": True},
    )
    print("workers.dev route enabled:", bool(sub.get("success")))
    if not sub.get("success"):
        print("ERROR: subdomain enable failed:", json.dumps(sub)[:400])
        return 1

    # 4. Set secrets (D1 migration: no Supabase secrets anymore).
    # KEY_ENC_SECRET + LLM_ADMIN_TOKEN are Phase 3 (router) secrets.
    # HUB_SIGN_SECRET is the M-4 Ed25519 signing key (PKCS8 base64).
    # SKILL_SIGN_SECRET + SKILL_SIGN_PUBLIC_KEY are the 3d skill-signing
    # keypair (a different keypair from HUB_SIGN_SECRET).
    # LICENCE_ADMIN_TOKEN is the M-I-28 copy of the licence Worker's
    # admin token (same value, read from its own secret file above).
    for name, value in [
        ("INTERNAL_SECRET", sec["INTERNAL_SECRET"]),
        ("CRON_SECRET", sec["CRON_SECRET"]),
        ("KEY_ENC_SECRET", sec["KEY_ENC_SECRET"]),
        ("LLM_ADMIN_TOKEN", sec["LLM_ADMIN_TOKEN"]),
        ("HUB_SIGN_SECRET", sec["HUB_SIGN_SECRET"]),
        ("SKILL_SIGN_SECRET", sec["SKILL_SIGN_SECRET"]),
        ("SKILL_SIGN_PUBLIC_KEY", sec["SKILL_SIGN_PUBLIC_KEY"]),
        ("LICENCE_ADMIN_TOKEN", licence_admin_token),
    ]:
        r = cf_request(
            "PUT",
            f"/accounts/{CF_ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/secrets",
            data={"name": name, "text": value, "type": "secret_text"},
        )
        ok = bool(r.get("success"))
        print(f"Secret {name}: {'OK' if ok else 'FAILED: ' + json.dumps(r)[:300]}")
        if not ok:
            return 1
    # 4b. Delete stale Supabase secrets (D1 migration cleanup; 404 = gone).
    for name in ("SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"):
        try:
            r = cf_request(
                "DELETE",
                f"/accounts/{CF_ACCOUNT_ID}/workers/scripts/{SCRIPT_NAME}/secrets/{name}",
            )
            print(f"Stale secret {name}: deleted" if r.get("success") else f"Stale secret {name}: {json.dumps(r)[:200]}")
        except RuntimeError as e:
            msg = str(e)
            if "404" in msg or "not found" in msg.lower():
                print(f"Stale secret {name}: already gone (404)")
            else:
                print(f"Stale secret {name}: delete FAILED: {msg[:200]}")
                return 1
    print("NOTE: Supabase fully removed (D1 migration 2026-11-21) — pairing init verifies against D1 licences now.")

    # 5. Workers subdomain + final URL.
    sub = cf_request("GET", f"/accounts/{CF_ACCOUNT_ID}/workers/subdomain")
    subdomain = (sub.get("result") or {}).get("subdomain") if sub.get("success") else None
    print("Workers subdomain:", subdomain)
    if subdomain:
        print(f"LIVE URL: https://{SCRIPT_NAME}.{subdomain}.workers.dev")
    return 0


if __name__ == "__main__":
    sys.exit(main())
