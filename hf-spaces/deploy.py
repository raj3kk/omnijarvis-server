#!/usr/bin/env python3
"""Deploy the OmniJarvis light worker to Hugging Face Spaces (Track B).

Creates/updates the Docker Space, waits for the build, then verifies
every endpoint live against the Space URL.

Usage (run from this directory):
    HF_TOKEN=<your-hf-write-token> python3 deploy.py [--wait-minutes 25]

Rules (hard):
  - The token comes ONLY from the HF_TOKEN environment variable at
    runtime. It is never written to disk, never printed, and never
    passed on a command line (no `ps` exposure). This script does not
    call `huggingface-cli login` (that would cache the token on disk).
  - No card, no paid hardware: the Space is created on `cpu-basic`
    (the free hardware) and PUBLIC (the worker has no auth by design;
    the hub's docs routes are the auth boundary).
  - Exit codes: 0 = deployed + verified; 1 = build/deploy/verify
    failure; 2 = token missing/invalid; 3 = HF refused creation with
    HTTP 402 (PRO subscription required for Docker Spaces — see below).

HTTP 402 WARNING (verified against HF docs 2026-11-22):
  Hugging Face's current docs say Gradio/Docker Spaces on cpu-basic
  REQUIRE a PRO subscription (or Team/Enterprise for orgs); without
  one, creating the Space fails with HTTP 402. This contradicts the
  "free, no card" premise the track was scoped on. This script
  attempts creation and reports the real outcome: if you get exit 3,
  the free-Docker path is closed for this account and the coordinator
  must decide (try an account that already has PRO / is grandfathered,
  or pick another free host). Do NOT upgrade to PRO from this script —
  that is spend and needs the user's explicit approval.

After a successful deploy, the hub-side switch is one Worker secret
(see REPORT.md):
    wrangler secret put RENDER_WORKER_URL
    # value: https://<namespace>-omnijarvis-render.hf.space  (no trailing slash)
No hub code change is needed — the hub reads that secret as a bare
base URL. Then run the live-verification checklist in REPORT.md.
"""

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SPACE_NAME_DEFAULT = "omnijarvis-render"
SPACE_FILES = ["Dockerfile", "README.md", "main.py", "requirements.txt",
               "requirements-heavy.txt",
               ".dockerignore"]


def die(msg: str, code: int = 1) -> "SystemExit":
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def ensure_huggingface_hub():
    """Import huggingface_hub, installing it (no secrets involved) if absent."""
    try:
        import huggingface_hub  # noqa: F401
        return huggingface_hub
    except ImportError:
        print("huggingface_hub not installed — installing it (no token involved)...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-q",
             "--disable-pip-version-check", "huggingface_hub"],
            check=True)
        import huggingface_hub  # noqa: F401
        return huggingface_hub


def main() -> int:
    ap = argparse.ArgumentParser(description="Deploy the OmniJarvis worker to HF Spaces.")
    ap.add_argument("--space-name", default=os.environ.get("HF_SPACE_NAME", SPACE_NAME_DEFAULT),
                    help="Space name (default: omnijarvis-render)")
    ap.add_argument("--wait-minutes", type=float, default=25,
                    help="Max minutes to wait for build+health (default 25)")
    ap.add_argument("--skip-verify", action="store_true",
                    help="Skip the live endpoint verification step")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        die("HF_TOKEN is not set. Run with HF_TOKEN in the environment, e.g.\n"
            "  HF_TOKEN=<hf-write-token> python3 deploy.py\n"
            "Create a write token at https://huggingface.co/settings/tokens\n"
            "(fine-grained token with write access to Spaces, or a full-access token).\n"
            "The token is read from the environment only — never type it into a file.", 2)

    for name in SPACE_FILES:
        if not os.path.exists(os.path.join(HERE, name)):
            die(f"missing Space file in {HERE}: {name} (run from the hf-spaces dir)", 1)

    hub = ensure_huggingface_hub()
    from huggingface_hub import HfApi  # noqa: E402
    from huggingface_hub.utils import HfHubHTTPError  # noqa: E402

    api = HfApi(token=token)

    # Namespace: explicit override, else the token owner's username.
    namespace = os.environ.get("HF_NAMESPACE")
    if not namespace:
        try:
            namespace = api.whoami()["name"]
        except HfHubHTTPError as e:
            if getattr(e.response, "status_code", None) == 401:
                die("HF_TOKEN was rejected (401). Check the token is a valid write "
                    "token and has not expired.", 2)
            raise
    repo_id = f"{namespace}/{args.space_name}"
    space_url = f"https://{namespace}-{args.space_name}.hf.space"
    print(f"Space: {repo_id}")
    print(f"URL:   {space_url}")

    # 1. Create (or confirm) the Space. exist_ok=True makes re-runs safe.
    try:
        api.create_repo(repo_id=repo_id, repo_type="space",
                        space_sdk="docker", space_hardware="cpu-basic",
                        private=False, exist_ok=True)
        print("Space exists (created or already present).")
    except HfHubHTTPError as e:
        status = getattr(e.response, "status_code", None)
        if status == 402:
            print(
                "\nHTTP 402 from Hugging Face: this account cannot create a "
                "Docker Space on cpu-basic without a PRO subscription.\n"
                "Per HF docs (2026-11-22): Gradio/Docker Spaces require PRO "
                "(users) / Team/Enterprise (orgs); free accounts get only "
                "Static Spaces free (and up to 2 ZeroGPU Spaces if the "
                "account is in good standing). The free-Docker premise of "
                "this track does not hold for this account.\n"
                "Options for the coordinator: (a) retry with an account "
                "that already has PRO / is grandfathered; (b) pick another "
                "free host for the worker. Upgrading to PRO is spend ($9/mo) "
                "and needs the user's explicit approval — this script never "
                "does it.\n", file=sys.stderr)
            return 3
        if status == 401:
            die("HF_TOKEN was rejected (401). Check the token is a valid write "
                "token and has not expired.", 2)
        if status == 403:
            die("HF refused with 403: the token likely lacks write permission "
                "on Spaces. Use a token with Space write access.", 2)
        die(f"create_repo failed (HTTP {status}): {e}", 1)

    # 2. Upload the Space files (this triggers a rebuild).
    print("Uploading Space files (Dockerfile, README.md, main.py, requirements.txt, requirements-heavy.txt)...")
    try:
        api.upload_folder(folder_path=HERE, repo_id=repo_id, repo_type="space",
                          allow_patterns=SPACE_FILES,
                          commit_message="Deploy OmniJarvis worker (Docker Space, Track B)")
    except HfHubHTTPError as e:
        die(f"upload failed (HTTP {getattr(e.response, 'status_code', '?')}): {e}", 1)
    print("Upload done — build started.")

    # 3. Wait for the runtime to be RUNNING (build + container start).
    deadline = time.time() + args.wait_minutes * 60
    last_stage = None
    restarted = False
    while time.time() < deadline:
        runtime = api.get_space_runtime(repo_id=repo_id)
        stage = str(getattr(runtime, "stage", "") or "")
        if stage != last_stage:
            print(f"runtime stage: {stage} (hardware={getattr(runtime, 'hardware', '?')})")
            last_stage = stage
        if "ERROR" in stage:
            try:
                logs = api.fetch_space_logs(repo_id=repo_id)
                print("--- Space logs (tail) ---")
                print("\n".join(str(logs).splitlines()[-40:]))
            except Exception as exc:  # noqa: BLE001
                print(f"(could not fetch logs: {exc})")
            die(f"Space entered error stage: {stage}. See logs above.", 1)
        if stage == "RUNNING":
            break
        if stage == "SLEEPING" and not restarted:
            print("Space is sleeping — restarting it...")
            api.restart_space(repo_id=repo_id)
            restarted = True
        time.sleep(20)
    else:
        die(f"timed out after {args.wait_minutes} min waiting for RUNNING "
            f"(last stage: {last_stage}). Check https://huggingface.co/spaces/{repo_id}", 1)
    print("Runtime is RUNNING.")

    # 4. Wait for /health on the public URL (real readiness: app bound to $PORT).
    import urllib.request  # noqa: E402
    import urllib.error  # noqa: E402
    import json  # noqa: E402
    health_deadline = time.time() + 10 * 60
    healthy = False
    while time.time() < health_deadline:
        try:
            with urllib.request.urlopen(space_url + "/health", timeout=15) as resp:
                body = json.loads(resp.read().decode())
                if resp.status == 200 and body.get("ok") is True:
                    healthy = True
                    print(f"/health OK: {body}")
                    break
        except Exception as exc:  # noqa: BLE001
            print(f"... waiting for /health ({type(exc).__name__})")
        time.sleep(15)
    if not healthy:
        die(f"/health never answered on {space_url}. Runtime is RUNNING but the "
            f"app may not be bound to $PORT — check the Space logs at "
            f"https://huggingface.co/spaces/{repo_id}", 1)

    # 5. Full live verification (all six endpoints).
    if args.skip_verify:
        print("Skipped live verification (--skip-verify).")
    else:
        print("\nRunning live verification (verify.py)...")
        fixtures = os.path.normpath(os.path.join(HERE, "..", "render", "worker", "fixtures"))
        cmd = [sys.executable, os.path.join(HERE, "verify.py"), space_url]
        if os.path.isdir(fixtures):
            cmd += ["--fixtures", fixtures]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            die("live verification FAILED — see FAIL lines above.", 1)

    print("\n================ DEPLOYED + VERIFIED ================")
    print(f"Space URL: {space_url}")
    print(f"Space page: https://huggingface.co/spaces/{repo_id}")
    print("\nHub-side switch (one Worker secret, no code change):")
    print("  cd ~/workspace/omnijarvis-server   # (or the hub repo checkout)")
    print("  wrangler secret put RENDER_WORKER_URL")
    print(f"  # value (no trailing slash): {space_url}")
    print("Then run the live-verification checklist in REPORT.md")
    print("(hub docs routes -> worker OCR/extract/certificate/scan).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
