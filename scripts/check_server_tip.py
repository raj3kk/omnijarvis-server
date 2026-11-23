#!/usr/bin/env python3
"""Verify ~/workspace/omnijarvis-server local tree == GitHub tip (raj3kk/omnijarvis-server main).
Compares git blob SHAs (sha1("blob <len>\\0" + content)) for every file, same
SKIP_DIRS as push_server.py. Exit 0 = identical, 1 = drift (lists diffs).
Usage: check_server_tip.py [expected-tip-prefix]
"""
import sys, json, os, hashlib, urllib.request, urllib.error
sys.path.insert(0, "/opt/muse/skills/custom-connector-setup/bin")
from dynamic_credentials import add_surrogate_to_request, read_json_response

ROOT = "/home/hatch/workspace/omnijarvis-server"
REST = "https://api.github.com/repos/raj3kk/omnijarvis-server"
SKIP_DIRS = {".git", "node_modules", ".wrangler", "dist", "__pycache__", ".venv"}

def call(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Accept", "application/vnd.github+json")
    r.add_header("User-Agent", "muse-github-skill")
    if data:
        r.add_header("Content-Type", "application/json")
    add_surrogate_to_request(r, "custom.github", allowed_hosts=["api.github.com"])
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, read_json_response(resp)
    except urllib.error.HTTPError as e:
        print("HTTP ERROR", e.code, method, url, e.read().decode()[:500])
        sys.exit(1)

def blob_sha(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()

def main():
    _, refd = call("GET", f"{REST}/git/ref/heads/main")
    tip = refd["object"]["sha"]
    print("tip:", tip)
    if len(sys.argv) > 1 and not tip.startswith(sys.argv[1]):
        print(f"MISMATCH: expected tip prefix {sys.argv[1]}, got {tip}")
        sys.exit(1)
    _, tree = call("GET", f"{REST}/git/trees/{tip}?recursive=1")
    remote = {e["path"]: e["sha"] for e in tree["tree"] if e["type"] == "blob"}
    local = {}
    for dirpath, dirs, filenames in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, ROOT)
            with open(full, "rb") as f:
                local[rel] = blob_sha(f.read())
    only_remote = sorted(set(remote) - set(local))
    only_local = sorted(set(local) - set(remote))
    mismatched = sorted(p for p in set(remote) & set(local) if remote[p] != local[p])
    print(f"remote files: {len(remote)}, local files: {len(local)}")
    if only_remote:
        print("ONLY ON REMOTE (deleted locally):")
        for p in only_remote:
            print("  -", p)
    if only_local:
        print("ONLY LOCAL (new files):")
        for p in only_local:
            print("  +", p)
    if mismatched:
        print("CONTENT DIFFERS:")
        for p in mismatched:
            print("  ~", p, f"(remote {remote[p][:12]} vs local {local[p][:12]})")
    if only_remote or only_local or mismatched:
        print("DRIFT DETECTED")
        sys.exit(1)
    print("IDENTICAL to tip", tip[:12])
    sys.exit(0)

main()
