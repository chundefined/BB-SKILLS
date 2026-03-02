# Bug Bounty Report Template — Auth Bypass + File Overwrite

## Title
`[High/Critical] Authentication Bypass via Bearer Header Stripping Enables Arbitrary File Overwrite via Path Traversal in Upload Endpoint`

## Summary
The admin panel at `admin.target.com` performs authentication through a middleware that accepts raw JWT tokens in the `Authorization` header without enforcing the `Bearer ` scheme prefix. An attacker who obtains any valid JWT (e.g., their own low-privilege token, a leaked token, or a token harvested via another vulnerability) can strip the `Bearer ` prefix and gain access to admin-only functionality.

Once inside the admin panel, the `/api/upload-resource` endpoint accepts a user-controlled `fullFilePath` query parameter that is passed directly to the file system without path canonicalization. By injecting `../` sequences, an attacker can write arbitrary content to any file the web server process has write access to, including web root assets, server-side scripts, and configuration files.

## Impact
- **Authentication Bypass:** Any valid JWT (regardless of privilege level) grants administrative access. Eliminates the security boundary between normal users and administrators.
- **Arbitrary File Write:** Content can be written to any path reachable by the server process — web root, configuration files, cron jobs.
- **Potential RCE:** Overwriting an executable file (PHP script, Node.js module, cron job) with a malicious payload enables remote code execution and full server compromise.
- **Persistent Backdoor:** Overwriting a static asset (JS bundle, HTML page) allows injecting malicious code served to all users of the application (stored XSS with system-wide impact).

## Severity
**High** — CVSS 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N) for auth bypass + file overwrite.

Escalates to **Critical** — CVSS 9.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) if RCE is demonstrated.

## Steps to Reproduce
1. Log in as any user (low-privilege account) and capture the JWT from the `Authorization` header.
2. Send a GET request to `https://admin.target.com/api/admin/dashboard` with `Authorization: <JWT>` (no "Bearer " prefix). Observe `200 OK` response — authentication bypass confirmed.
3. Navigate to the admin file upload section. Upload a benign file and intercept the POST request to `/api/upload-resource`.
4. Modify the `fullFilePath` parameter to `resource%2F%2e%2e%2F%2e%2e%2Fweb%2Fbuild%2Fpoc.html` (decoded: `resource/../../web/build/poc.html`).
5. Set the file body to `<html><body>Vulnerable</body></html>`.
6. Send the request. Observe `200 OK` — file write accepted outside upload root.
7. Access `https://admin.target.com/build/poc.html` and confirm the file content is served.

## Recommended Fix

**Authentication Middleware:**
- Strictly validate that the `Authorization` header begins with exactly `Bearer ` (with trailing space). Reject any request where the scheme is absent or different with `401 Unauthorized`.

**Upload Endpoint:**
- Canonicalize the `fullFilePath` value using `path.resolve()` (or equivalent) before constructing the file system destination.
- Enforce a path jail: verify that the resolved absolute path starts with the designated upload root directory.
- Apply an extension allowlist and reject files with executable or sensitive extensions (`.php`, `.jsp`, `.js`, `.sh`, `.py`, `.env`, `.conf`).
- Store uploaded files in a directory that is not directly web-accessible; serve them through a controlled route that sets appropriate `Content-Type` and `Content-Disposition` headers.

---

## References
- [OWASP — Path Traversal (CWE-22)](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP — Broken Access Control (A01:2021)](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide v4.2 — Testing for Path Traversal (OTG-AUTHZ-001)](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger — File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [PortSwigger — Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [PayloadsAllTheThings — Path Traversal Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)
- [HackTricks — File Upload Vulnerabilities](https://book.hacktricks.xyz/pentesting-web/file-upload)
- [RFC 6750 — The OAuth 2.0 Authorization Framework: Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
