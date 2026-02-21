# Web2 Bug Bounty Skills — Category Index

## Purpose
Index of all Web2 / Traditional Web Application security skills. Read this to find the right skill for your target.

## Scope of This Category
Any target involving: web applications, REST APIs, GraphQL APIs, admin panels, authentication systems, file upload endpoints, server-side logic, session management, or any non-blockchain web infrastructure.

---

## Available Sub-Categories

### Broken Access Control
**Path:** `broken-access-control/SKILL.md`
**Use when:** Target has authentication or authorization enforcement issues — missing server-side checks, client-side-only controls, header manipulation, or IDOR vulnerabilities.

| Vulnerability | Severity | Path |
|---|---|---|
| Auth Bypass via Header Stripping + Arbitrary File Overwrite | High/Critical | `broken-access-control/auth-bypass-header-stripping-file-overwrite/SKILL.md` |

---

## Routing Logic

```
Is the vulnerability in...
│
├── Authentication / Authorization bypass?
│   └── → broken-access-control/SKILL.md
│
├── Injection (SQLi, XSS, SSTI, SSRF)?
│   └── → [COMING SOON] injection/SKILL.md
│
├── File Upload / Path Traversal?
│   └── → broken-access-control/SKILL.md
│
├── Business Logic / Race Conditions?
│   └── → [COMING SOON] business-logic/SKILL.md
│
└── Cryptographic / Session Management?
    └── → [COMING SOON] crypto-session/SKILL.md
```

---

## Key Concepts for Web2 Auditing
- **Client-Side vs Server-Side Enforcement:** Any security check that only exists in the browser (JavaScript, CSS display:none) is trivially bypassable. Real access control must be enforced on every API request server-side.
- **JWT Bearer Token Format:** The `Authorization: Bearer <token>` header format is conventional — servers that check only for the word "Bearer" without parsing the full scheme are vulnerable to stripping attacks.
- **Path Traversal:** File systems process `../` sequences to move up directory trees. Any user-controlled input that flows into a file path must be canonicalized and validated before use.
- **OWASP Top 10 A01 — Broken Access Control:** The most prevalent web vulnerability class as of 2021. Includes missing function-level access control, IDOR, path traversal, and metadata manipulation.
