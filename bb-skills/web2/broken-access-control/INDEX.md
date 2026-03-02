# Web2 — Broken Access Control Skills Index

## Purpose
Index of Broken Access Control vulnerabilities for web2 targets. Read this to find the right skill.

## Scope
Broken Access Control encompasses any vulnerability where the application fails to correctly enforce who can perform which actions. This includes authentication bypass, authorization bypass, IDOR, path traversal, and privilege escalation.

---

## Available Skills

| Vulnerability | Severity | CVSS | Path |
|---|---|---|---|
| Auth Bypass via Bearer Header Stripping + Arbitrary File Overwrite via Path Traversal | High / Critical | 8.1–9.1 | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |

---

## Routing Decision Table

| Observed Condition | Skill to Apply |
|---|---|
| Admin panel accessible by removing "Bearer " prefix from Authorization header | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |
| Upload endpoint accepts `filename` / `fullFilePath` parameter with `../` sequences | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |
| Client-side React/Vue admin checks auth via header but server validates loosely | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |
| JWT token present but server accepts raw token without "Bearer " scheme prefix | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |

---

## OWASP References
- **A01:2021 — Broken Access Control** (was A05:2017)
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- **CWE-284:** Improper Access Control
- **CWE-862:** Missing Authorization
