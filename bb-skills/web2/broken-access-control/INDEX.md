# Broken Access Control — Skills

## Quick Recon
```bash
# Find JWT / Bearer handling
grep -rn "Bearer\|Authorization\|jwt\|token" --include="*.js" --include="*.ts" --include="*.py" --include="*.go"

# Find file path parameters (path traversal candidates)
grep -rn "fullFilePath\|filename\|dest\|path\|filepath" --include="*.js" --include="*.ts" --include="*.py"

# Find file write operations
grep -rn "writeFile\|write_file\|open.*w\|fs\.write\|os\.write" --include="*.js" --include="*.ts" --include="*.py"
```

## Skills

| Skill | CWE | Trigger pattern | Severity | File |
|---|---|---|---|---|
| Auth Bypass via Bearer Header Stripping + Arbitrary File Overwrite | CWE-287, CWE-22, CWE-434 | Server accepts raw JWT without `Bearer ` prefix **AND** file upload endpoint with user-controlled destination path | High → Critical (RCE) | `auth-bypass-header-stripping-file-overwrite/SKILL.md` |
