# Vulnerability Catalog

WARNING: This project is intentionally vulnerable and designed only for security testing practice.
Do not deploy this API to production and do not reuse these patterns in real systems.

## Included Vulnerabilities

1. SQL Injection (CWE-89)
- Endpoint: GET /api/data/search?username=<value>
- Endpoint: GET /api/data/profile/<idExpression>
- Endpoint: POST /api/auth/login
- Location: VulnerableDbService uses string-interpolated SQL with untrusted input.

2. Broken Authentication / Authorization (CWE-287, CWE-863)
- Endpoint: POST /api/auth/login
- Endpoint: GET /api/auth/admin?token=<value>
- Location: weak base64 token contains secrets; admin check uses substring match.

3. Sensitive Data Exposure (CWE-200)
- Endpoint: GET /api/data/profile/<idExpression>
- Location: API returns password and SSN values directly.

4. Path Traversal (CWE-22)
- Endpoint: GET /api/files/read?path=<value>
- Location: file read combines user input path without canonical path checks.

5. Weak Cryptography (CWE-327)
- Endpoint: POST /api/crypto/md5
- Location: MD5 used for hashing.

## Safer Alternatives

1. Use parameterized SQL commands and ORM query parameters.
2. Use signed tokens (JWT/OIDC) and robust role/claims authorization checks.
3. Never return secrets, credentials, SSNs, or internals to clients.
4. Normalize and validate paths; enforce allowlists; constrain to known roots.
5. Use modern algorithms such as SHA-256/Argon2/bcrypt/PBKDF2 as appropriate.
