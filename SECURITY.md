# SECURITY

## Reporting a Vulnerability

**Do NOT** open a public GitHub issue for security vulnerabilities.

Email security details to: **contact@kiskolabs.com**

Include: description, steps to reproduce, potential impact, and suggested fix (if available).

**Response Timeline:**
- Acknowledgment within 48 hours
- Initial assessment within 7 days
- Coordinated disclosure after patching

## Library Security Features

### Implemented Protections

**✅ Constant-Time State Comparison**
- Uses `Rack::Utils.secure_compare` for state parameter validation to prevent timing attacks
- Location: `strategy.rb:182`

**✅ Path Traversal Protection**
- `Utils.validate_file_path!` prevents `..` sequences and validates against allowed directories
- File paths are restricted to configured allowed directories

**✅ Signed Request Objects (RFC 9101)**
- All authorization requests **MUST** use signed request objects (mandatory per OpenID Federation 1.0 spec)
- Signing is enforced at library level - cannot be bypassed
- Request objects **MAY** be encrypted (optional) when provider requires it or `always_encrypt_request_object` is enabled
- Prevents parameter tampering and ensures request authenticity

**✅ JWT Algorithm Validation**
- JWT library validates algorithms and signatures
- Unsigned tokens (`alg: none`) are explicitly handled and rejected for signed tokens
- Only strong algorithms accepted (RS256, etc.)

**✅ Logging Sanitization**
- Sensitive data (tokens, keys) is never logged
- File paths are sanitized before logging
- URLs are sanitized (query parameters removed) in debug logs

**✅ Timeout Limits**
- HTTP requests have configurable timeouts to prevent long-running requests

### Known Limitations & Risks

**⚠️ SSRF Risk (Server-Side Request Forgery)**
- The library fetches entity statements and JWKS from URLs without validating against internal network access
- **Risk:** URLs could target localhost, private IPs, or cloud metadata endpoints
- **Mitigation:** Application should validate URLs before passing to library, or implement URL validation in library configuration

**⚠️ Memory Safety**
- Ruby does not provide secure memory management for sensitive data
- Private keys may persist in memory until garbage collection
- Memory dumps may contain key material
- **Mitigation:** Use secure environments and access controls

**⚠️ SSL/TLS Verification**
- SSL verification is automatically disabled in Rails development mode
- **Production:** Application must ensure SSL verification is enabled

**⚠️ Entity Statement Validation**
- Fingerprint validation is optional - skipping validation may allow malicious entity statements
- **Recommendation:** Always validate entity statement fingerprints when fetching from untrusted sources

**⚠️ Key Rotation Window**
- Brief window (up to cache TTL, default 24 hours) where rotated keys might not be immediately available
- Library handles this with retry logic, but applications should monitor rotation events

## Input/Output Points

### Input Points (Library Handles)

1. **OAuth Callback Parameters** (`code`, `state`, `error`)
   - State validated with constant-time comparison
   - Authorization codes are single-use and time-limited

2. **OAuth Request Parameters** (`acr_values`, `login_hint`, etc.)
   - All parameters are signed in JWT request objects (RFC 9101)
   - Parameters validated before inclusion

3. **Entity Statement URLs**
   - Fetched via HTTP client
   - **SSRF Risk:** No validation against internal network access

4. **File Paths** (configuration)
   - Validated with `Utils.validate_file_path!` to prevent path traversal
   - Restricted to allowed directories

5. **JWT/JWE Tokens** (from OAuth provider)
   - Algorithm validation enforced
   - Signature validation required for signed tokens
   - Entity statement fingerprints provide additional validation

### Output Points (Library Exposes)

1. **HTTP Responses** (if using `RackEndpoint`)
   - `/.well-known/openid-federation` - Entity statement (JWT)
   - `/.well-known/jwks.json` - Public JWKS
   - `/.well-known/signed-jwks.json` - Signed JWKS (JWT)
   - Only public keys exposed (private keys never exposed)

2. **Logs**
   - Sensitive data (tokens, keys) never logged
   - File paths and URLs sanitized before logging

3. **Error Messages**
   - File paths sanitized in error messages
   - Generic error messages (stack traces only in development)

## Security Considerations

- **Timing Attacks**: State parameter protected with constant-time comparison
- **Path Traversal**: ✅ `Utils.validate_file_path!` prevents `..` sequences
- **JWT Algorithm Confusion**: ✅ Algorithm validation enforced, `alg: none` rejected
- **Replay Attacks**: Authorization codes are single-use and time-limited

## Automation Security

* **Context Isolation:** It is strictly forbidden to include production credentials, API keys, or Personally Identifiable Information (PII) in prompts sent to third-party LLMs or automation services.

* **Supply Chain:** All automated dependencies must be verified.

## Contact

**Security concerns**: contact@kiskolabs.com  
**General support**: https://github.com/amkisko/omniauth_openid_federation.rb/issues
