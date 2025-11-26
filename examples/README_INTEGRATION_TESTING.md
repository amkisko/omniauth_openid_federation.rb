# OpenID Federation Integration Testing

This directory contains comprehensive mock servers and integration tests for the complete OpenID Federation flow.

## Architecture

The integration test setup consists of:

1. **Mock OP Server** (`mock_op_server.rb`) - Simulates an OpenID Provider
2. **Mock RP Server** (`mock_rp_server.rb`) - Simulates a Relying Party (Client)
3. **Integration Test Flow** (`integration_test_flow.rb`) - Automated tests for the complete flow

## Complete OpenID Federation Flow

### 1. Provider Exposes Entity Statement with JWKS

The OP server exposes its entity configuration at:
```
GET /.well-known/openid-federation
```

Returns a signed JWT containing:
- Provider metadata (authorization_endpoint, token_endpoint, etc.)
- JWKS (public keys for signing/encryption)
- Authority hints (if subordinate to a Trust Anchor)

### 2. Client Exposes Entity Statement with JWKS

The RP server exposes its entity configuration at:
```
GET /.well-known/openid-federation
```

Returns a signed JWT containing:
- RP metadata (redirect_uris, client_name, etc.)
- JWKS (public keys for signing request objects)
- Authority hints (if subordinate to a Trust Anchor)

### 3. Client Fetches Provider Statement with Keys

When the RP initiates login:
1. RP fetches OP's entity statement from `/.well-known/openid-federation`
2. RP validates the entity statement signature
3. RP extracts OP's JWKS for future token validation
4. RP extracts OP's metadata (endpoints, capabilities)

### 4. Client Sends Login Request

RP generates a signed request object (JWT) containing:
- `client_id`: RP's Entity ID
- `redirect_uri`: Callback URL
- `scope`: Requested scopes
- `state`: CSRF protection
- `nonce`: Replay protection
- `aud`: OP's Entity ID

The request object is:
- **Always signed** with RP's private key (RFC 9101 requirement)
- **Optionally encrypted** if OP requires encryption

RP redirects to OP's authorization endpoint:
```
GET /auth?request=<signed_jwt>
```

### 5. Provider Fetches Client Statement and Keys

When OP receives the authorization request:
1. OP extracts `client_id` from the request object
2. OP fetches RP's entity statement from `/.well-known/openid-federation`
3. OP validates RP's entity statement signature
4. OP extracts RP's JWKS from the entity statement
5. OP validates the request object signature using RP's public key
6. OP resolves RP's trust chain (if trust anchors configured)
7. OP applies metadata policies from trust chain
8. OP validates `redirect_uri` against RP's allowed redirect URIs

### 6. Exchange and Authenticated Login

After user authorization:
1. OP redirects back to RP with authorization code
2. RP exchanges code for tokens at OP's token endpoint
3. OP returns ID token (signed with OP's private key)
4. RP validates ID token signature using OP's JWKS
5. RP validates ID token claims (iss, aud, exp, nonce)
6. User is authenticated

## Error Scenarios Supported

The mock servers support error injection via `?error_mode=<mode>` parameter:

### Invalid Statement
```
GET /.well-known/openid-federation?error_mode=invalid_statement
```
Returns malformed JWT to test error handling.

### Wrong Keys
```
GET /.well-known/jwks.json?error_mode=wrong_keys
GET /.well-known/openid-federation?error_mode=wrong_keys
```
Returns JWKS with keys that don't match the signing key.

### Invalid Request
```
GET /auth?error_mode=invalid_request
```
Rejects request object validation to test error handling.

### Invalid Signature
```
GET /.well-known/signed-jwks.json?error_mode=invalid_signature
```
Returns signed JWKS with invalid signature.

### Expired Statement
```
GET /.well-known/openid-federation?error_mode=expired_statement
```
Returns expired entity statement to test expiration handling.

### Missing Metadata
```
GET /.well-known/openid-federation?error_mode=missing_metadata
```
Returns entity statement without metadata to test validation.

## Usage

### Quick Start (Automated - Recommended)

The integration test flow can automatically start servers, generate keys, and run all tests:

```bash
# Single command - fully automated
ruby examples/integration_test_flow.rb
```

This will:
1. Create temporary directories for keys and configs
2. Generate RSA keys for both OP and RP (using rake task logic)
3. Configure and start both servers automatically
4. Wait for servers to be ready
5. Run all integration tests
6. Clean up (kill servers, remove tmp dirs) on exit

### Manual Start (For Debugging)

If you want to start servers manually for debugging:

**Terminal 1 - OP Server:**
```bash
ruby examples/mock_op_server.rb
# Server runs on http://localhost:9292
```

**Terminal 2 - RP Server:**
```bash
ruby examples/mock_rp_server.rb
# Server runs on http://localhost:9293
```

**Terminal 3 - Integration Tests:**
```bash
# Disable auto-start to use manually started servers
AUTO_START_SERVERS=false ruby examples/integration_test_flow.rb
```

### Environment Variables

The integration test flow supports the following environment variables:

```bash
# Server URLs
OP_URL=http://localhost:9292          # OP server URL
RP_URL=http://localhost:9293          # RP server URL

# Server Ports
OP_PORT=9292                          # OP server port
RP_PORT=9293                          # RP server port

# Entity IDs
OP_ENTITY_ID=https://op.example.com   # OP entity identifier
RP_ENTITY_ID=https://rp.example.com   # RP entity identifier

# Temporary Directory
TMP_DIR=tmp/integration_test          # Directory for keys/configs (default: tmp/integration_test)

# Auto-start servers (true/false)
AUTO_START_SERVERS=true               # Auto-start servers (default: true)

# Cleanup on exit (true/false)
CLEANUP_ON_EXIT=true                  # Clean up tmp dirs on exit (default: true)

# Key Type
KEY_TYPE=separate                     # 'single' or 'separate' (default: separate)
```

**Example with custom configuration:**
```bash
KEY_TYPE=separate \
TMP_DIR=/tmp/my_test \
ruby examples/integration_test_flow.rb
```

**Note**: By default, the integration test uses localhost URLs for complete isolation:
- No DNS resolution required
- No external network dependencies
- All communication happens on localhost
- Entity IDs default to `http://localhost:9292` (OP) and `http://localhost:9293` (RP)

This ensures the tests work in any environment without network configuration.

### Manual Testing

**1. Test Provider Entity Statement:**
```bash
curl http://localhost:9292/.well-known/openid-federation
```

**2. Test Client Entity Statement:**
```bash
curl http://localhost:9293/.well-known/openid-federation
```

**3. Test Login Flow:**
```bash
# Initiate login (will redirect to OP)
curl -L "http://localhost:9293/login?provider=https://op.example.com"
```

**4. Test Error Scenarios:**
```bash
# Invalid statement
curl "http://localhost:9292/.well-known/openid-federation?error_mode=invalid_statement"

# Wrong keys
curl "http://localhost:9292/.well-known/jwks.json?error_mode=wrong_keys"

# Expired statement
curl "http://localhost:9292/.well-known/openid-federation?error_mode=expired_statement"
```

## Configuration

### OP Server Configuration

Create `examples/config/mock_op.yml`:

```yaml
entity_id: "https://op.example.com"
server_host: "localhost:9292"
signing_key: |
  -----BEGIN RSA PRIVATE KEY-----
  ...
  -----END RSA PRIVATE KEY-----
encryption_key: |  # Optional, defaults to signing_key
  -----BEGIN RSA PRIVATE KEY-----
  ...
  -----END RSA PRIVATE KEY-----
trust_anchors:
  - entity_id: "https://ta.example.com"
    jwks:
      keys:
        - kty: "RSA"
          kid: "ta-key-1"
          use: "sig"
          n: "..."
          e: "AQAB"
authority_hints:  # Optional, if OP is subordinate
  - "https://ta.example.com"
op_metadata:
  issuer: "https://op.example.com"
  authorization_endpoint: "https://op.example.com/auth"
  token_endpoint: "https://op.example.com/token"
  request_object_encryption_alg_values_supported: ["RSA-OAEP"]
  request_object_encryption_enc_values_supported: ["A128CBC-HS256"]
require_request_encryption: false  # Set to true to require encryption
validate_request_objects: true     # Set to false to skip validation
```

### RP Server Configuration

Create `examples/config/mock_rp.yml`:

```yaml
entity_id: "https://rp.example.com"
server_host: "localhost:9293"
signing_key: |
  -----BEGIN RSA PRIVATE KEY-----
  ...
  -----END RSA PRIVATE KEY-----
encryption_key: |  # Optional, for decrypting encrypted ID tokens
  -----BEGIN RSA PRIVATE KEY-----
  ...
  -----END RSA PRIVATE KEY-----
trust_anchors:
  - entity_id: "https://ta.example.com"
    jwks:
      keys: [...]
authority_hints:  # Optional, if RP is subordinate
  - "https://ta.example.com"
redirect_uris:
  - "https://rp.example.com/callback"
```

## Testing Scenarios

### Happy Path

1. Start both servers
2. Run integration tests: `ruby examples/integration_test_flow.rb`
3. All tests should pass

### Error Scenarios

1. Test invalid entity statement:
   ```bash
   curl "http://localhost:9292/.well-known/openid-federation?error_mode=invalid_statement"
   ```

2. Test wrong keys:
   ```bash
   curl "http://localhost:9292/.well-known/jwks.json?error_mode=wrong_keys"
   ```

3. Test expired statement:
   ```bash
   curl "http://localhost:9292/.well-known/openid-federation?error_mode=expired_statement"
   ```

### Request Object Validation

1. Test with valid signed request object:
   ```bash
   curl "http://localhost:9293/login?provider=https://op.example.com"
   ```

2. Test with invalid request object:
   ```bash
   curl "http://localhost:9292/auth?error_mode=invalid_request&request=invalid.jwt"
   ```

### Trust Chain Resolution

1. Configure trust anchors in both servers
2. Ensure RP has authority_hints pointing to trust anchor
3. OP will resolve RP's trust chain during authorization
4. OP will apply metadata policies from trust chain

## Security Testing

The mock servers support comprehensive security testing:

- **Algorithm Confusion**: Test rejection of non-RS256 algorithms
- **Key Confusion**: Test rejection of wrong keys
- **Signature Verification**: Test rejection of tampered signatures
- **Path Traversal**: Test rejection of malicious paths
- **Replay Attacks**: Test nonce validation
- **Request Object Validation**: Test signature and encryption validation
- **Trust Chain Validation**: Test authority hints and metadata policy enforcement

## Troubleshooting

### Server Won't Start

- Check if ports 9292 (OP) and 9293 (RP) are available
- Verify all dependencies are installed: `bundle install`
- Check configuration files exist and are valid YAML

### Entity Statements Not Validating

- Verify keys are correctly configured
- Check entity IDs match between servers
- Ensure trust anchors are configured if using trust chains

### Request Objects Rejected

- Verify RP's entity statement is accessible
- Check RP's JWKS contains the signing key
- Ensure request object is properly signed
- Verify encryption if required by OP

### Trust Chain Resolution Fails

- Verify trust anchors are configured
- Check authority_hints are correct
- Ensure all entity statements in chain are valid
- Verify subordinate statements are available

## Next Steps

1. **Add More Error Scenarios**: Extend error injection modes
2. **Performance Testing**: Add load testing scenarios
3. **Security Testing**: Add fuzzing and penetration tests
4. **Trust Mark Testing**: Add trust mark validation
5. **Metadata Policy Testing**: Add comprehensive policy merging tests

