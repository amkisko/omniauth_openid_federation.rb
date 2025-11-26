# Mock OpenID Provider (OP) Server

A standalone Rack/Sinatra application for testing OpenID Federation flows.

## Features

- ✅ Entity Configuration endpoint (`/.well-known/openid-federation`)
- ✅ Fetch Endpoint (`/.well-known/openid-federation/fetch`) for Subordinate Statements
- ✅ Authorization Endpoint (`/auth`) with trust chain resolution
- ✅ Token Endpoint (`/token`) with ID Token signing
- ✅ JWKS endpoints (standard and signed)
- ✅ UserInfo endpoint (mock)

## Quick Start

### 1. Install Dependencies

```bash
bundle install
```

### 2. Configure

Copy the example configuration:

```bash
cp examples/config/mock_op.yml.example examples/config/mock_op.yml
```

Edit `examples/config/mock_op.yml` with your settings:

```yaml
entity_id: "https://op.example.com"
server_host: "localhost:9292"
signing_key: |
  -----BEGIN RSA PRIVATE KEY-----
  ...
  -----END RSA PRIVATE KEY-----
trust_anchors:
  - entity_id: "https://ta.example.com"
    jwks:
      keys: [...]
```

### 3. Generate Keys (if needed)

```bash
# Generate OP signing key
openssl genrsa -out op-private-key.pem 2048
openssl rsa -in op-private-key.pem -pubout -out op-public-key.pem

# Extract JWKS from public key (or use the rake task)
rake openid_federation:prepare_client_keys
```

### 4. Run Server

```bash
# Option 1: Direct Ruby execution
ruby examples/mock_op_server.rb

# Option 2: Using Rack
rackup examples/mock_op_server.ru

# Option 3: With specific port
rackup -p 9292 examples/mock_op_server.ru
```

## Configuration Options

### Environment Variables

Instead of YAML, you can use environment variables:

```bash
export OP_ENTITY_ID="https://op.example.com"
export OP_SERVER_HOST="localhost:9292"
export OP_SIGNING_KEY="$(cat op-private-key.pem)"
export OP_TRUST_ANCHORS='[{"entity_id":"https://ta.example.com","jwks":{"keys":[...]}}]'
export OP_AUTHORITY_HINTS="https://federation.example.com"
```

### YAML Configuration

See `examples/config/mock_op.yml.example` for full configuration options.

## Testing Scenarios

### 1. Direct Entity Statement (No Trust Chain)

```bash
# Fetch OP's Entity Configuration
curl http://localhost:9292/.well-known/openid-federation

# Use in RP configuration
config.omniauth :openid_federation,
  issuer: "https://op.example.com",
  entity_statement_url: "http://localhost:9292/.well-known/openid-federation",
  client_options: { ... }
```

### 2. Trust Chain Resolution

```bash
# Configure trust anchors in mock_op.yml
trust_anchors:
  - entity_id: "https://ta.example.com"
    jwks: {...}

# RP with trust chain
# The OP will resolve the RP's trust chain automatically
curl "http://localhost:9292/auth?client_id=https://rp.example.com&redirect_uri=https://rp.example.com/callback"
```

### 3. Subordinate Statements

```bash
# Configure subordinate statements in mock_op.yml
subordinate_statements:
  "https://rp.example.com":
    metadata: {...}
    metadata_policy: {...}

# Fetch Subordinate Statement
curl "http://localhost:9292/.well-known/openid-federation/fetch?sub=https://rp.example.com"
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-federation` | GET | Entity Configuration (JWT) |
| `/.well-known/openid-federation/fetch` | GET | Fetch Subordinate Statement (requires `sub` parameter) |
| `/.well-known/jwks.json` | GET | Standard JWKS (JSON) |
| `/.well-known/signed-jwks.json` | GET | Signed JWKS (JWT) |
| `/auth` | GET | Authorization Endpoint (requires `client_id`, `redirect_uri`) |
| `/token` | POST | Token Endpoint (requires `code`, `grant_type=authorization_code`) |
| `/userinfo` | GET | UserInfo Endpoint (mock data) |
| `/` | GET | Health check and endpoint list |

## Example Flow

### 1. RP Discovers OP

```bash
# RP fetches OP's Entity Configuration
curl http://localhost:9292/.well-known/openid-federation
```

### 2. RP Initiates Authentication

```bash
# RP redirects user to authorization endpoint
# client_id is the RP's Entity ID (for automatic registration)
curl "http://localhost:9292/auth?client_id=https://rp.example.com&redirect_uri=https://rp.example.com/callback&state=xyz&nonce=abc"
```

### 3. OP Resolves RP's Trust Chain

The OP automatically:
- Resolves RP's trust chain using `TrustChainResolver`
- Merges metadata policies using `MetadataPolicyMerger`
- Validates RP's effective metadata
- Redirects back to RP with authorization code

### 4. RP Exchanges Code for Tokens

```bash
curl -X POST http://localhost:9292/token \
  -d "grant_type=authorization_code" \
  -d "code=<authorization_code>" \
  -d "redirect_uri=https://rp.example.com/callback" \
  -d "client_id=https://rp.example.com"
```

### 5. RP Validates ID Token

The RP validates the ID Token using the OP's JWKS from the effective metadata.

## Integration with Real RP

To test with a real RP application:

```ruby
# In RP's config/initializers/devise.rb
config.omniauth :openid_federation,
  issuer: "http://localhost:9292",
  entity_statement_url: "http://localhost:9292/.well-known/openid-federation",
  trust_anchors: [
    {
      entity_id: "https://ta.example.com",
      jwks: trust_anchor_jwks
    }
  ],
  client_options: {
    identifier: "https://rp.example.com", # RP's Entity ID
    redirect_uri: "http://localhost:3000/users/auth/openid_federation/callback",
    private_key: rp_private_key
  }
```

## Limitations

This is a **mock server for testing only**:

- ⚠️ No real user authentication (always returns mock user)
- ⚠️ Authorization codes stored in memory (lost on restart)
- ⚠️ No database persistence
- ⚠️ No production security hardening
- ⚠️ ID Tokens contain mock user data

## Production Considerations

For production use, you would need:

- Real user authentication system
- Database for authorization codes and tokens
- Proper session management
- Security hardening (rate limiting, CSRF protection, etc.)
- Real user data in ID Tokens
- Proper error handling and logging

## Troubleshooting

**"Federation endpoint not configured"**
- Ensure `signing_key` is provided in config
- Check that `entity_id` is set

**"Trust chain resolution failed"**
- Verify `trust_anchors` are correctly configured
- Ensure trust anchor JWKS are valid
- Check that RP's Entity ID is resolvable

**"Subordinate Statement not found"**
- Configure `subordinate_statements` in `mock_op.yml`
- Ensure subject Entity ID matches exactly

## See Also

- [OpenID Federation 1.0 Specification](https://openid.net/specs/openid-federation-1_0.html)
- [Main README](../README.md)
- [Federation Endpoint Documentation](../README.md#publishing-federation-endpoint)

