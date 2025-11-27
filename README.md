# omniauth_openid_federation

[![Gem Version](https://badge.fury.io/rb/omniauth_openid_federation.svg?v=1.1.0)](https://badge.fury.io/rb/omniauth_openid_federation) [![Test Status](https://github.com/amkisko/omniauth_openid_federation.rb/actions/workflows/test.yml/badge.svg)](https://github.com/amkisko/omniauth_openid_federation.rb/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/amkisko/omniauth_openid_federation.rb/graph/badge.svg?token=CX3O9M1GIT)](https://codecov.io/gh/amkisko/omniauth_openid_federation.rb)

OmniAuth strategy for OpenID Federation providers with comprehensive security features, supporting signed request objects, ID token encryption, and full OpenID Federation 1.0 compliance.

Sponsored by [Kisko Labs](https://www.kiskolabs.com).

<a href="https://www.kiskolabs.com">
  <img src="kisko.svg" width="200" alt="Sponsored by Kisko Labs" />
</a>


## Installation

```ruby
# Gemfile
gem "omniauth_openid_federation"
```

```bash
bundle install
```

## Features

- ✅ **Signed Request Objects (RFC 9101)** - RS256 signing of authorization requests (per OpenID Federation spec: "MUST be signed")
- ✅ **Optional Request Object Encryption** - Optional RSA-OAEP encryption when provider requires it (per spec: "MAY be encrypted")
- ✅ **ID Token Encryption/Decryption** - RSA-OAEP encryption and A128CBC-HS256 decryption
- ✅ **OpenID Federation 1.0** - Full entity statement support and federation metadata
- ✅ **Federation Endpoint** - Publish entity statements at `/.well-known/openid-federation`
- ✅ **Automatic Key Provisioning** - Automatic extraction/generation of signing and encryption keys with caching support
- ✅ **Separate Key Support** - Production-ready support for separate signing and encryption keys
- ✅ **Entity Type Support** - Full support for both `openid_relying_party` (RP) and `openid_provider` (OP) entity types
- ✅ **Signed JWKS Support** - Automatic validation for key rotation compliance
- ✅ **Automatic Provider Key Rotation** - Handles external provider key rotation automatically via Signed JWKS (client key rotation is manual)
- ✅ **Client Assertion (private_key_jwt)** - Secure client authentication
- ✅ **Security Hardened** - OWASP compliant, rate limiting, path traversal protection
- ✅ **Production Ready** - Thread-safe, comprehensive error handling

## Quick Start

The library relies on **URLs and fingerprint verification** for security. Always fetch entity statements from provider URLs - local files are cached copies for configuration use. Everything is automated via discovery.

### Step 1: Get Provider Information

Your provider will provide:
- **Entity statement URL**: `https://provider.example.com/.well-known/openid-federation`
- **Expected fingerprint hash**: For verification (security guard)

**Always use URLs**: Fetch and cache the entity statement locally using the URL and fingerprint:

```bash
rake openid_federation:fetch_entity_statement[
  "https://provider.example.com/.well-known/openid-federation",
  "expected-fingerprint-hash",
  "config/provider-entity-statement.jwt"
]
```

This fetches from the URL, verifies the fingerprint, and stores locally. The local file is a cached copy of the URL - always use the URL as the source of truth.

### Step 2: Generate Client Keys

Generate RSA key pair for client authentication:

   ```bash
rake openid_federation:prepare_client_keys
```

This generates:
- Private key: `config/client-private-key.pem` (keep secure, never commit)
- Public JWKS: `config/client-jwks.json` (send to provider for explicit registration)

**Security**: Never commit private keys. Add to `.gitignore`:
```
config/*-private-key.pem
```

### Step 3: Register Client

**Explicit Registration** (default):
1. Send `config/client-jwks.json` to your provider
2. Receive Client ID from provider

**Automatic Registration** (if provider supports it):
- No pre-registration needed
- Client entity statement is auto-generated via `FederationEndpoint` (see Step 5)
- Set `client_entity_statement_url` to `https://your-app.com/.well-known/openid-federation`

### Step 4: Configure OmniAuth Strategy

#### For Devise (Rails)

```ruby
# config/initializers/devise.rb
require "omniauth_openid_federation"

private_key = OpenSSL::PKey::RSA.new(File.read("config/client-private-key.pem"))

# Always provide the entity statement URL
entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
entity_statement_fingerprint = "expected-fingerprint-hash"

# Fetch and cache entity statement from URL (run this via rake task or in initializer)
# rake openid_federation:fetch_entity_statement[entity_statement_url, entity_statement_fingerprint, "config/provider-entity-statement.jwt"]

config.omniauth :openid_federation,
  discovery: true,  # Enables automatic endpoint discovery
  # Option 1: Provide URL (recommended - library fetches and caches automatically)
  entity_statement_url: entity_statement_url,  # Always provide URL as source of truth
  entity_statement_fingerprint: entity_statement_fingerprint,  # Fingerprint for verification
  # Option 2: Provide issuer (library builds URL from issuer + /.well-known/openid-federation)
  # issuer: "https://provider.example.com",
  # Option 3: Provide cached path (optional - for offline development)
  # entity_statement_path: "config/provider-entity-statement.jwt",  # Cached copy from URL
  client_options: {
    identifier: ENV["OPENID_CLIENT_ID"],
    redirect_uri: "#{ENV["APP_URL"]}/users/auth/openid_federation/callback",
    private_key: private_key
  }
```

**Key Points**:
- `entity_statement_url` is recommended - library automatically fetches and caches
- `entity_statement_fingerprint` is used for verification when fetching from URL
- `issuer` can be used instead - library builds URL from issuer + `/.well-known/openid-federation`
- `entity_statement_path` is optional - only for offline development (cached copy)
- `discovery: true` automatically discovers all endpoints from entity statement

**Important**: Don't forget to configure CSRF protection (see [Step 7: Configure CSRF Protection](#step-7-configure-csrf-protection)) to ensure proper security for both request and callback phases.

#### For OmniAuth (non-Rails)

```ruby
# config/initializers/omniauth.rb
require "omniauth_openid_federation"

entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
entity_statement_fingerprint = "expected-fingerprint-hash"

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_federation,
    discovery: true,
    entity_statement_path: "config/provider-entity-statement.jwt",  # Cached copy from URL
    entity_statement_url: entity_statement_url,  # Always provide URL as source of truth
    entity_statement_fingerprint: entity_statement_fingerprint,  # Fingerprint for verification
    client_options: {
      identifier: ENV["OPENID_CLIENT_ID"],
      redirect_uri: "https://your-app.com/auth/openid_federation/callback",
      private_key: OpenSSL::PKey::RSA.new(File.read("config/client-private-key.pem"))
    }
end
```

### Step 5: Configure Federation Endpoint (For Automatic Registration)

If using automatic registration, publish your client entity statement:

```ruby
# config/initializers/omniauth_openid_federation.rb
OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  issuer: ENV["APP_URL"],
  private_key: private_key,
  entity_statement_path: "config/client-entity-statement.jwt",  # Optional: cached copy for offline dev
  metadata: {
    openid_provider: {
      issuer: ENV["APP_URL"],
      authorization_endpoint: "#{ENV["APP_URL"]}/users/auth/openid_federation",
      token_endpoint: "#{ENV["APP_URL"]}/users/auth/openid_federation",
      userinfo_endpoint: "#{ENV["APP_URL"]}/users/auth/openid_federation",
      jwks_uri: "#{ENV["APP_URL"]}/.well-known/jwks.json",
      signed_jwks_uri: "#{ENV["APP_URL"]}/.well-known/signed-jwks.json"
    }
  }
)
```

```ruby
# config/routes.rb
# RECOMMENDED: Mount the Engine (Rails-idiomatic way)
mount OmniauthOpenidFederation::Engine => "/"

# ALTERNATIVE: Use mount_routes helper (for backward compatibility)
# OmniauthOpenidFederation::FederationEndpoint.mount_routes(self)
```

**Key Points**:
- `auto_configure` automatically extracts/generates JWKS from keys
- Only application-specific endpoints need to be provided in metadata
- Well-known endpoints are auto-generated

### Step 6: Add Routes

#### Mount the Engine (Required for Federation Endpoints)

The gem provides a Rails Engine that serves the well-known OpenID Federation endpoints. Mount it in your routes:

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # Mount the Engine to enable /.well-known/openid-federation endpoint
  mount OmniauthOpenidFederation::Engine => "/"
  
  # Your other routes...
  devise_for :users, controllers: {
    omniauth_callbacks: "users/omniauth_callbacks"
  }
end
```

**Note**: The Engine is mounted at root (`"/"`) because OpenID Federation requires endpoints at specific well-known paths (e.g., `/.well-known/openid-federation`). The Engine's routes are defined in the gem and automatically available when mounted.

#### For OmniAuth (Non-Devise)

```ruby
# config/routes.rb
Rails.application.routes.draw do
  mount OmniauthOpenidFederation::Engine => "/"
  
  get "/auth/:provider/callback", to: "sessions#create"
  get "/auth/failure", to: "sessions#failure"
end
```

#### Alternative: Manual Route Mounting (Backward Compatibility)

If you need custom paths or prefer manual route definition, you can use the `mount_routes` helper (deprecated):

```ruby
# config/routes.rb
Rails.application.routes.draw do
  # Use mount_routes helper for custom paths (deprecated - prefer Engine mounting)
  OmniauthOpenidFederation::FederationEndpoint.mount_routes(self)
  # ... your other routes
end
```

### Step 7: Configure CSRF Protection

OmniAuth requires CSRF protection configuration to handle both the request phase (initiating OAuth) and callback phase (external provider redirect).

**Important**: The request phase uses Rails CSRF tokens (forms must include them), while the callback phase uses OAuth state parameter for CSRF protection (external providers cannot include Rails CSRF tokens).

#### For Devise (Rails)

```ruby
# config/initializers/devise.rb
if defined?(OmniAuth)
  OmniAuth.config.allowed_request_methods = [:post]
  OmniAuth.config.silence_get_warning = false

  # Configure CSRF validation to check tokens only for request phase (initiating OAuth)
  # Callback phase uses OAuth state parameter for CSRF protection (validated in strategy)
  # This ensures:
  # - Request phase: Forms must include Rails CSRF tokens (standard Rails protection)
  # - Callback phase: OAuth state parameter provides CSRF protection (external providers can't include Rails tokens)
  OmniAuth.config.request_validation_phase = lambda do |env|
    request = Rack::Request.new(env)
    path = request.path

    # Skip CSRF validation for callback paths (external providers can't include Rails CSRF tokens)
    # OAuth state parameter provides CSRF protection for callbacks (validated in OpenIDFederation strategy)
    return true if path.end_with?("/callback")

    # For request phase, use Rails' standard CSRF token validation
    # This ensures forms must include valid CSRF tokens when initiating OAuth
    session = env["rack.session"] || {}
    token = request.params["authenticity_token"] || request.get_header("X-CSRF-Token")
    expected_token = session[:_csrf_token] || session["_csrf_token"]

    # Validate CSRF token using constant-time comparison
    if token.present? && expected_token.present?
      ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected_token.to_s)
    else
      false
    end
  end
end
```

**Security Notes**:
- **Request phase** (initiating OAuth): Forms must include Rails CSRF tokens via `button_to` or `form_with` helpers
- **Callback phase** (external provider redirect): OAuth `state` parameter provides CSRF protection (automatically validated in `OpenIDFederation` strategy using constant-time comparison)
- Both layers provide equivalent security - Rails CSRF tokens for request phase, OAuth state parameter for callbacks

### Step 8: Create Callback Controller

#### For Devise

```ruby
# app/controllers/users/omniauth_callbacks_controller.rb
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  # Skip Rails CSRF protection for OAuth callbacks
  # OAuth callbacks from external providers cannot include Rails CSRF tokens
  # CSRF protection is handled by OAuth state parameter validation in the strategy
  skip_before_action :verify_authenticity_token, only: [:openid_federation, :failure]
  skip_before_action :authenticate_user!, only: [:openid_federation, :failure]

  def openid_federation
    auth = request.env["omniauth.auth"]
    user = User.find_or_create_from_omniauth(auth)
    
    if user&.persisted?
      sign_in_and_redirect user, event: :authentication
    else
      redirect_to root_path, alert: "Authentication failed"
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed"
  end
end
```

**Note**: The `skip_before_action :verify_authenticity_token` is required because Rails' `protect_from_forgery` in `ApplicationController` checks CSRF tokens for all POST requests. External providers cannot include Rails CSRF tokens in callbacks, so we skip Rails' check while relying on OAuth state parameter validation (handled by the strategy).

### Step 9: Create User Model Method

```ruby
# app/models/user.rb
class User < ApplicationRecord
  def self.find_or_create_from_omniauth(auth)
    user = find_by(provider: auth.provider, uid: auth.uid)
    
    if user
      user.update(
        email: auth.info.email,
        name: auth.info.name,
        first_name: auth.info.first_name,
        last_name: auth.info.last_name
      )
    else
      user = create(
        provider: auth.provider,
        uid: auth.uid,
        email: auth.info.email,
        name: auth.info.name,
        first_name: auth.info.first_name,
        last_name: auth.info.last_name
      )
    end
    
    user
  end
end
```

## Rake Tasks

### Prepare Client Keys

```bash
rake openid_federation:prepare_client_keys
rake openid_federation:prepare_client_keys[separate,config]  # Separate signing/encryption keys
```

### Fetch Entity Statement

Fetches entity statement from provider URL, verifies fingerprint, and caches locally:

```bash
rake openid_federation:fetch_entity_statement[
  "https://provider.example.com/.well-known/openid-federation",
  "expected-fingerprint-hash",
  "config/provider-entity-statement.jwt"
]
```

**Note**: Always use the URL as the source of truth - the local file is just a cached copy.

### Parse Entity Statement

```bash
rake openid_federation:parse_entity_statement["config/provider-entity-statement.jwt"]
```

### Test Local Entity Statement Endpoint

Validates your local entity statement endpoint and tests all linked endpoints. Useful for verifying your federation endpoint implementation:

```bash
# Default (localhost:3000)
rake openid_federation:test_local_endpoint

# Custom base URL
rake openid_federation:test_local_endpoint[http://localhost:3000]

# Via environment variable
BASE_URL=http://localhost:3000 rake openid_federation:test_local_endpoint
```

This task:
- Fetches and validates the entity statement from `/.well-known/openid-federation`
- Shows key configuration status (single vs separate keys) with recommendations
- Tests all endpoints mentioned in the entity statement
- Displays validation warnings without blocking execution

See all tasks: `rake -T openid_federation`

### Cache Configuration and Key Rotation

Configure automatic key rotation:

```ruby
OmniauthOpenidFederation.configure do |config|
  config.cache_ttl = 3600  # Refresh provider keys every hour
  config.rotate_on_errors = true  # Auto-handle provider key rotation
end
```

### Security Instrumentation

Configure custom instrumentation for security events, MITM attack detection, and authentication mismatches:

```ruby
OmniauthOpenidFederation.configure do |config|
  # Configure with Sentry
  config.instrumentation = ->(event, data) do
    Sentry.capture_message(
      "OpenID Federation: #{event}",
      level: data[:severity] == :error ? :error : :warning,
      extra: data
    )
  end
end
```

**With Honeybadger**:
```ruby
OmniauthOpenidFederation.configure do |config|
  config.instrumentation = ->(event, data) do
    Honeybadger.notify("OpenID Federation: #{event}", context: data)
  end
end
```

**With custom logger**:
```ruby
OmniauthOpenidFederation.configure do |config|
  config.instrumentation = ->(event, data) do
    Rails.logger.warn("[Security] #{event}: #{data.inspect}")
  end
end
```

**Instrumented Events**:
- `csrf_detected` - CSRF attack detected (state mismatch in callback phase)
- `authenticity_error` - OmniAuth CSRF protection blocked request (Rails CSRF token validation failed in request phase)
- `signature_verification_failed` - JWT signature verification failed (possible MITM)
- `decryption_failed` - Token decryption failed (possible MITM or key mismatch)
- `token_validation_failed` - Token validation failed (possible tampering)
- `key_rotation_detected` - Key rotation detected (normal operation)
- `kid_not_found` - Key ID not found in JWKS (possible key rotation or MITM)
- `entity_statement_validation_failed` - Entity statement validation failed (possible MITM)
- `fingerprint_mismatch` - Entity statement fingerprint mismatch (possible MITM)
- `trust_chain_validation_failed` - Trust chain validation failed
- `unexpected_authentication_break` - Unexpected authentication failure (missing code, token exchange errors, unknown errors)
- `missing_required_claims` - Token missing required claims

**Note**: All blocking exceptions are automatically reported through instrumentation, including:
- OmniAuth middleware errors (like `AuthenticityTokenProtection` blocking requests)
- Strategy-level errors (CSRF detected, missing code, token exchange failures)
- Unknown error types (reported as `unexpected_authentication_break`)

**Security Note**: All sensitive data (tokens, keys, fingerprints) is automatically sanitized before being sent to your instrumentation callback.

**Key Rotation Types**:
- **Provider Keys** (from external providers): ✅ Automatic via Signed JWKS - library automatically detects and uses new provider keys
- **Client Keys** (your own keys): ⚠️ **Manual rotation required** - you must generate new RSA keys and update entity statement

**Client Key Rotation Process** (Manual Steps Required):
1. **Generate new RSA keys** (manual):
   ```bash
   bundle exec rake omniauth_openid_federation:prepare_client_keys[key_type=separate]
   ```
2. **Update entity statement file** (manual): Update `entity_statement_path` with new keys, or let the library regenerate it
3. **Library automatically uses new keys** (automatic): Library extracts JWKS from updated entity statement file on next cache refresh

**Note**: The library automatically generates JWKS from your RSA keys, but you must manually generate new RSA keys when rotating. The library then automatically uses the new keys from the updated entity statement file. See [Automatic Key Provisioning](#automatic-key-provisioning) for details.

### Publishing Federation Endpoint

Publish your entity statement at `/.well-known/openid-federation` using `auto_configure`.

The library supports two entity types:
- **openid_relying_party (RP)**: For clients/relying parties (PRIMARY USE CASE)
- **openid_provider (OP)**: For providers/servers (secondary use case)

#### Relying Party (RP) Configuration (Primary Use Case)

**First, generate your RSA keys** (if not already generated):

```bash
# Generate separate signing and encryption keys (RECOMMENDED for production)
bundle exec rake omniauth_openid_federation:prepare_client_keys[key_type=separate]

# Or generate single key for dev/testing (NOT RECOMMENDED for production)
bundle exec rake omniauth_openid_federation:prepare_client_keys[key_type=single]
```

This creates:
- `config/client-signing-private-key.pem` and `config/client-encryption-private-key.pem` (separate keys)
- OR `config/client-private-key.pem` (single key for dev/testing)

**Then configure the federation endpoint** - the library automatically generates JWKS from your keys:

```ruby
# config/initializers/omniauth_openid_federation.rb
# Production Setup (RECOMMENDED): Separate signing and encryption keys
# The library automatically generates JWKS from these keys
OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  issuer: "https://your-app.com",
  signing_key: OpenSSL::PKey::RSA.new(File.read("config/client-signing-private-key.pem")),
  encryption_key: OpenSSL::PKey::RSA.new(File.read("config/client-encryption-private-key.pem")),
  entity_statement_path: "config/client-entity-statement.jwt", # Cache for automatic key rotation
  metadata: {
    openid_relying_party: {
      redirect_uris: ["https://your-app.com/users/auth/openid_federation/callback"],
      client_registration_types: ["automatic"],
      application_type: "web",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "RS256",
      request_object_signing_alg: "RS256",
      id_token_encrypted_response_alg: "RSA-OAEP",
      id_token_encrypted_response_enc: "A128CBC-HS256"
    }
  },
  auto_provision_keys: true # Library automatically generates JWKS from provided keys
)
```

**Development/Testing** (NOT RECOMMENDED FOR PRODUCTION):
```ruby
OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  issuer: "https://your-app.com",
  private_key: private_key, # DEV/TESTING ONLY - single key for both signing and encryption
  entity_statement_path: "config/client-entity-statement.jwt",
  metadata: {
    openid_relying_party: { ... }
  },
  auto_provision_keys: true
)
```

#### OpenID Provider (OP) Configuration (Secondary Use Case)

**First, generate your RSA keys** (if not already generated):

```bash
# Generate separate signing and encryption keys (RECOMMENDED for production)
bundle exec rake omniauth_openid_federation:prepare_client_keys[key_type=separate,output_dir=config]

# Or generate single key for dev/testing (NOT RECOMMENDED for production)
bundle exec rake omniauth_openid_federation:prepare_client_keys[key_type=single,output_dir=config]
```

**Then configure the federation endpoint** - the library automatically generates JWKS from your keys:

```ruby
# For provider/server applications
# Production Setup (RECOMMENDED): Separate signing and encryption keys
# The library automatically generates JWKS from these keys
signing_key = OpenSSL::PKey::RSA.new(File.read("config/client-signing-private-key.pem"))
encryption_key = OpenSSL::PKey::RSA.new(File.read("config/client-encryption-private-key.pem"))

OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  issuer: "https://provider.example.com",
  signing_key: signing_key,
  encryption_key: encryption_key,
  entity_statement_path: "config/provider-entity-statement.jwt",
  metadata: {
    openid_provider: {
      issuer: "https://provider.example.com",
      authorization_endpoint: "https://provider.example.com/oauth2/authorize",
      token_endpoint: "https://provider.example.com/oauth2/token",
      userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
      jwks_uri: "https://provider.example.com/.well-known/jwks.json",
      signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
      # federation_fetch_endpoint is automatically added for OPs
    }
  },
  auto_provision_keys: true # Library automatically generates JWKS from provided keys
)
```

**Development/Testing** (NOT RECOMMENDED FOR PRODUCTION):
```ruby
# Single private key for both signing and encryption (DEV/TESTING ONLY)
OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  issuer: "https://provider.example.com",
  private_key: private_key, # DEV/TESTING ONLY - not recommended for production
  entity_statement_path: "config/provider-entity-statement.jwt",
  metadata: {
    openid_provider: {
      issuer: "https://provider.example.com",
      authorization_endpoint: "https://provider.example.com/oauth2/authorize",
      token_endpoint: "https://provider.example.com/oauth2/token",
      userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
      jwks_uri: "https://provider.example.com/.well-known/jwks.json",
      signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
    }
  },
  auto_provision_keys: true
)
```

```ruby
# config/routes.rb
# RECOMMENDED: Mount the Engine (Rails-idiomatic way)
mount OmniauthOpenidFederation::Engine => "/"

# ALTERNATIVE: Use mount_routes helper (for backward compatibility)
# OmniauthOpenidFederation::FederationEndpoint.mount_routes(self)
```

**What `auto_configure` does automatically**:
- Extracts JWKS from entity statement file or generates from provided keys
- Supports separate signing/encryption keys (RECOMMENDED) or single key (dev/testing)
- Auto-detects entity type and generates well-known endpoints
- Uses `entity_statement_path` as cache for key rotation

**Manual Configuration** (advanced, not recommended):

If you need manual control, use `configure` instead of `auto_configure`:

```ruby
OmniauthOpenidFederation::FederationEndpoint.configure do |config|
  config.issuer = "https://your-app.com"
  config.subject = "https://your-app.com"
  config.signing_key = signing_key  # RECOMMENDED: Separate signing key
  config.encryption_key = encryption_key  # RECOMMENDED: Separate encryption key
  config.jwks = jwks  # Must provide manually
  config.metadata = { ... }
end
```

### Automatic Key Provisioning

The `auto_configure` method automatically generates JWKS from your RSA keys (generate keys first using the rake task).

**Priority Order**:
1. Extracts JWKS from `entity_statement_path` if file exists (supports key rotation)
2. Generates JWKS from separate `signing_key` and `encryption_key` (RECOMMENDED)
3. Generates JWKS from single `private_key` (dev/testing only)

**Key Rotation** (Semi-Automatic):
1. **Manual**: Generate new RSA keys using `rake omniauth_openid_federation:prepare_client_keys`
2. **Manual**: Update entity statement file at `entity_statement_path` with new keys
3. **Automatic**: Library extracts and uses new keys from updated file on next cache refresh

## Configuration Options

### Required

- `client_options[:identifier]` - Client ID from provider
- `client_options[:redirect_uri]` - Callback URL
- `client_options[:private_key]` - RSA private key for signing
- **One of the following** (for provider entity statement):
  - `entity_statement_url` - Provider entity statement URL (recommended - library fetches and caches automatically)
  - `issuer` - Provider issuer URI (library builds entity statement URL from issuer + `/.well-known/openid-federation`)
  - `entity_statement_path` - Provider entity statement path (optional - for offline development)

### Optional

- `discovery` - Enable automatic endpoint discovery (default: `true`)
- `entity_statement_fingerprint` - Expected SHA-256 fingerprint for verification (recommended when using `entity_statement_url` or `issuer`)
- `entity_statement_path` - Path to provider entity statement (optional - for offline development, cached copy)
- `always_encrypt_request_object` - Always encrypt request objects if encryption keys are available (default: `false`, see [Request Object Security](#request-object-security-signing-vs-encryption) below)
- `client_entity_statement_url` - URL to client entity statement (for automatic registration)
- `client_entity_statement_path` - Path to client entity statement (fallback if URL not available)
- `client_registration_type` - `:explicit` (default) or `:automatic` (auto-detected if client_entity_statement_url/path provided)
- `client_entity_identifier` - Entity identifier for automatic registration
- `scope` - OAuth scopes (default: `[:openid]`)
- `response_type` - Response type (default: `"code"`)
- `client_auth_method` - Client authentication (default: `:jwt_bearer`)
- `client_signing_alg` - Signing algorithm (default: `:RS256`)
- `fetch_userinfo` - Whether to fetch userinfo endpoint (default: `true`)
- `acr_values` - Authentication Context Class Reference values (provider-specific)
- `key_source` - `:local` (default) or `:federation` (advanced)

### Global Configuration

Configure global settings via `OmniauthOpenidFederation.configure`:

```ruby
OmniauthOpenidFederation.configure do |config|
  # Cache configuration
  config.cache_ttl = 3600  # JWKS cache TTL in seconds
  config.rotate_on_errors = true  # Auto-rotate on key-related errors
  
  # Security instrumentation (Sentry, Honeybadger, etc.)
  config.instrumentation = ->(event, data) do
    Sentry.capture_message("OpenID Federation: #{event}", level: :warning, extra: data)
  end
  
  # HTTP configuration
  config.http_timeout = 10
  config.max_retries = 3
  config.verify_ssl = true
end
```

### Request Object Security (Signing vs Encryption)

**Per OpenID Federation 1.0 and RFC 9101:**
- **Signing (MANDATORY)**: Request objects **MUST be signed** using RS256 (always enforced, cannot be disabled)
- **Encryption (OPTIONAL)**: Request objects **MAY be encrypted** when provider requires it or when `always_encrypt_request_object: true`

**Encryption Behavior:**
- **Default** (`always_encrypt_request_object: false`): Only encrypts if provider metadata specifies `request_object_encryption_alg`
- **When `true`**: Encrypts even if provider doesn't require it (if encryption keys available)
- **Use case**: High-security deployments requiring defense-in-depth beyond minimum spec

**Note**: Signing provides authentication and integrity. Encryption adds confidentiality but is optional and adds overhead.

### Detailed Configuration Examples

#### Devise with Environment Variables (Recommended)

```ruby
# config/initializers/devise.rb
require "omniauth_openid_federation"

private_key = if ENV["OPENID_CLIENT_PRIVATE_KEY"]
  OpenSSL::PKey::RSA.new(Base64.decode64(ENV["OPENID_CLIENT_PRIVATE_KEY"]))
else
  OpenSSL::PKey::RSA.new(File.read("config/client-private-key.pem"))
end

config.omniauth :openid_federation,
  discovery: true,  # Auto-discovers endpoints from entity statement
  entity_statement_url: ENV["OPENID_ENTITY_STATEMENT_URL"],  # Always provide URL
  entity_statement_fingerprint: ENV["OPENID_ENTITY_STATEMENT_FINGERPRINT"],  # Fingerprint for verification
  entity_statement_path: "config/provider-entity-statement.jwt",  # Cached copy from URL (fetch via rake task)
  client_entity_statement_url: "#{ENV["APP_URL"]}/.well-known/openid-federation",  # For automatic registration
  client_options: {
    identifier: ENV["OPENID_CLIENT_ID"],
    redirect_uri: "#{ENV["APP_URL"]}/users/auth/openid_federation/callback",
    private_key: private_key
  }
  # All endpoints are auto-discovered - no manual configuration needed
```

#### OmniAuth with URL-based Entity Statement (Production)

```ruby
# config/initializers/omniauth.rb
require "omniauth_openid_federation"

entity_statement_url = "https://provider.example.com/.well-known/openid-federation"
entity_statement_fingerprint = "expected-fingerprint-hash"

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :openid_federation,
    discovery: true,
    entity_statement_url: entity_statement_url,  # Always provide URL
    entity_statement_fingerprint: entity_statement_fingerprint,  # Fingerprint for verification
    entity_statement_path: "config/provider-entity-statement.jwt",  # Cached copy from URL
    client_options: {
      identifier: ENV["OPENID_CLIENT_ID"],
      redirect_uri: "https://your-app.com/auth/openid_federation/callback",
      private_key: OpenSSL::PKey::RSA.new(File.read("config/client-private-key.pem"))
    }
end
```

**Key Points**:
- **Always provide `entity_statement_url`** - this is the source of truth
- `entity_statement_fingerprint` is used for verification when fetching
- `entity_statement_path` points to the cached copy fetched from the URL
- All endpoints are automatically discovered - no manual endpoint configuration

## API Reference

### `OmniauthOpenidFederation::Jws`

Builds and signs JWT request objects:

```ruby
jws = OmniauthOpenidFederation::Jws.new(
  client_id: "client-id",
  redirect_uri: "https://example.com/callback",
  scope: "openid",
  issuer: "https://provider.example.com",
  audience: "https://provider.example.com",
  private_key: private_key
)
signed_jwt = jws.sign
```

### `OmniauthOpenidFederation::Federation::EntityStatement`

Fetches and validates entity statements:

```ruby
statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
  "https://provider.example.com/.well-known/openid-federation",
  fingerprint: "expected-fingerprint"
)
metadata = statement.parse
```

### `OmniauthOpenidFederation::Federation::SignedJWKS`

Fetches and validates signed JWKS:

```ruby
signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
  signed_jwks_uri,
  entity_jwks
)
```

See inline code documentation for complete API reference.

## Troubleshooting

**"Private key is required"**
- Generate keys: `rake openid_federation:prepare_client_keys`
- Verify key path and format (PEM)

**"Audience is required"**
- Provide `entity_statement_url` and `entity_statement_path` (auto-resolves audience from entity statement)

**"Entity statement fingerprint mismatch"**
- Verify `entity_statement_fingerprint` with provider
- Fetch fresh entity statement from URL: `rake openid_federation:fetch_entity_statement[entity_statement_url, entity_statement_fingerprint, entity_statement_path]`
- Always use the provider URL as the source of truth

**"JWT signature verification failed"**
- Provider may have rotated keys (auto-handled with `rotate_on_errors: true`)
- Clear cache: `Rails.cache.delete_matched("openid_federation_jwks_*")`

**"Attack prevented by OmniAuth::AuthenticityTokenProtection" or "OmniAuth::AuthenticityError"**
- **Request phase (initiating OAuth)**: Ensure forms include Rails CSRF tokens using `button_to` or `form_with` helpers
- **Callback phase (external provider redirect)**: Ensure CSRF protection is configured correctly (see [Step 7: Configure CSRF Protection](#step-7-configure-csrf-protection))
- Verify `OmniAuth.config.request_validation_phase` is configured to skip CSRF validation for callback paths
- Ensure `skip_before_action :verify_authenticity_token` is present in the callback controller for callback actions
- Check that OAuth state parameter validation is working (handled automatically by the strategy)

## Security

See [SECURITY.md](SECURITY.md) for detailed security features, protections, and vulnerability reporting.

## Requirements

- Ruby >= 3.0
- Rails >= 6.0 (optional)
- `omniauth-oauth2` ~> 1.8
- `openid_connect` ~> 2.3
- `jwe` ~> 1.1
- `jwt` ~> 3.1
- `http` ~> 5.3

## Example Files

See `examples/` directory for complete configuration examples:
- `examples/config/initializers/devise.rb.example`
- `examples/app/controllers/users/omniauth_callbacks_controller.rb.example`
- `examples/app/models/user.rb.example`

## Development

Run release.rb script to prepare code for publishing, it has all the required checks and tests.

```bash
usr/bin/release.rb
```

### Development: Using from Local Repository

When developing the gem or testing changes in your application, you can point your Gemfile to a local path:

```ruby
# In your application's Gemfile
gem "omniauth_openid_federation", path: "../omniauth_openid_federation.rb"
```

Then run:

```bash
bundle install
```

**Note:** When using `path:` in your Gemfile, Bundler will use the local gem directly. Changes you make to the gem code will be immediately available in your application without needing to rebuild or reinstall the gem. This is ideal for development and testing.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/amkisko/omniauth_openid_federation.rb

Contribution policy:
- New features are not necessarily added to the gem
- Pull request should have test coverage for affected parts
- Pull request should have changelog entry

Review policy:
- It might take up to 2 calendar weeks to review and merge critical fixes
- It might take up to 6 calendar months to review and merge pull request
- It might take up to 1 calendar year to review an issue


## Publishing

```sh
rm omniauth_openid_federation-*.gem
gem build omniauth_openid_federation.gemspec
gem push omniauth_openid_federation-*.gem
```

## References

- [OpenID Federation 1.0 Specification](https://openid.net/specs/openid-federation-1_0.html)
- [RFC 9101 - OAuth 2.0 Authorization Request](https://datatracker.ietf.org/doc/html/rfc9101)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
