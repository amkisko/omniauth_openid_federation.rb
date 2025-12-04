# omniauth_openid_federation

[![Gem Version](https://badge.fury.io/rb/omniauth_openid_federation.svg?v=1.1.0)](https://badge.fury.io/rb/omniauth_openid_federation) [![Test Status](https://github.com/amkisko/omniauth_openid_federation.rb/actions/workflows/test.yml/badge.svg)](https://github.com/amkisko/omniauth_openid_federation.rb/actions/workflows/test.yml) [![codecov](https://codecov.io/gh/amkisko/omniauth_openid_federation.rb/graph/badge.svg?token=CX3O9M1GIT)](https://codecov.io/gh/amkisko/omniauth_openid_federation.rb) [![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=amkisko_omniauth_openid_federation.rb&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=amkisko_omniauth_openid_federation.rb)

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

- ✅ **Signed Request Objects (RFC 9101)** - RS256 signing of authorization requests
- ✅ **Optional Request Object Encryption** - RSA-OAEP encryption when provider requires it
- ✅ **ID Token Encryption/Decryption** - RSA-OAEP encryption and A128CBC-HS256 decryption
- ✅ **OpenID Federation 1.0** - Full entity statement support and federation metadata
- ✅ **Federation Endpoint** - Publish entity statements at `/.well-known/openid-federation`
- ✅ **Automatic Key Provisioning** - Automatic extraction/generation of signing and encryption keys
- ✅ **Separate Key Support** - Production-ready support for separate signing and encryption keys
- ✅ **Client Assertion (private_key_jwt)** - Secure client authentication
- ✅ **Security Hardened** - OWASP compliant, input validation, rate limiting

## Quick Start

### Step 1: Get Provider Information

Your provider will provide:
- **Entity statement URL**: `https://provider.example.com/.well-known/openid-federation`
- **Expected fingerprint hash**: For verification

Fetch and cache the entity statement:

```bash
rake openid_federation:fetch_entity_statement[
  "https://provider.example.com/.well-known/openid-federation",
  "expected-fingerprint-hash",
  "config/provider-entity-statement.jwt"
]
```

### Step 2: Generate Client Keys

```bash
rake openid_federation:prepare_client_keys
```

This generates:
- Private key: `config/client-private-key.pem` (keep secure, never commit)
- Public JWKS: `config/client-jwks.json` (send to provider for explicit registration)

**Security Warning**: 
- **NEVER commit production private keys to your repository**
- For production: Use environment variables (`OPENID_CLIENT_PRIVATE_KEY_BASE64`) or secure key management systems
- For development: Add private key files to `.gitignore`:
```
.federation*
*.pem
```

### Step 3: Register Client

**Explicit Registration** (default):
1. Send `config/client-jwks.json` to your provider
2. Receive Client ID from provider

**Automatic Registration** (if provider supports it):
- No pre-registration needed
- Set `client_entity_statement_url` to `https://your-app.com/.well-known/openid-federation`

### Step 4: Configure OmniAuth Strategy

```ruby
# config/initializers/devise.rb
require "omniauth_openid_federation"

# Global settings (optional)
OmniauthOpenidFederation.configure do |config|
  config.cache_ttl = 24 * 60 * 60
  config.rotate_on_errors = true
  config.http_timeout = 10
  config.max_retries = 3
end

if ENV["OPENID_ENABLED"] == "true"
  # Load private key from environment variable (recommended for production)
  private_key = if ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]
    OpenSSL::PKey::RSA.new(Base64.decode64(ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]))
  elsif ENV["OPENID_CLIENT_PRIVATE_KEY_PATH"]
    OpenSSL::PKey::RSA.new(File.read(Rails.root.join(ENV["OPENID_CLIENT_PRIVATE_KEY_PATH"])))
  else
    OpenSSL::PKey::RSA.new(File.read(Rails.root.join("config", "client-private-key.pem")))
  end

  entity_statement_path = ENV["OPENID_ENTITY_STATEMENT_PATH"] || 
    Rails.root.join("config", ".federation-entity-statement.jwt").to_s

  # Configure CSRF protection
  if defined?(OmniAuth)
    OmniAuth.config.allowed_request_methods = [:post]
    OmniAuth.config.request_validation_phase = lambda do |env|
      request = Rack::Request.new(env)
      return true if request.path.end_with?("/callback")
      
      session = env["rack.session"] || {}
      token = request.params["authenticity_token"] || request.get_header("X-CSRF-Token")
      expected_token = session[:_csrf_token] || session["_csrf_token"]
      
      if token.present? && expected_token.present?
        ActiveSupport::SecurityUtils.secure_compare(token.to_s, expected_token.to_s)
      else
        false
      end
    end
  end

  Devise.setup do |config|
    config.omniauth :openid_federation,
      strategy_class: OmniAuth::Strategies::OpenIDFederation,
      name: :openid_federation,
      scope: [:openid],
      response_type: "code",
      discovery: true,
      client_auth_method: :jwt_bearer,
      client_signing_alg: :RS256,
      entity_statement_path: entity_statement_path,
      always_encrypt_request_object: true,
      client_options: {
        identifier: ENV["OPENID_CLIENT_ID"],
        redirect_uri: ENV["OPENID_REDIRECT_URI"] || "#{ENV["APP_URL"]}/users/auth/openid_federation/callback",
        private_key: private_key
      }
  end
end
```

### Step 5: Configure Federation Endpoint (For Automatic Registration)

```ruby
# config/initializers/omniauth_openid_federation.rb
if ENV["OPENID_ENABLED"] == "true"
  app_url = ENV["APP_URL"] || "https://your-app.example.com"
  
  private_key = if ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]
    OpenSSL::PKey::RSA.new(Base64.decode64(ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]))
  elsif ENV["OPENID_CLIENT_PRIVATE_KEY_PATH"]
    OpenSSL::PKey::RSA.new(File.read(Rails.root.join(ENV["OPENID_CLIENT_PRIVATE_KEY_PATH"])))
  else
    OpenSSL::PKey::RSA.new(File.read(Rails.root.join("config", "client-private-key.pem")))
  end

  client_entity_statement_path = ENV["OPENID_CLIENT_ENTITY_STATEMENT_PATH"] || 
    Rails.root.join("config", "client-entity-statement.jwt").to_s

  OmniauthOpenidFederation::FederationEndpoint.auto_configure(
    issuer: app_url,
    private_key: private_key,
    entity_statement_path: client_entity_statement_path,
    metadata: {
      openid_relying_party: {
        redirect_uris: [
          ENV["OPENID_REDIRECT_URI"] || "#{app_url}/users/auth/openid_federation/callback"
        ],
        client_registration_types: ["automatic"],
        application_type: "web",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "RS256",
        request_object_signing_alg: "RS256",
        id_token_encrypted_response_alg: "RSA-OAEP",
        id_token_encrypted_response_enc: "A128CBC-HS256",
        organization_name: ENV["OPENID_ORGANIZATION_NAME"]
      }
    }
  )
end
```

### Step 6: Add Routes

```ruby
# config/routes.rb
if ENV["OPENID_ENABLED"] == "true"
  mount OmniauthOpenidFederation::Engine => "/"
end

Rails.application.routes.draw do
  devise_for :users, controllers: {
    omniauth_callbacks: "users/omniauth_callbacks"
  }
end
```

### Step 7: Create Callback Controller

```ruby
# app/controllers/users/omniauth_callbacks_controller.rb
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
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

### Step 8: Create User Model Method

```ruby
# app/models/user.rb
class User < ApplicationRecord
  def self.find_or_create_from_omniauth(auth)
    user = find_by(provider: auth.provider, uid: auth.uid)
    
    if user
      user.update(
        email: auth.info.email,
        name: auth.info.name
      )
    else
      user = create(
        provider: auth.provider,
        uid: auth.uid,
        email: auth.info.email,
        name: auth.info.name
      )
    end
    
    user
  end
end
```

## Passing Custom Parameters

### Using `request_object_params` (Allow-List)

Pass custom parameters via `request_object_params` allow-list:

```ruby
config.omniauth :openid_federation,
  request_object_params: ["custom_param", "another_param"],
  # ... other options
```

Parameters in the allow-list are automatically included in the JWT request object if present in the HTTP request.

### Using `prepare_request_object_params` (Proc)

Use `prepare_request_object_params` proc to modify parameters before they're added to the signed request object. This is useful for:
- Combining config values with form values (e.g., base `acr_values` + provider-specific)
- Adding config-based parameters (e.g., `ftn_spname` from config)
- Transforming or validating parameters

```ruby
config.omniauth :openid_federation,
  request_object_params: [:ftn_spname], # Allow-list for custom params
  prepare_request_object_params: proc do |params|
    # Combine config acr_values with form acr_values
    form_acr_values = params["acr_values"]&.to_s&.strip
    config_acr_values = ENV["OPENID_ACR_VALUES"].to_s.strip
    
    if config_acr_values.present? && form_acr_values.present?
      params["acr_values"] = "#{config_acr_values} #{form_acr_values}".strip
    elsif config_acr_values.present?
      params["acr_values"] = config_acr_values
    end
    
    # Add custom parameter from config
    params["ftn_spname"] = ENV["OPENID_FTN_SPNAME"] if ENV["OPENID_FTN_SPNAME"].present?
    
    params
  end,
  # ... other options
```

**Form Example** (pass clean values, proc handles combining):

```ruby
# In your form - pass only provider-specific value
<%= button_to "Login", user_openid_federation_omniauth_authorize_path, 
    method: :post,
    params: { acr_values: "provider_specific_level" } %>
```

The proc will combine this with config values before adding to the signed JWT.

## Rake Tasks

### Prepare Client Keys

```bash
rake openid_federation:prepare_client_keys
```

### Fetch Entity Statement

```bash
rake openid_federation:fetch_entity_statement[
  "https://provider.example.com/.well-known/openid-federation",
  "expected-fingerprint-hash",
  "config/provider-entity-statement.jwt"
]
```

### Test Authentication Flow

```bash
rake openid_federation:test_authentication_flow[
  "https://provider.example.com/login",
  "https://your-app.com",
  "urn:mace:incommon:iap:silver"
]
```

## Configuration Options

### Required

- `client_options.identifier` - Client ID from provider
- `client_options.redirect_uri` - Callback URL
- `client_options.private_key` - RSA private key for signing
- `entity_statement_path` - Path to cached entity statement file

### Optional

- `entity_statement_url` - URL to fetch entity statement (auto-fetches if provided)
- `entity_statement_fingerprint` - Fingerprint for verification
- `client_entity_statement_url` - Client entity statement URL (for automatic registration)
- `client_entity_statement_path` - Client entity statement path (cached copy)
- `always_encrypt_request_object` - Force encryption of request objects (default: false)
- `request_object_params` - Array of parameter names to include in request object (allow-list)
- `prepare_request_object_params` - Proc to modify params before adding to signed request object: `proc { |params| modified_params }`
- `discovery` - Enable automatic endpoint discovery (default: true)

## Security

- All user input is validated and sanitized
- Configuration values are trusted (not validated)
- Signed request objects are required (RFC 9101)
- CSRF protection via Rails tokens (request phase) and OAuth state (callback phase)
- Private keys should never be committed to version control

## Troubleshooting

**"Missing authorization code"**: Check that redirect_uri matches provider configuration exactly.

**"Failed to exchange authorization code"**: Verify private key is correct and client_id matches provider.

**"Entity statement not found"**: Ensure entity statement is fetched and cached locally, or provide `entity_statement_url`.

## Requirements

- Ruby >= 3.0
- Rails >= 6.1 (or compatible Rack application)
- OpenSSL (for RSA key operations)

## Example Files

See `examples/` directory for complete configuration examples:
- `examples/config/initializers/devise.rb.example`
- `examples/config/initializers/omniauth_openid_federation.rb.example`
- `examples/config/open_id_connect_config.rb.example`

## Development

```bash
git clone https://github.com/amkisko/omniauth_openid_federation.rb.git
cd omniauth_openid_federation.rb
bundle install
bin/rspec
```

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## References

### Specifications

- [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
- [RFC 9101: OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9101.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Related Gems

- [omniauth](https://github.com/omniauth/omniauth) - Authentication framework
- [devise](https://github.com/heartcombo/devise) - Rails authentication solution
- [jwt](https://github.com/jwt/ruby-jwt) - JSON Web Token implementation
- [jwe](https://github.com/nov/jwe) - JSON Web Encryption
- [openid_connect](https://github.com/nov/openid_connect) - OpenID Connect client
- [http](https://github.com/httprb/http) - HTTP client
- [anyway_config](https://github.com/palkan/anyway_config) - Configuration management
- [action_reporter](https://github.com/basecamp/action_reporter) - Error reporting

## License

MIT License. See [LICENSE.md](LICENSE.md) for details.
