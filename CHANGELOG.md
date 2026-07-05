# CHANGELOG

## Unreleased

## 2.0.0 (2026-07-05)

- BREAKING: Replace `openid_connect` and `json-jwt` with `OmniauthOpenidFederation::OidcClient`, `AccessToken`, and `IdToken` built on `oauth2` and `jwt`
- BREAKING: Drop explicit `rack` runtime dependency; load Rack federation endpoints via `require "omniauth_openid_federation/rack"`
- BREAKING: Validate ID token `iss`, `aud`, and session `nonce` in `callback_phase`
- BREAKING: Fail closed on trust chain resolution errors instead of returning empty metadata
- BREAKING: Reject `alg: none` in access token JWT handling
- BREAKING: Remove broad JWKS decode retry on non-signature errors
- BREAKING: Reject unknown `crit` claims in entity statement validation
- BREAKING: Enforce minimum RSA key size (2048 bits) in `Validators.validate_private_key!`
- Use `jwe` gem for JWE encrypt/decrypt instead of `json-jwt`
- Refactor `OmniAuth::Strategies::OpenIDFederation` into concern modules under `lib/omniauth_openid_federation/strategy/`
- Add `OmniauthOpenidFederation::SecureCompare` for constant-time string comparison in the strategy
- Add `OmniauthOpenidFederation::JwtResponseDecoder` for encrypted/signed JWT userinfo and resource responses
- Add behavioral contract specs for token exchange, userinfo, and JWE parity with former `openid_connect` flow
- Add Telia Tunnistus PP entity statement fixture and contract spec (A128GCM and A128CBC-HS256)
- Add provider-agnostic strategy options: `default_request_object_claims`, `required_request_object_claims`, `allowed_acr_values`, `require_entity_statement_fingerprint`
- Use `Jwe.encrypted?` for JWE detection in `AccessToken#resource_request` and `TasksHelper`
- Deduplicate entity statement loading in `access_token.rb` via `load_entity_statement_content`
- Verify subordinate entity statement signatures in trust chain resolution
- Wire `verify_ssl` into `HttpClient` SSL options
- Use `CacheAdapter` in `RateLimiter` instead of `Rails.cache` directly
- Use issuer-scoped cache keys for federation JWKS and signed JWKS endpoints
- Fix OAuth callback failures in `callback_phase` to return the Rack response from `fail!` instead of `nil`; avoids `Rack::ETag` `NoMethodError` and HTTP 500 on auth failure
- Fix flaky `test_local_endpoint` spec when `SSL_CERT_FILE` is set in the environment
- Replace internal `decode_id_token` stubs in strategy specs with JWKS-backed setup

## 1.3.2 (2025-12-09)

- Added `TimeHelpers` module for compatibility with non-Rails environments
- Replaced `Time.zone` usage with `TimeHelpers` to work with or without ActiveSupport

## 1.3.1 (2025-12-09)

- Enhanced SSL configuration for HTTPS requests in tasks_helper.rb
- Updated federation controller to use ApplicationController
- Updated routes to have semaphore if it is already loaded
- Updated gemfiles and workflows for Rails 8 compatibility
- Improved time handling in integration and mock server classes using Time.zone.now

## 1.3.0 (2025-11-28)

- Added `prepare_request_object_params` proc option to customize request parameters before signing
- Enhanced security validation for all user-provided parameters
- Improved `acr_values` handling per OpenID Connect Core 1.0 specification

## 1.2.2 (2025-11-27)

- Fix gemfile to include app and config directories

## 1.2.1 (2025-11-27)

- Clean up Railtie loading patches to fully rely on Zeitwerk and autoloading

## 1.2.0 (2025-11-27)

- Created `OmniauthOpenidFederation::Engine` class inheriting from `Rails::Engine`
- Engine provides controllers via standard Rails autoloading mechanisms
- Routes are now defined in Engine's `config/routes.rb` file
- Routes must now be mounted using `mount OmniauthOpenidFederation::Engine => "/"` in `config/routes.rb`
- `FederationEndpoint.mount_routes` is still available for backward compatibility

## 1.1.0 (2025-11-26)

- Enhanced instrumentation: All blocking exceptions automatically reported through instrumentation system, including OmniAuth middleware errors (like AuthenticityTokenProtection)
- CSRF protection instrumentation: New authenticity_error event type for reporting OmniAuth CSRF failures
- Comprehensive error reporting: Override fail! method in strategy to catch and instrument all authentication failures
- CSRF protection documentation: Added comprehensive Step 7 in README explaining CSRF protection configuration for both request and callback phases
- CSRF configuration examples: Added complete examples in examples/config/initializers/devise.rb.example and examples/app/controllers/users/omniauth_callbacks_controller.rb.example
- Deprecation warnings: Added runtime deprecation warnings for json_jwt method and ftn_spname option to guide users to recommended alternatives
- Code cleanup: Removed deprecated load_signing_key method (unused, returned nil)
- Updated deprecation notices: Fixed deprecation notices to reference correct replacement methods (request_object_params instead of non-existent provider_extension_params)
- Renamed option: `allow_authorize_params` → `request_object_params` for clarity (uses RFC 9101 terminology, clearly indicates params go into JWT request object)

## 1.0.0 (2025-11-26)

- Initial public release, production-ready
- Full OpenID Federation 1.0 support with automatic entity statement validation and trust chain resolution
- Secure authentication with automatic signing of authorization requests
- ID token encryption and decryption support for enhanced security
- Secure client authentication without shared secrets
- Automatic provider key rotation handling for seamless key updates
- Built-in security features: rate limiting, path traversal protection, and error sanitization
- Production-ready with thread-safe configuration and intelligent retry logic
- Works with any OpenID Federation provider, supporting custom extension parameters
- Framework-agnostic: compatible with Rails, Sinatra, Rack, and other Rack-compatible frameworks
- Comprehensive management tools for entity statements and key management
- Enhanced developer experience with type signatures for better IDE support
