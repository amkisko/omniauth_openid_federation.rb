# CHANGELOG

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
- CSRF protection instrumentation: New authenticity_error event type for reporting OmniAuth CSRF protection failures
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
