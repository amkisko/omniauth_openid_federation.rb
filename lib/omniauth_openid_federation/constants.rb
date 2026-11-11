# Constants for omniauth_openid_federation
module OmniauthOpenidFederation
  module Constants
    # HTTP status codes that indicate key-related errors (possible key rotation)
    KEY_ROTATION_HTTP_CODES = [401, 403, 404].freeze

    # Request object expiration time in seconds (10 minutes)
    REQUEST_OBJECT_EXPIRATION_SECONDS = 600

    # Maximum retry delay in seconds (prevents unbounded retry delays)
    MAX_RETRY_DELAY_SECONDS = 60

    # Maximum string length for request parameters (8KB)
    # Prevents DoS attacks while allowing legitimate use cases (e.g., encrypted JWT authorization codes)
    # Use Configuration.config.max_string_length for runtime configuration instead of patching this constant
    MAX_STRING_LENGTH = 8192

    # Minimum RSA modulus size for OIDC signing and encryption keys (common federation profiles)
    MIN_RSA_KEY_BITS = 2048

    # Maximum HTTP response body size for federation/JWKS fetches (1 MiB)
    MAX_HTTP_RESPONSE_BODY_BYTES = 1_048_576

    # OpenID Federation 1.0 entity statement / entity configuration responses (section 8.1, section 9.2)
    CONTENT_TYPE_ENTITY_STATEMENT_JWT = "application/entity-statement+jwt"

    # Signed JWKS and generic JWT responses
    CONTENT_TYPE_JWT = "application/jwt"

    CONTENT_TYPE_JSON = "application/json"
  end
end
