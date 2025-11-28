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
  end
end
