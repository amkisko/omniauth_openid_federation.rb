# Exception hierarchy for omniauth_openid_federation
# Provides structured error handling with specific exception types
module OmniauthOpenidFederation
  # Base error class for all omniauth_openid_federation errors
  class Error < StandardError; end

  # Configuration errors (missing required options, invalid values, etc.)
  class ConfigurationError < Error; end

  # Security-related errors (signature failures, decryption errors, etc.)
  class SecurityError < Error; end

  # Network errors (HTTP failures, timeouts, etc.)
  class NetworkError < Error; end

  # Validation errors (invalid tokens, malformed data, etc.)
  class ValidationError < Error; end

  # Decryption errors (ID token decryption failures)
  class DecryptionError < SecurityError; end

  # Encryption errors (request object encryption failures)
  class EncryptionError < SecurityError; end

  # Signature errors (JWT signature verification failures)
  class SignatureError < SecurityError; end

  # Fetch errors (failed to fetch entity statements, JWKS, etc.)
  class FetchError < NetworkError; end

  # Key-related errors (indicates possible key rotation)
  # Used for cache rotation logic when key-related HTTP errors occur
  class KeyRelatedError < FetchError
    def key_related_error?
      true
    end
  end

  # Key-related validation errors (signature failures, decode errors)
  class KeyRelatedValidationError < ValidationError
    def key_related_error?
      true
    end
  end

  # Compatibility aliases for federation classes
  module Federation
    # Alias for backward compatibility with tests
    FetchError = OmniauthOpenidFederation::FetchError
    ValidationError = OmniauthOpenidFederation::ValidationError
  end
end
