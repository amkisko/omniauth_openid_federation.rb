require "jwt"
require "jwe"
require "securerandom"
require "base64"
require_relative "string_helpers"
require_relative "logger"
require_relative "errors"
require_relative "validators"
require_relative "key_extractor"

# JWT Request Object builder for signed authorization requests
# @see https://datatracker.ietf.org/doc/html/rfc9101 RFC 9101 - OAuth 2.0 Authorization Request
# @see https://openid.net/specs/openid-federation-1_0.html#section-12.1.1.1.1 Section 12.1.1.1.1: Authorization Request with a Trust Chain
#
# Implements signed request objects as required by RFC 9101 for secure authorization requests.
# All authorization parameters are included in a JWT signed with RS256 using the client's signing key.
#
# Required claims per RFC 9101:
# - iss: Client identifier
# - aud: Provider issuer or configured audience (for OpenID Federation, typically provider issuer)
# - client_id: Client identifier
# - redirect_uri: Callback URI
# - response_type: Authorization response type (typically "code")
# - scope: Requested scopes (typically "openid")
# - state: CSRF protection token
# - nonce: Replay protection token
# - exp: Expiration time (10 minutes)
# - jti: JWT ID for replay prevention
module OmniauthOpenidFederation
  # JWT Request Object builder for signed authorization requests
  #
  # @example Create and sign a request object with local private key
  #   jws = Jws.new(
  #     client_id: "client-id",
  #     redirect_uri: "https://example.com/callback",
  #     scope: "openid",
  #     issuer: "https://provider.example.com",
  #     audience: "https://provider.example.com",
  #     private_key: private_key,
  #     key_source: :local
  #   )
  #   signed_jwt = jws.sign
  #
  # @example Create and sign a request object with federation/JWKS
  #   jws = Jws.new(
  #     client_id: "client-id",
  #     redirect_uri: "https://example.com/callback",
  #     scope: "openid",
  #     issuer: "https://provider.example.com",
  #     audience: "https://provider.example.com",
  #     private_key: private_key, # Fallback if JWKS not available
  #     jwks: jwks_hash,
  #     entity_statement_path: "config/provider-entity-statement.jwt",
  #     key_source: :federation
  #   )
  #   signed_jwt = jws.sign
  class Jws
    # Request object expiration constants
    REQUEST_OBJECT_EXPIRATION_SECONDS = 600 # 10 minutes in seconds
    REQUEST_OBJECT_EXPIRATION_MINUTES = 10

    # State generation constants
    STATE_BYTES = 16 # Number of hex bytes for state parameter

    attr_accessor :private_key, :state, :nonce
    # Provider-specific extension parameters (outside JWT)
    # Some providers may require additional parameters that are not part of the JWT
    # @deprecated Use provider_extension_params hash instead
    attr_accessor :ftn_spname

    # Initialize JWT request object builder
    #
    # @param client_id [String] OAuth client identifier
    # @param redirect_uri [String] OAuth redirect URI
    # @param scope [String] OAuth scopes (default: "openid")
    # @param issuer [String, nil] Provider issuer URI
    # @param audience [String, nil] JWT audience (typically provider issuer)
    # @param state [String, nil] CSRF protection state (auto-generated if nil)
    # @param nonce [String, nil] Replay protection nonce
    # @param response_type [String] OAuth response type (default: "code")
    # @param response_mode [String, nil] OAuth response mode
    # @param login_hint [String, nil] Login hint for provider
    # @param ui_locales [String, nil] UI locale preferences
    # @param claims_locales [String, nil] Claims locale preferences
    # @param prompt [String, nil] OAuth prompt parameter
    # @param hd [String, nil] Hosted domain parameter
    # @param acr_values [String, nil] Authentication context class reference values
    # @param extra_params [Hash] Additional claims to include in JWT
    # @param private_key [OpenSSL::PKey::RSA, String, nil] Private key for signing (fallback if JWKS not provided)
    # @param jwks [Hash, Array, nil] JWKS hash or array for extracting signing key
    # @param entity_statement_path [String, nil] Path to entity statement file for key extraction (replaces metadata_path)
    # @param key_source [Symbol] Key source: :local (use local static private_key) or :federation (use federation/JWKS)
    # @param client_entity_statement [String, nil] Client's entity statement JWT string (for automatic registration)
    def initialize(
      client_id:,
      redirect_uri:,
      scope: "openid",
      issuer: nil,
      audience: nil,
      state: nil,
      nonce: nil,
      response_type: "code",
      response_mode: nil,
      login_hint: nil,
      ui_locales: nil,
      claims_locales: nil,
      prompt: nil,
      hd: nil,
      acr_values: nil,
      extra_params: {},
      private_key: nil,
      jwks: nil,
      entity_statement_path: nil,
      key_source: :local,
      client_entity_statement: nil
    )
      @client_id = client_id
      @redirect_uri = redirect_uri
      @scope = scope
      @issuer = issuer
      @audience = audience
      @state = state || SecureRandom.hex(STATE_BYTES)
      @nonce = nonce
      @response_type = response_type
      @response_mode = response_mode
      @login_hint = login_hint
      @ui_locales = ui_locales
      @claims_locales = claims_locales
      @prompt = prompt
      @hd = hd
      @acr_values = acr_values
      @extra_params = extra_params
      @jwks = jwks
      @entity_statement_path = entity_statement_path
      @key_source = key_source
      @client_entity_statement = client_entity_statement

      # Extract signing key based on key_source configuration
      # :local - Use local static private_key directly (for current setup)
      # :federation - Use federation/JWKS from entity statement first, fallback to private_key
      # According to OpenID Federation spec: supports separate signing/encryption keys
      if @key_source == :federation
        # Try federation/JWKS from entity statement first, then fallback to local private_key
        metadata = load_metadata_from_entity_statement if @entity_statement_path
        @private_key = KeyExtractor.extract_signing_key(
          jwks: @jwks,
          metadata: metadata,
          private_key: private_key
        ) || private_key
      else
        # :local - Use local private_key directly, ignore JWKS/metadata
        @private_key = private_key
      end
    end

    # Add a custom claim to the JWT
    #
    # @param key [Symbol, String] Claim key
    # @param value [Object] Claim value
    def add_claim(key, value)
      @extra_params[key] = value
    end

    # Sign the request object JWT
    #
    # Required for secure authorization requests per RFC 9101.
    # All authentication requests MUST use signed request objects.
    # This method enforces this requirement - unsigned requests are NOT allowed.
    #
    # According to OpenID Connect Core and RFC 9101, request objects can be:
    # - Signed only (default)
    # - Signed and encrypted (if provider metadata specifies encryption)
    #
    # @param provider_metadata [Hash, nil] Provider metadata from entity statement (optional)
    # @return [String] The signed (and optionally encrypted) JWT request object
    # @raise [SecurityError] If private key is missing or signing fails
    def sign(provider_metadata: nil, always_encrypt: false)
      # ENFORCE: Private key is MANDATORY - no bypass possible
      Validators.validate_private_key!(@private_key)

      begin
        signed_jwt = build_jwt
        unless OmniauthOpenidFederation::StringHelpers.present?(signed_jwt)
          error_msg = "Failed to sign JWT request object - signed request objects are MANDATORY"
          OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
          raise SecurityError, error_msg
        end

        # Extract kid from header for logging
        header_part = signed_jwt.split(".").first
        header = JSON.parse(Base64.urlsafe_decode64(header_part))
        kid = header["kid"]
        OmniauthOpenidFederation::Logger.debug("[Jws] Successfully signed request object with kid: #{kid}")

        # Encrypt if required (provider metadata specifies encryption OR always_encrypt option is true)
        # According to RFC 9101 and OpenID Connect Core, if provider specifies
        # request_object_encryption_alg, the client SHOULD encrypt request objects
        if should_encrypt_request_object?(provider_metadata, always_encrypt: always_encrypt)
          encrypted_jwt = encrypt_request_object(signed_jwt, provider_metadata)
          OmniauthOpenidFederation::Logger.debug("[Jws] Successfully encrypted request object")
          encrypted_jwt
        else
          signed_jwt
        end
      rescue => e
        error_msg = "Failed to sign JWT request object (required for secure authorization): #{e.class} - #{e.message}"
        OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
        raise SignatureError, error_msg, e.backtrace
      end
    end

    private

    def build_jwt
      claim = {
        iss: @client_id,
        aud: client_audience || @issuer,
        client_id: @client_id,
        redirect_uri: @redirect_uri,
        response_type: @response_type,
        scope: @scope,
        state: state,
        exp: (Time.now + (defined?(ActiveSupport) ? REQUEST_OBJECT_EXPIRATION_MINUTES.minutes : REQUEST_OBJECT_EXPIRATION_SECONDS)).to_i,
        jti: SecureRandom.uuid # JWT ID to prevent replay
      }

      # Add optional claims
      claim[:nonce] = nonce if OmniauthOpenidFederation::StringHelpers.present?(nonce)
      claim[:response_mode] = @response_mode if OmniauthOpenidFederation::StringHelpers.present?(@response_mode)
      claim[:login_hint] = @login_hint if OmniauthOpenidFederation::StringHelpers.present?(@login_hint)
      claim[:ui_locales] = @ui_locales if OmniauthOpenidFederation::StringHelpers.present?(@ui_locales)
      claim[:claims_locales] = @claims_locales if OmniauthOpenidFederation::StringHelpers.present?(@claims_locales)
      claim[:prompt] = @prompt if OmniauthOpenidFederation::StringHelpers.present?(@prompt)
      claim[:hd] = @hd if OmniauthOpenidFederation::StringHelpers.present?(@hd)
      claim[:acr_values] = @acr_values if OmniauthOpenidFederation::StringHelpers.present?(@acr_values)

      # Add extra parameters
      claim.merge!(@extra_params)

      # Include client entity statement for automatic registration (OpenID Federation Section 12.1)
      # When using automatic registration, the entity statement is included in the request object
      if OmniauthOpenidFederation::StringHelpers.present?(@client_entity_statement)
        claim[:trust_chain] = [@client_entity_statement]
        OmniauthOpenidFederation::Logger.debug("[Jws] Including client entity statement in request object for automatic registration")
      end

      # Build JWT header
      header = {
        alg: "RS256",
        typ: "JWT"
      }
      kid = signing_key_kid
      header[:kid] = kid if OmniauthOpenidFederation::StringHelpers.present?(kid)

      # Encode JWT using jwt gem
      JWT.encode(claim, @private_key, "RS256", header)
    end

    def load_signing_key
      # Deprecated: Use KeyExtractor.extract_signing_key instead
      # This method is kept for backward compatibility but should not be used
      nil
    end

    def signing_key_kid
      metadata = load_metadata_from_entity_statement
      return nil unless metadata

      jwks = metadata[:jwks] || metadata["jwks"] || {}
      keys = jwks[:keys] || jwks["keys"] || []
      signing_key = keys.find { |key| (key[:use] || key["use"]) == "sig" }
      return nil unless signing_key

      # Try to get kid from signing key (handle both symbol and string keys)
      signing_key[:kid] || signing_key["kid"]
    end

    def client_audience
      # Use configured audience if provided
      return @audience if OmniauthOpenidFederation::StringHelpers.present?(@audience)

      # If no audience configured, return nil - it should be provided via options
      # Audience is typically the token_endpoint URL
      nil
    end

    # Load metadata from entity statement (replaces static metadata file)
    # Extracts metadata and JWKS from entity statement for key extraction
    #
    # @return [Hash, nil] Metadata hash with JWKS or nil if not available
    def load_metadata_from_entity_statement
      return nil unless @entity_statement_path
      return nil unless File.exist?(@entity_statement_path)

      begin
        # Parse entity statement to extract metadata and JWKS
        parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks(
          @entity_statement_path
        )
        return nil unless parsed && parsed[:metadata]

        # Return metadata in format expected by KeyExtractor
        metadata = parsed[:metadata]
        entity_jwks = parsed[:entity_jwks] || metadata[:jwks] || {}

        # Return metadata with JWKS included
        metadata.merge(jwks: entity_jwks)
      rescue => e
        OmniauthOpenidFederation::Logger.warn("[Jws] Failed to load metadata from entity statement: #{e.message}")
        nil
      end
    end

    # Check if request object encryption is required
    # Priority:
    # 1. always_encrypt_request_object option (if set to true, always encrypt if keys available)
    # 2. Provider metadata request_object_encryption_alg (if provider requires encryption)
    #
    # According to OpenID Connect Core spec, if provider metadata specifies
    # request_object_encryption_alg, the client SHOULD encrypt request objects
    #
    # @param provider_metadata [Hash, nil] Provider metadata from entity statement
    # @param always_encrypt [Boolean, nil] Force encryption if encryption keys are available
    # @return [Boolean] true if encryption is required, false otherwise
    def should_encrypt_request_object?(provider_metadata, always_encrypt: false)
      # If always_encrypt is true, check if encryption keys are available
      if always_encrypt
        return has_encryption_keys?(provider_metadata)
      end

      # Otherwise, check provider metadata for encryption requirements
      return false unless provider_metadata

      encryption_alg = provider_metadata["request_object_encryption_alg"] ||
        provider_metadata[:request_object_encryption_alg]

      OmniauthOpenidFederation::StringHelpers.present?(encryption_alg) && encryption_alg == "RSA-OAEP"
    end

    # Check if encryption keys are available in provider metadata
    #
    # @param provider_metadata [Hash, nil] Provider metadata from entity statement
    # @return [Boolean] true if encryption keys are available, false otherwise
    def has_encryption_keys?(provider_metadata)
      return false unless provider_metadata

      provider_jwks = provider_metadata["jwks"] || provider_metadata[:jwks]
      return false unless provider_jwks

      keys = provider_jwks["keys"] || provider_jwks[:keys] || []
      keys.any? { |key| (key["use"] == "enc" || key[:use] == "enc") || (!key["use"] && !key[:use]) }
    end

    # Encrypt the signed request object using provider's public key
    # According to RFC 9101 and OpenID Connect Core, encryption uses:
    # - Key encryption: RSA-OAEP (from request_object_encryption_alg)
    # - Content encryption: A128CBC-HS256 or A128GCM (from request_object_encryption_enc)
    #
    # @param signed_jwt [String] The signed JWT request object
    # @param provider_metadata [Hash] Provider metadata containing encryption parameters
    # @return [String] The encrypted JWT (JWE format)
    # @raise [EncryptionError] If encryption fails
    def encrypt_request_object(signed_jwt, provider_metadata)
      encryption_alg = provider_metadata["request_object_encryption_alg"] ||
        provider_metadata[:request_object_encryption_alg]
      encryption_enc = provider_metadata["request_object_encryption_enc"] ||
        provider_metadata[:request_object_encryption_enc]

      unless encryption_alg == "RSA-OAEP"
        error_msg = "Unsupported request object encryption algorithm: #{encryption_alg}"
        OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
        raise EncryptionError, error_msg
      end

      # Get provider's public key from JWKS
      # Note: This requires provider JWKS to be available
      # In practice, provider JWKS should be fetched from entity statement or jwks_uri
      provider_jwks = provider_metadata["jwks"] || provider_metadata[:jwks]
      unless provider_jwks
        error_msg = "Provider JWKS not available for request object encryption"
        OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
        raise EncryptionError, error_msg
      end

      # Find encryption key (use: "enc" or first key if no use specified)
      keys = provider_jwks["keys"] || provider_jwks[:keys] || []
      encryption_key_data = keys.find { |key| key["use"] == "enc" || key[:use] == "enc" } || keys.first

      unless encryption_key_data
        error_msg = "No encryption key found in provider JWKS"
        OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
        raise EncryptionError, error_msg
      end

      begin
        # Convert JWK to OpenSSL public key
        public_key = KeyExtractor.jwk_to_openssl_key(encryption_key_data)

        # Encrypt the signed JWT using JWE gem
        # For JWE, we encrypt the signed JWT string as plaintext
        # The pattern is: sign first, then encrypt (nested JWT)
        # JWE.encrypt(plaintext, key, alg: "RSA-OAEP", enc: "A128CBC-HS256")
        JWE.encrypt(
          signed_jwt,
          public_key,
          alg: encryption_alg,
          enc: encryption_enc
        )
      rescue => e
        error_msg = "Failed to encrypt request object: #{e.class} - #{e.message}"
        OmniauthOpenidFederation::Logger.error("[Jws] #{error_msg}")
        raise EncryptionError, error_msg, e.backtrace
      end
    end
  end
end
