require "jwt"
require "jwe"
require "json"
require "uri"
require_relative "string_helpers"
require_relative "logger"
require_relative "validators"
require_relative "utils"
require_relative "key_extractor"

# AccessToken extension for OpenID Federation ID token decryption and signed JWKS support
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-connect-core-1_0.html OpenID Connect Core 1.0
#
# Extends OpenIDConnect::AccessToken to support:
# - ID Token decryption (RSA-OAEP + A128CBC-HS256) - Required for token security
# - Signed JWKS validation - Required for key rotation compliance
# - Entity statement key loading for signed JWKS validation
#
# This extension is automatically loaded when the omniauth_openid_federation library is required.
module OpenIDConnect
  class AccessToken
    def resource_request
      res = yield
      status_code = if res.status.is_a?(Integer)
        res.status
      else
        (res.status.respond_to?(:code) ? res.status.code : res.status)
      end
      case status_code
      when 200
        # Simple check if the response looks like a JWT string (could be ID token or encrypted userinfo)
        if /\A[\w\-.]+\z/.match?(res.body)
          # Check if it's encrypted (JWE format has 5 parts separated by dots)
          is_encrypted = res.body.split(".").length == 5

          if is_encrypted
            # Decrypt if encrypted (ID token or userinfo encryption)
            # Use encryption key from JWKS if available, fallback to private_key
            encryption_key = extract_encryption_key_for_decryption
            # Decrypt using JWE gem
            plain_text = JWE.decrypt(res.body, encryption_key)

            # Check if plain_text is a JWT (3 parts) or JSON payload
            # For nested JWTs: encrypted JWT contains signed JWT as plaintext
            # For direct encryption: encrypted JWT may contain JWT representation of payload
            if plain_text.split(".").length == 3
              # It's a JWT (signed or unsigned) - decode it
              signed_jwt = plain_text
            else
              # Try to parse as JSON, if that fails, it might be a malformed JWT
              begin
                return JSON.parse(plain_text).with_indifferent_access
              rescue JSON::ParserError
                # If parsing fails, treat as JWT and try to decode
                signed_jwt = plain_text
              end
            end
          else
            # Not encrypted, use body directly (signed JWT)
            signed_jwt = res.body
          end

          # Try to get options from strategy configuration
          strategy_options = get_strategy_options

          # Access client_options from the options hash and normalize keys
          raw_client_options = strategy_options[:client_options] || strategy_options["client_options"] || {}
          client_options = OmniauthOpenidFederation::Validators.normalize_hash(raw_client_options)

          # Get jwks_uri from client_options or fallback to client
          jwks_uri_value = client_options[:jwks_uri] || ((respond_to?(:client) && client&.respond_to?(:jwks_uri)) ? client.jwks_uri : nil)

          jwks_uri =
            if jwks_uri_value && %r{https?://.+}.match?(jwks_uri_value.to_s)
              URI.parse(jwks_uri_value.to_s)
            elsif jwks_uri_value
              URI::HTTPS.build(
                host: client_options[:host] || ((respond_to?(:client) && client&.respond_to?(:host)) ? client.host : nil),
                path: jwks_uri_value.to_s
              )
            else
              # If we can't determine jwks_uri, we'll need to handle this in the JWT decode
              nil
            end

          # Always use federation features (signed JWKS preferred, fallback to standard JWKS)
          normalized_strategy_options = OmniauthOpenidFederation::Validators.normalize_hash(strategy_options)

          # Check if JWT is signed or unsigned
          # Decode header to check algorithm
          begin
            header_part = signed_jwt.split(".").first
            header = JSON.parse(Base64.urlsafe_decode64(header_part))
            algorithm = header["alg"] || header[:alg]

            if algorithm == "none" || algorithm.nil?
              # Unsigned JWT - decode without verification
              jwt = ::JWT.decode(signed_jwt, nil, false)
            else
              # Signed JWT - decode with verification
              signed_jwks = fetch_signed_jwks(normalized_strategy_options)
              if signed_jwks
                # Decode using signed JWKS
                jwt = ::JWT.decode(
                  signed_jwt,
                  nil,
                  true,
                  {algorithms: [algorithm], jwks: signed_jwks}
                )
              else
                # Fallback to standard JWKS
                # Try to resolve JWKS URI from entity statement if not in client_options
                unless jwks_uri
                  OmniauthOpenidFederation::Logger.debug("[AccessToken] JWKS URI not in client_options, trying to resolve from entity statement")
                  jwks_uri = resolve_jwks_uri_from_entity_statement(normalized_strategy_options)
                  if jwks_uri
                    OmniauthOpenidFederation::Logger.debug("[AccessToken] Successfully resolved JWKS URI from entity statement")
                    # Convert to URI object if it's a string
                    jwks_uri = URI.parse(jwks_uri) if jwks_uri.is_a?(String) && !jwks_uri.is_a?(URI)
                  end
                end

                unless jwks_uri
                  error_msg = "JWKS URI not available. Cannot verify JWT signature. Provide jwks_uri in client_options or entity statement."
                  OmniauthOpenidFederation::Logger.error("[AccessToken] #{error_msg}")
                  raise OmniauthOpenidFederation::ConfigurationError, error_msg
                end

                entity_statement_keys = load_entity_statement_keys_for_jwks_validation(normalized_strategy_options)
                jwt = OmniauthOpenidFederation::Jwks::Decode.jwt(
                  signed_jwt,
                  jwks_uri.to_s,
                  entity_statement_keys: entity_statement_keys
                )
              end
            end
          rescue => e
            # If header parsing fails, try to decode as unsigned
            OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to parse JWT header, trying unsigned decode: #{e.message}")
            jwt = ::JWT.decode(signed_jwt, nil, false)
          end

          jwt.first.with_indifferent_access
        else
          JSON.parse(res.body).with_indifferent_access
        end
      when 400
        raise BadRequest.new("API Access Faild", res)
      when 401
        raise Unauthorized.new("Access Token Invalid or Expired", res)
      when 403
        raise Forbidden.new("Insufficient Scope", res)
      else
        raise HttpError.new(res.status, "Unknown HttpError", res)
      end
    end

    private

    # Get strategy options from client (stored by strategy when client was created)
    # Falls back to extracting from client attributes if strategy options not available
    #
    # @return [Hash] Strategy options hash
    def get_strategy_options
      # Try to get strategy options stored on client by the strategy
      if respond_to?(:client) && client
        strategy_options = client.instance_variable_get(:@strategy_options)
        return strategy_options if strategy_options&.is_a?(Hash)
      end

      # Fallback: try to extract from client attributes if available
      if respond_to?(:client) && client
        # Build minimal options from client
        client_options = {}
        client_options[:jwks_uri] = client.jwks_uri.to_s if client.respond_to?(:jwks_uri) && client.jwks_uri
        client_options[:private_key] = client.private_key if client.respond_to?(:private_key) && client.private_key

        return {
          client_options: client_options
        }
      end

      # Last resort: return empty hash (will cause errors later, but at least won't crash immediately)
      OmniauthOpenidFederation::Logger.warn("[AccessToken] Could not determine strategy options from client. Some features may not work correctly.")
      {}
    end

    # Extract encryption key for decrypting ID tokens or userinfo responses
    # Uses KeyExtractor to support separate signing/encryption keys per OpenID Federation spec
    #
    # @return [OpenSSL::PKey::RSA] Encryption key
    def extract_encryption_key_for_decryption
      # Try to get strategy options
      strategy_options = get_strategy_options
      raw_client_options = strategy_options[:client_options] || strategy_options["client_options"]
      client_options = OmniauthOpenidFederation::Validators.normalize_hash(raw_client_options)

      private_key = client_options[:private_key] || ((respond_to?(:client) && client&.respond_to?(:private_key)) ? client.private_key : nil)
      jwks = client_options[:jwks] || client_options["jwks"]

      # Try to load metadata for key extraction
      metadata = nil
      entity_statement_path = strategy_options[:entity_statement_path]
      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          if File.exist?(validated_path)
            metadata = JSON.parse(File.read(validated_path))
          end
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Could not load metadata for key extraction: #{e.message}")
        end
      end

      # Extract encryption key from JWKS or use provided private_key (backward compatibility)
      encryption_key = OmniauthOpenidFederation::KeyExtractor.extract_encryption_key(
        jwks: jwks,
        metadata: metadata,
        private_key: private_key
      ) || private_key

      OmniauthOpenidFederation::Validators.validate_private_key!(encryption_key)
      encryption_key
    end

    def fetch_signed_jwks(strategy_options)
      # Support entity_statement_path, entity_statement_url, or issuer (like strategy does)
      entity_statement_path = strategy_options[:entity_statement_path] || strategy_options["entity_statement_path"]
      entity_statement_url = strategy_options[:entity_statement_url] || strategy_options["entity_statement_url"]
      issuer = strategy_options[:issuer] || strategy_options["issuer"]
      entity_statement_fingerprint = strategy_options[:entity_statement_fingerprint] || strategy_options["entity_statement_fingerprint"]

      # Load entity statement from path, URL, or issuer
      entity_statement_content = nil

      # Priority 1: File path (if provided)
      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          if File.exist?(validated_path)
            entity_statement_content = File.read(validated_path)
          else
            OmniauthOpenidFederation::Logger.debug("[AccessToken] Entity statement file not found: #{OmniauthOpenidFederation::Utils.sanitize_path(validated_path)}")
          end
        rescue SecurityError => e
          OmniauthOpenidFederation::Logger.error("[AccessToken] #{e.message}")
        end
      end

      # Priority 2: Fetch from URL (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(entity_statement_url)
        begin
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Fetching entity statement from URL for signed JWKS")
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            entity_statement_url,
            fingerprint: entity_statement_fingerprint
          )
          # fetch! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to fetch entity statement from URL: #{e.message}")
        end
      end

      # Priority 3: Fetch from issuer (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(issuer)
        begin
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Fetching entity statement from issuer for signed JWKS")
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch_from_issuer!(
            issuer,
            fingerprint: entity_statement_fingerprint
          )
          # fetch_from_issuer! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to fetch entity statement from issuer: #{e.message}")
        end
      end

      if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)
        OmniauthOpenidFederation::Logger.debug("[AccessToken] Entity statement not available (path, URL, or issuer not configured), skipping signed JWKS")
        return nil
      end

      begin
        parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
          entity_statement_content
        )
        if parsed.nil?
          return nil
        end

        signed_jwks_uri = parsed[:signed_jwks_uri]
        if OmniauthOpenidFederation::StringHelpers.blank?(signed_jwks_uri)
          OmniauthOpenidFederation::Logger.warn("[AccessToken] signed_jwks_uri not found in entity statement metadata")
          return nil
        end

        # Get entity JWKS for validation
        entity_jwks = parsed[:entity_jwks]

        # Fetch and validate signed JWKS
        sanitized_uri = OmniauthOpenidFederation::Utils.sanitize_uri(signed_jwks_uri)
        OmniauthOpenidFederation::Logger.debug("[AccessToken] Fetching signed JWKS from #{sanitized_uri}")
        signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(signed_jwks_uri, entity_jwks)
        OmniauthOpenidFederation::Logger.debug("[AccessToken] Successfully fetched and validated signed JWKS")
        signed_jwks
      rescue SecurityError => e
        # Security errors should not be silently ignored
        OmniauthOpenidFederation::Logger.error("[AccessToken] Security error: #{e.message}")
        nil
      rescue
        OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to fetch signed JWKS, falling back to standard JWKS")
        # Return nil to allow fallback to standard JWKS, but log the error
        nil
      end
    end

    def load_entity_statement_keys_for_jwks_validation(strategy_options)
      # Support entity_statement_path, entity_statement_url, or issuer (like strategy does)
      entity_statement_path = strategy_options[:entity_statement_path] || strategy_options["entity_statement_path"]
      entity_statement_url = strategy_options[:entity_statement_url] || strategy_options["entity_statement_url"]
      issuer = strategy_options[:issuer] || strategy_options["issuer"]
      entity_statement_fingerprint = strategy_options[:entity_statement_fingerprint] || strategy_options["entity_statement_fingerprint"]

      # Load entity statement from path, URL, or issuer
      entity_statement_content = nil

      # Priority 1: File path (if provided)
      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          if File.exist?(validated_path)
            entity_statement_content = File.read(validated_path)
          end
        rescue SecurityError => e
          OmniauthOpenidFederation::Logger.error("[AccessToken] #{e.message}")
        end
      end

      # Priority 2: Fetch from URL (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(entity_statement_url)
        begin
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            entity_statement_url,
            fingerprint: entity_statement_fingerprint
          )
          # fetch! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to fetch entity statement from URL: #{e.message}")
        end
      end

      # Priority 3: Fetch from issuer (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(issuer)
        begin
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch_from_issuer!(
            issuer,
            fingerprint: entity_statement_fingerprint
          )
          # fetch_from_issuer! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[AccessToken] Failed to fetch entity statement from issuer: #{e.message}")
        end
      end

      if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)
        OmniauthOpenidFederation::Logger.warn("[AccessToken] Entity statement not available for federation")
        return nil
      end

      begin
        # Parse entity statement to extract keys
        # entity_statement_content is now always a string (JWT)
        entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
        parsed = entity_statement.parse
        entity_jwks = parsed[:jwks] if parsed

        # Extract keys from entity JWKS
        keys = if entity_jwks.is_a?(Hash) && entity_jwks.key?("keys")
          entity_jwks["keys"]
        elsif entity_jwks.is_a?(Hash) && entity_jwks.key?(:keys)
          entity_jwks[:keys]
        elsif entity_jwks.is_a?(Array)
          entity_jwks
        else
          []
        end
        if keys.empty?
          OmniauthOpenidFederation::Logger.warn("[AccessToken] No keys found in entity statement")
          return nil
        end

        # Convert to format expected by JWT gem (HashWithIndifferentAccess with keys array)
        jwks_hash = {
          keys: keys.map { |jwk| jwk.is_a?(Hash) ? jwk : JSON.parse(jwk.to_json) }
        }
        OmniauthOpenidFederation::Utils.to_indifferent_hash(jwks_hash)
      rescue => e
        error_msg = "Failed to load entity statement keys for JWKS validation: #{e.class} - #{e.message}"
        OmniauthOpenidFederation::Logger.error("[AccessToken] #{error_msg}")
        # Return nil to allow fallback, but log the error
        nil
      end
    end

    # Resolve JWKS URI from entity statement if not in client_options
    #
    # @param strategy_options [Hash] Strategy options hash
    # @return [String, nil] JWKS URI or nil if not available
    def resolve_jwks_uri_from_entity_statement(strategy_options)
      # Try both symbol and string keys (OmniAuth options can be either)
      entity_statement_path = strategy_options[:entity_statement_path] || strategy_options["entity_statement_path"]
      entity_statement_url = strategy_options[:entity_statement_url] || strategy_options["entity_statement_url"]
      issuer = strategy_options[:issuer] || strategy_options["issuer"]
      entity_statement_fingerprint = strategy_options[:entity_statement_fingerprint] || strategy_options["entity_statement_fingerprint"]

      # Debug logging to help diagnose issues
      if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_path) &&
          OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_url) &&
          OmniauthOpenidFederation::StringHelpers.blank?(issuer)
        OmniauthOpenidFederation::Logger.debug("[AccessToken] No entity statement source configured (path, URL, or issuer) in strategy options. Available keys: #{strategy_options.keys.join(", ")}")
      end

      # Load entity statement from path, URL, or issuer
      entity_statement_content = nil

      # Priority 1: File path (if provided)
      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          if File.exist?(validated_path)
            entity_statement_content = File.read(validated_path)
          end
        rescue SecurityError => e
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Could not load entity statement from path: #{e.message}")
        end
      end

      # Priority 2: Fetch from URL (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(entity_statement_url)
        begin
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            entity_statement_url,
            fingerprint: entity_statement_fingerprint
          )
          # fetch! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Could not fetch entity statement from URL: #{e.message}")
        end
      end

      # Priority 3: Fetch from issuer (if provided)
      if entity_statement_content.nil? && OmniauthOpenidFederation::StringHelpers.present?(issuer)
        begin
          entity_statement_instance = OmniauthOpenidFederation::Federation::EntityStatement.fetch_from_issuer!(
            issuer,
            fingerprint: entity_statement_fingerprint
          )
          # fetch_from_issuer! returns EntityStatement instance, extract JWT string from it
          entity_statement_content = entity_statement_instance.entity_statement
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[AccessToken] Could not fetch entity statement from issuer: #{e.message}")
        end
      end

      return nil if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)

      begin
        # Parse entity statement to extract JWKS URI
        # entity_statement_content is now always a string (JWT)
        entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
        parsed = entity_statement.parse
        return nil unless parsed

        # Extract JWKS URI from provider metadata
        jwks_uri = parsed.dig(:metadata, :openid_provider, :jwks_uri) ||
          parsed.dig("metadata", "openid_provider", "jwks_uri")

        return jwks_uri if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
      rescue => e
        OmniauthOpenidFederation::Logger.debug("[AccessToken] Could not extract JWKS URI from entity statement: #{e.message}")
      end

      nil
    end
  end
end
