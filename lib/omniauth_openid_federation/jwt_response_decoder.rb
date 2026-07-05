require "base64"
require "json"
require "jwt"
require "uri"

require_relative "string_helpers"
require_relative "logger"
require_relative "validators"
require_relative "utils"
require_relative "key_extractor"
require_relative "jwe"
require_relative "jwks/decode"
require_relative "federation/entity_statement"
require_relative "federation/entity_statement_helper"
require_relative "federation/signed_jwks"

module OmniauthOpenidFederation
  # Decrypts and verifies compact JWE/JWS response bodies (nested JWTs).
  class JwtResponseDecoder
    COMPACT_TOKEN_PATTERN = /\A[\w\-.]+\z/

    def initialize(strategy_options:, client: nil)
      @strategy_options = strategy_options
      @client = client
    end

    def decode(body)
      body_text = body.to_s.strip
      return {} if OmniauthOpenidFederation::StringHelpers.blank?(body_text)

      unless compact_token?(body_text)
        return OmniauthOpenidFederation::Utils.to_indifferent_hash(JSON.parse(body_text))
      end

      signed_jwt = resolve_signed_jwt(body_text)
      return OmniauthOpenidFederation::Utils.to_indifferent_hash(signed_jwt) if signed_jwt.is_a?(Hash)

      payload = verify_signed_jwt(signed_jwt)
      OmniauthOpenidFederation::Utils.to_indifferent_hash(payload)
    end

    private

    def compact_token?(body_text)
      COMPACT_TOKEN_PATTERN.match?(body_text) && body_text.count(".") >= 2
    end

    def resolve_signed_jwt(body_text)
      if OmniauthOpenidFederation::Jwe.encrypted?(body_text)
        plain_text = OmniauthOpenidFederation::Jwe.decrypt(body_text, encryption_key)
        return plain_text if plain_text.to_s.split(".").length == 3

        begin
          parsed = JSON.parse(plain_text)
          return parsed if parsed.is_a?(Hash)
        rescue JSON::ParserError
          # fall through to JWT verification path
        end

        plain_text
      else
        body_text
      end
    end

    def verify_signed_jwt(signed_jwt)
      parts = signed_jwt.to_s.split(".")
      raise ValidationError, "Signed response is not a valid JWT" if parts.empty?

      header = JSON.parse(Base64.urlsafe_decode64(parts.first))
      algorithm = header["alg"] || header[:alg]

      if algorithm.nil? || algorithm.to_s.downcase == "none"
        raise ValidationError, "JWT algorithm '#{algorithm}' is not permitted for signed responses"
      end

      unless parts.length == 3
        raise ValidationError, "Signed response is not a valid JWT"
      end

      normalized_strategy_options = OmniauthOpenidFederation::Validators.normalize_hash(@strategy_options)
      signed_jwks = fetch_signed_jwks(normalized_strategy_options)

      if signed_jwks
        payload, = ::JWT.decode(
          signed_jwt,
          nil,
          true,
          {algorithms: [algorithm], jwks: signed_jwks}
        )
        return payload
      end

      jwks_uri = resolve_jwks_uri(normalized_strategy_options)
      unless jwks_uri
        raise ConfigurationError,
          "JWKS URI not available. Cannot verify JWT signature. Provide jwks_uri in client_options or entity statement."
      end

      entity_statement_keys = load_entity_statement_keys_for_jwks_validation(normalized_strategy_options)
      payload, = OmniauthOpenidFederation::Jwks::Decode.jwt(
        signed_jwt,
        jwks_uri.to_s,
        entity_statement_keys: entity_statement_keys
      )
      payload
    rescue ConfigurationError, ValidationError, SignatureError
      raise
    rescue => error
      raise ValidationError, "Failed to verify JWT response: #{error.class} - #{error.message}", error.backtrace
    end

    def encryption_key
      raw_client_options = @strategy_options[:client_options] || @strategy_options["client_options"] || {}
      client_options = OmniauthOpenidFederation::Validators.normalize_hash(raw_client_options)

      private_key = client_options[:private_key] ||
        ((@client.respond_to?(:private_key) ? @client.private_key : nil))
      jwks = client_options[:jwks] || client_options["jwks"]

      metadata = nil
      entity_statement_path = @strategy_options[:entity_statement_path] || @strategy_options["entity_statement_path"]
      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          metadata = JSON.parse(File.read(validated_path)) if File.exist?(validated_path)
        rescue => error
          OmniauthOpenidFederation::Logger.debug("[JwtResponseDecoder] Could not load metadata for key extraction: #{error.message}")
        end
      end

      key = OmniauthOpenidFederation::KeyExtractor.extract_encryption_key(
        jwks: jwks,
        metadata: metadata,
        private_key: private_key
      ) || private_key

      OmniauthOpenidFederation::Validators.validate_private_key!(key)
      key
    end

    def resolve_jwks_uri(strategy_options)
      raw_client_options = strategy_options[:client_options] || strategy_options["client_options"] || {}
      client_options = OmniauthOpenidFederation::Validators.normalize_hash(raw_client_options)
      jwks_uri_value = client_options[:jwks_uri] ||
        ((@client.respond_to?(:jwks_uri) ? @client.jwks_uri : nil))

      if jwks_uri_value && %r{https?://.+}.match?(jwks_uri_value.to_s)
        return URI.parse(jwks_uri_value.to_s)
      end

      if jwks_uri_value
        return URI::HTTPS.build(
          host: client_options[:host] || ((@client.respond_to?(:host) ? @client.host : nil)),
          path: jwks_uri_value.to_s
        )
      end

      remote_uri = resolve_jwks_uri_from_entity_statement(strategy_options)
      remote_uri ? URI.parse(remote_uri.to_s) : nil
    end

    def fetch_signed_jwks(strategy_options)
      entity_statement_content = load_entity_statement_content(strategy_options)
      return nil if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)

      parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
        entity_statement_content
      )
      return nil if parsed.nil?

      signed_jwks_uri = parsed[:signed_jwks_uri]
      return nil if OmniauthOpenidFederation::StringHelpers.blank?(signed_jwks_uri)

      OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(signed_jwks_uri, parsed[:entity_jwks])
    rescue OmniauthOpenidFederation::SecurityError => error
      OmniauthOpenidFederation::Logger.error("[JwtResponseDecoder] Security error: #{error.message}")
      nil
    rescue
      OmniauthOpenidFederation::Logger.warn("[JwtResponseDecoder] Failed to fetch signed JWKS, falling back to standard JWKS")
      nil
    end

    def load_entity_statement_keys_for_jwks_validation(strategy_options)
      entity_statement_content = load_entity_statement_content(strategy_options)
      return nil if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)

      entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
      parsed = entity_statement.parse
      entity_jwks = parsed[:jwks] if parsed

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
        OmniauthOpenidFederation::Logger.warn("[JwtResponseDecoder] No keys found in entity statement")
        return nil
      end

      OmniauthOpenidFederation::Utils.to_indifferent_hash(
        keys: keys.map { |jwk| jwk.is_a?(Hash) ? jwk : JSON.parse(jwk.to_json) }
      )
    rescue => error
      OmniauthOpenidFederation::Logger.error(
        "[JwtResponseDecoder] Failed to load entity statement keys for JWKS validation: #{error.message}"
      )
      nil
    end

    def resolve_jwks_uri_from_entity_statement(strategy_options)
      entity_statement_content = load_entity_statement_content(strategy_options, log_fetch_errors: :debug)
      return nil if OmniauthOpenidFederation::StringHelpers.blank?(entity_statement_content)

      entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
      parsed = entity_statement.parse
      return nil unless parsed

      jwks_uri = parsed.dig(:metadata, :openid_provider, :jwks_uri) ||
        parsed.dig("metadata", "openid_provider", "jwks_uri")
      OmniauthOpenidFederation::StringHelpers.present?(jwks_uri) ? jwks_uri : nil
    rescue => error
      OmniauthOpenidFederation::Logger.debug(
        "[JwtResponseDecoder] Could not extract JWKS URI from entity statement: #{error.message}"
      )
      nil
    end

    def load_entity_statement_content(strategy_options, log_fetch_errors: :warn)
      normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(strategy_options)
      entity_statement_path = normalized_options[:entity_statement_path]
      entity_statement_url = normalized_options[:entity_statement_url]
      issuer = normalized_options[:issuer]
      entity_statement_fingerprint = normalized_options[:entity_statement_fingerprint]

      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
        begin
          validated_path = OmniauthOpenidFederation::Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: defined?(Rails) ? [Rails.root.join("config").to_s] : nil
          )
          return File.read(validated_path) if File.exist?(validated_path)
        rescue OmniauthOpenidFederation::SecurityError => error
          OmniauthOpenidFederation::Logger.error("[JwtResponseDecoder] #{error.message}")
        end
      end

      if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_url)
        begin
          return OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            entity_statement_url,
            fingerprint: entity_statement_fingerprint
          ).entity_statement
        rescue => error
          log_entity_statement_fetch_failure(log_fetch_errors, "URL", error)
        end
      end

      if OmniauthOpenidFederation::StringHelpers.present?(issuer)
        begin
          return OmniauthOpenidFederation::Federation::EntityStatement.fetch_from_issuer!(
            issuer,
            fingerprint: entity_statement_fingerprint
          ).entity_statement
        rescue => error
          log_entity_statement_fetch_failure(log_fetch_errors, "issuer", error)
        end
      end

      nil
    end

    def log_entity_statement_fetch_failure(level, source, error)
      message = "[JwtResponseDecoder] Failed to fetch entity statement from #{source}: #{error.message}"
      if level == :debug
        OmniauthOpenidFederation::Logger.debug(message)
      else
        OmniauthOpenidFederation::Logger.warn(message)
      end
    end
  end
end
