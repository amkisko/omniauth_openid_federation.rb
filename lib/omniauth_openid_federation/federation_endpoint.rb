require_relative "federation/entity_statement_builder"
require_relative "logger"
require_relative "errors"
require_relative "utils"
require_relative "string_helpers"
require "jwt"
require "base64"
require "digest"
require "time"
require "fileutils"

# Federation Endpoint for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Provides a federation endpoint (/.well-known/openid-federation) that serves
# entity statements for clients to fetch provider configuration and JWKS.
#
# This enables signed JWKS support as required by OpenID Federation 1.0 specification.
module OmniauthOpenidFederation
  # Federation Endpoint for serving entity statements
  #
  # Supports automatic key provisioning with separate signing and encryption keys.
  # See AUTOMATIC_KEY_PROVISIONING.md for detailed documentation.
  #
  # @example Auto-configure with separate keys (RECOMMENDED for production)
  #   # In config/initializers/omniauth_openid_federation.rb
  #   OmniauthOpenidFederation::FederationEndpoint.auto_configure(
  #     issuer: "https://provider.example.com",
  #     signing_key: OpenSSL::PKey::RSA.new(File.read("config/signing-key.pem")),
  #     encryption_key: OpenSSL::PKey::RSA.new(File.read("config/encryption-key.pem")),
  #     entity_statement_path: "config/entity-statement.jwt", # Cache for automatic key rotation
  #     metadata: {
  #       openid_relying_party: {
  #         redirect_uris: ["https://provider.example.com/auth/callback"],
  #         client_registration_types: ["automatic"]
  #       }
  #     },
  #     auto_provision_keys: true
  #   )
  #
  # @example Manual configuration (advanced)
  #   OmniauthOpenidFederation::FederationEndpoint.configure do |config|
  #     config.issuer = "https://provider.example.com"
  #     config.subject = "https://provider.example.com"
  #     config.signing_key = OpenSSL::PKey::RSA.new(File.read("config/signing-key.pem"))
  #     config.encryption_key = OpenSSL::PKey::RSA.new(File.read("config/encryption-key.pem"))
  #     config.jwks = {
  #       keys: [
  #         { kty: "RSA", use: "sig", kid: "sig-key-id", n: "...", e: "..." },
  #         { kty: "RSA", use: "enc", kid: "enc-key-id", n: "...", e: "..." }
  #       ]
  #     }
  #     config.metadata = {
  #       openid_provider: {
  #         issuer: "https://provider.example.com",
  #         authorization_endpoint: "https://provider.example.com/oauth2/authorize",
  #         token_endpoint: "https://provider.example.com/oauth2/token",
  #         userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
  #         jwks_uri: "https://provider.example.com/.well-known/jwks.json",
  #         signed_jwks_uri: "https://provider.example.com/.well-known/signed-jwks.json"
  #       }
  #     }
  #   end
  #
  #   # In config/routes.rb (Rails)
  #   get "/.well-known/openid-federation", to: "omniauth_openid_federation/federation#show"
  #
  class FederationEndpoint
    class << self
      # Configure the federation endpoint
      #
      # @yield [config] Configuration block
      # @yieldparam config [Configuration] Configuration object
      def configure
        yield(configuration) if block_given?
        configuration
      end

      # Auto-configure the federation endpoint with automatic key provisioning
      # Automatically calculates JWKS, metadata, and other settings from provided inputs
      #
      # Automatic Key Provisioning:
      # - Extracts JWKS from entity_statement_path if provided (cached, supports key rotation)
      # - Supports separate signing_key and encryption_key (RECOMMENDED for production)
      # - Falls back to single private_key (DEV/TESTING ONLY - not recommended for production)
      # - Automatically generates both signing and encryption keys from provided keys
      #
      # @param issuer [String] Entity issuer (typically the application URL)
      # @param signing_key [OpenSSL::PKey::RSA, nil] Signing private key (RECOMMENDED: separate from encryption)
      # @param encryption_key [OpenSSL::PKey::RSA, nil] Encryption private key (RECOMMENDED: separate from signing)
      # @param private_key [OpenSSL::PKey::RSA, nil] Single private key for both signing and encryption (DEV/TESTING ONLY)
      #   - Only used if signing_key and encryption_key are not provided
      #   - NOT RECOMMENDED for production - use separate keys instead
      # @param jwks [Hash, nil] Pre-configured JWKS (optional, overrides automatic provisioning)
      # @param subject [String, nil] Entity subject (defaults to issuer if not provided)
      # @param entity_statement_path [String, nil] Path to existing entity statement to extract JWKS from (optional)
      #   - Used as cache for automatic key provisioning
      #   - Supports automatic key rotation: update file, library uses new keys on next cache refresh
      # @param entity_statement_url [String, nil] URL to existing entity statement to extract JWKS from (optional)
      # @param metadata [Hash, nil] Provider metadata (auto-generated if not provided)
      # @param expiration_seconds [Integer, nil] Entity statement expiration in seconds (default: 86400)
      # @param jwks_cache_ttl [Integer, nil] Cache TTL for JWKS endpoints in seconds (default: 3600)
      # @param auto_provision_keys [Boolean] Enable automatic key provisioning (default: true)
      #   - If true: Automatically extracts/generates keys from provided sources
      #   - If false: Requires explicit jwks parameter
      # @param key_rotation_period [Integer, nil] Key rotation period in seconds (default: nil, no automatic rotation)
      #   - If set: Keys are automatically rotated when entity statement file age exceeds this period
      #   - Keys are regenerated and entity statement file is updated
      #   - Example: 90.days.to_i for 90-day rotation period
      # @return [Configuration] The configured configuration object
      # @raise [ConfigurationError] If required parameters are missing
      def auto_configure(
        issuer:,
        signing_key: nil,
        encryption_key: nil,
        private_key: nil,
        jwks: nil,
        subject: nil,
        entity_statement_path: nil,
        entity_statement_url: nil,
        metadata: nil,
        expiration_seconds: nil,
        jwks_cache_ttl: nil,
        auto_provision_keys: true,
        key_rotation_period: nil
      )
        raise ConfigurationError, "Issuer is required" if StringHelpers.blank?(issuer)

        if signing_key && encryption_key && private_key
          raise ConfigurationError, "Cannot specify signing_key, encryption_key, and private_key simultaneously. " \
            "Use either (signing_key + encryption_key) OR private_key, not both."
        end

        unless auto_provision_keys
          if signing_key.nil? && encryption_key.nil? && private_key.nil? && jwks.nil?
            raise ConfigurationError, "At least one key source is required: signing_key, encryption_key, private_key, or jwks"
          end
        end

        # Warn if using single private_key (dev/testing only)
        if private_key && signing_key.nil? && encryption_key.nil?
          OmniauthOpenidFederation::Logger.warn(
            "[FederationEndpoint] Using single private_key for both signing and encryption. " \
            "This is DEV/TESTING ONLY. For production, use separate signing_key and encryption_key."
          )
        end

        config = configuration

        config.issuer = issuer
        config.subject = subject || issuer

        if auto_provision_keys && jwks.nil?
          jwks = provision_jwks(
            signing_key: signing_key,
            encryption_key: encryption_key,
            private_key: private_key,
            entity_statement_path: entity_statement_path,
            issuer: issuer,
            subject: subject || issuer,
            metadata: metadata,
            entity_statement_path_provided: !entity_statement_path.nil?
          )

          if jwks.nil? && signing_key.nil? && encryption_key.nil? && private_key.nil? && config.signing_key.nil?
            raise ConfigurationError, "Signing key is required. Provide signing_key, encryption_key, or private_key, or enable auto_provision_keys with entity_statement_path."
          end
        end

        config.jwks = jwks || raise(ConfigurationError, "JWKS is required. Provide jwks parameter or enable auto_provision_keys.")

        if signing_key && encryption_key
          config.signing_key = signing_key
          config.encryption_key = encryption_key
          config.private_key = signing_key
        elsif signing_key
          config.signing_key = signing_key
          config.encryption_key = signing_key
          config.private_key = signing_key
        elsif private_key
          config.private_key = private_key
          config.signing_key = private_key
          config.encryption_key = private_key
        elsif config.signing_key && config.encryption_key
          config.private_key = config.signing_key
        elsif config.signing_key
          config.private_key = config.signing_key
          config.encryption_key = config.signing_key
        else
          raise ConfigurationError, "Signing key is required. Provide signing_key, encryption_key, or private_key, or enable auto_provision_keys with entity_statement_path."
        end

        keys = config.jwks[:keys] || config.jwks["keys"] || []
        signing_key_jwk = keys.find { |k| (k[:use] || k["use"]) == "sig" } || keys.first
        config.kid = signing_key_jwk&.dig(:kid) || signing_key_jwk&.dig("kid")

        entity_type = detect_entity_type(metadata)

        if metadata
          metadata = ensure_jwks_endpoints(metadata, issuer, entity_type)
          config.metadata = metadata
          entity_type = detect_entity_type(config.metadata)
        else
          base_metadata = {
            issuer: issuer
          }

          if entity_type == :openid_provider
            base_metadata[:federation_fetch_endpoint] = "#{issuer}/.well-known/openid-federation/fetch"
            config.metadata = {
              openid_provider: base_metadata
            }
          else
            config.metadata = {
              openid_relying_party: base_metadata
            }
          end

          config.metadata = ensure_jwks_endpoints(config.metadata, issuer, entity_type)

          OmniauthOpenidFederation::Logger.warn(
            "[FederationEndpoint] Auto-generated metadata only includes well-known endpoints. " \
            "Provide custom metadata parameter for application-specific endpoints " \
            "(authorization_endpoint, token_endpoint, userinfo_endpoint for OP; " \
            "redirect_uris, client_registration_types for RP)."
          )
        end

        config.entity_type = entity_type

        config.expiration_seconds = expiration_seconds if expiration_seconds
        config.jwks_cache_ttl = jwks_cache_ttl if jwks_cache_ttl
        config.key_rotation_period = key_rotation_period if key_rotation_period
        config.entity_statement_path = entity_statement_path if entity_statement_path

        if entity_statement_path && (signing_key || private_key)
          begin
            keys_dir = File.dirname(entity_statement_path)
            FileUtils.mkdir_p(keys_dir) unless File.directory?(keys_dir)

            if signing_key && encryption_key
              signing_key_path = File.join(keys_dir, ".federation-signing-key.pem")
              encryption_key_path = File.join(keys_dir, ".federation-encryption-key.pem")
              File.write(signing_key_path, signing_key.to_pem)
              File.write(encryption_key_path, encryption_key.to_pem)
              File.chmod(0o600, signing_key_path)
              File.chmod(0o600, encryption_key_path)
              OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Saved provided signing and encryption keys to disk")
            elsif private_key
              signing_key_path = File.join(keys_dir, ".federation-signing-key.pem")
              encryption_key_path = File.join(keys_dir, ".federation-encryption-key.pem")
              File.write(signing_key_path, private_key.to_pem)
              File.write(encryption_key_path, private_key.to_pem)
              File.chmod(0o600, signing_key_path)
              File.chmod(0o600, encryption_key_path)
              OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Saved provided private_key to disk (used for both signing and encryption)")
            end

            entity_statement = generate_entity_statement
            FileUtils.mkdir_p(File.dirname(entity_statement_path)) if File.dirname(entity_statement_path) != "."
            File.write(entity_statement_path, entity_statement)
            File.chmod(0o600, entity_statement_path) if File.exist?(entity_statement_path)
            OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Regenerated entity statement with provided keys")
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Failed to save keys or regenerate entity statement: #{e.message}")
          end
        end

        if auto_provision_keys && entity_statement_path && config.key_rotation_period
          rotate_keys_if_needed(config)
        end

        OmniauthOpenidFederation::Logger.info("[FederationEndpoint] Auto-configured with issuer: #{issuer}")
        config
      end

      # Automatic key provisioning: Extract or generate JWKS from available sources
      #
      # @param signing_key [OpenSSL::PKey::RSA, nil] Signing private key
      # @param encryption_key [OpenSSL::PKey::RSA, nil] Encryption private key
      # @param private_key [OpenSSL::PKey::RSA, nil] Single private key (dev/testing only)
      # @param entity_statement_path [String, nil] Path to entity statement file
      # @param issuer [String, nil] Issuer for entity statement (needed for key generation)
      # @param subject [String, nil] Subject for entity statement (needed for key generation)
      # @param metadata [Hash, nil] Metadata for entity statement (needed for key generation)
      # @param entity_statement_path_provided [Boolean] Whether entity_statement_path was provided as parameter (not auto-generated)
      # @return [Hash, nil] JWKS hash with keys array, or nil if provisioning fails
      def provision_jwks(signing_key: nil, encryption_key: nil, private_key: nil, entity_statement_path: nil, issuer: nil, subject: nil, metadata: nil, entity_statement_path_provided: false)
        if encryption_key
          signing_key_for_jwk = signing_key || private_key
          raise ConfigurationError, "Signing key is required when encryption_key is provided. Provide signing_key or private_key." unless signing_key_for_jwk

          # If same, generate single JWK to avoid duplicate kid values
          if signing_key_for_jwk.public_key.to_pem == encryption_key.public_key.to_pem
            single_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key_for_jwk, use: nil)
            return {keys: [single_jwk]}
          else
            signing_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key_for_jwk, use: "sig")
            encryption_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc")
            return {keys: [signing_jwk, encryption_jwk]}
          end
        elsif private_key || signing_key
          single_key = private_key || signing_key

          # Generate JWK without 'use' field to avoid duplicate kid values which violate the spec
          single_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(single_key, use: nil)
          return {keys: [single_jwk]}
        end

        extraction_failed = false
        if entity_statement_path&.then { |path| File.exist?(path) }
          begin
            entity_statement_content = File.read(entity_statement_path)
            jwks = OmniauthOpenidFederation::Utils.extract_jwks_from_entity_statement(entity_statement_content)
            if jwks&.dig(:keys)&.any?
              OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Extracted JWKS from entity statement file: #{entity_statement_path}")

              keys_dir = File.dirname(entity_statement_path)
              signing_key_path = File.join(keys_dir, ".federation-signing-key.pem")
              encryption_key_path = File.join(keys_dir, ".federation-encryption-key.pem")

              if File.exist?(signing_key_path) && File.exist?(encryption_key_path)
                begin
                  config = configuration
                  config.signing_key = OpenSSL::PKey::RSA.new(File.read(signing_key_path))
                  config.encryption_key = OpenSSL::PKey::RSA.new(File.read(encryption_key_path))
                  config.private_key = config.signing_key
                  OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Loaded private keys from disk")
                rescue => e
                  OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Failed to load private keys from disk: #{e.message}")
                end
              elsif File.exist?(signing_key_path)
                # Single key file (backward compatibility or dev/testing)
                begin
                  config = configuration
                  single_key = OpenSSL::PKey::RSA.new(File.read(signing_key_path))
                  config.signing_key = single_key
                  config.encryption_key = single_key
                  config.private_key = single_key
                  OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Loaded single private key from disk")
                rescue => e
                  OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Failed to load private key from disk: #{e.message}")
                end
              end

              return jwks
            else
              extraction_failed = true
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Failed to extract JWKS from entity statement file: #{e.message}")
            extraction_failed = true
          end
        end

        if issuer && (!entity_statement_path_provided || !extraction_failed)
          entity_statement_path ||= begin
            configuration
            if defined?(Rails) && Rails.root
              default_path = Rails.root.join("config/.federation-entity-statement.jwt").to_s
              OmniauthOpenidFederation::Logger.info("[FederationEndpoint] No entity_statement_path provided, using default: #{OmniauthOpenidFederation::Utils.sanitize_path(default_path)}")
              default_path
            end
          end

          if entity_statement_path
            OmniauthOpenidFederation::Logger.info("[FederationEndpoint] No keys provided, auto-generating new signing and encryption keys")
            jwks = generate_fresh_keys(
              entity_statement_path: entity_statement_path,
              issuer: issuer,
              subject: subject || issuer,
              metadata: metadata # Can be nil - generate_fresh_keys will create minimal metadata
            )
            return jwks if jwks
          else
            OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Cannot auto-generate keys: entity_statement_path is required for persistence")
          end
        end

        nil
      end

      def configuration
        @configuration ||= Configuration.new
      end

      def generate_entity_statement
        config = configuration
        validate_configuration(config)

        builder = Federation::EntityStatementBuilder.new(
          issuer: config.issuer,
          subject: config.subject || config.issuer,
          private_key: config.private_key,
          jwks: config.jwks,
          metadata: config.metadata,
          expiration_seconds: config.expiration_seconds || 86400,
          kid: config.kid,
          authority_hints: config.authority_hints
        )

        builder.build
      end

      def generate_signed_jwks
        config = configuration
        validate_configuration(config)

        jwks_payload = resolve_signed_jwks_payload(config)

        signing_kid = config.signed_jwks_signing_kid || config.kid || extract_kid_from_jwks(config.jwks)
        expiration_seconds = config.signed_jwks_expiration_seconds || 86400

        now = Time.now.to_i
        payload = {
          iss: config.issuer,
          sub: config.subject || config.issuer,
          iat: now,
          exp: now + expiration_seconds,
          jwks: jwks_payload
        }

        header = {
          alg: "RS256",
          typ: "JWT",
          kid: signing_kid
        }

        begin
          JWT.encode(payload, config.private_key, "RS256", header)
        rescue => e
          error_msg = "Failed to sign JWKS: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[FederationEndpoint] #{error_msg}")
          raise SignatureError, error_msg, e.backtrace
        end
      end

      def current_jwks
        config = configuration
        validate_configuration(config)
        resolve_current_jwks(config)
      end

      # Get a Rack-compatible endpoint handler
      # Use this for framework-agnostic routing (Sinatra, Rack, etc.)
      #
      # @return [RackEndpoint] Rack endpoint handler
      # @example Using with Sinatra
      #   require "sinatra"
      #   require "omniauth_openid_federation"
      #
      #   use OmniauthOpenidFederation::FederationEndpoint.rack_app
      #
      # @example Using with plain Rack
      #   require "rack"
      #   require "omniauth_openid_federation"
      #
      #   app = Rack::Builder.new do
      #     map "/.well-known" do
      #       run OmniauthOpenidFederation::FederationEndpoint.rack_app
      #     end
      #   end
      def rack_app
        require_relative "rack_endpoint"
        RackEndpoint.new
      end

      # Mount the federation endpoint routes in Rails routes
      #
      # RECOMMENDED: Use the Engine (Rails-idiomatic way):
      #   Rails.application.routes.draw do
      #     mount OmniauthOpenidFederation::Engine => "/"
      #   end
      #
      # This mounts all four endpoints at the root level:
      #   - GET /.well-known/openid-federation (entity statement)
      #   - GET /.well-known/openid-federation/fetch (fetch endpoint for Subordinate Statements)
      #   - GET /.well-known/jwks.json (standard JWKS)
      #   - GET /.well-known/signed-jwks.json (signed JWKS)
      #

      # Generate fresh signing and encryption keys and write entity statement to file
      #
      # @param entity_statement_path [String] Path to entity statement file
      # @param issuer [String, nil] Issuer for entity statement (optional, uses config if not provided)
      # @param subject [String, nil] Subject for entity statement (optional, uses issuer if not provided)
      # @param metadata [Hash, nil] Metadata for entity statement (optional, uses config if not provided, or generates minimal)
      # @param keys_output_dir [String, nil] Directory to store private keys (optional, defaults to same dir as entity_statement_path)
      # @return [Hash, nil] JWKS hash with keys array, or nil if generation fails
      def generate_fresh_keys(entity_statement_path:, issuer: nil, subject: nil, metadata: nil, keys_output_dir: nil)
        signing_key = OpenSSL::PKey::RSA.new(2048)
        encryption_key = OpenSSL::PKey::RSA.new(2048)

        signing_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key, use: "sig")
        encryption_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc")
        jwks = {keys: [signing_jwk, encryption_jwk]}

        config = configuration
        issuer ||= config.issuer
        subject ||= config.subject || issuer
        metadata ||= config.metadata

        unless metadata
          if issuer
            # Default to openid_relying_party (RP) entity type for clients
            metadata = {
              openid_relying_party: {
                issuer: issuer,
                jwks_uri: "#{issuer}/.well-known/jwks.json",
                signed_jwks_uri: "#{issuer}/.well-known/signed-jwks.json"
              }
            }
            OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Generated minimal metadata for key generation")
          else
            OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Cannot generate entity statement: issuer missing")
            return nil
          end
        end

        if issuer
          builder = Federation::EntityStatementBuilder.new(
            issuer: issuer,
            subject: subject,
            private_key: signing_key, # Use signing key for entity statement signature
            jwks: jwks,
            metadata: metadata,
            expiration_seconds: config.expiration_seconds || 86400,
            kid: signing_jwk[:kid] || signing_jwk["kid"]
          )

          entity_statement = builder.build

          keys_dir = keys_output_dir || File.dirname(entity_statement_path)
          FileUtils.mkdir_p(keys_dir) unless File.directory?(keys_dir)

          signing_key_path = File.join(keys_dir, ".federation-signing-key.pem")
          encryption_key_path = File.join(keys_dir, ".federation-encryption-key.pem")

          File.write(signing_key_path, signing_key.to_pem)
          File.write(encryption_key_path, encryption_key.to_pem)
          File.chmod(0o600, signing_key_path)
          File.chmod(0o600, encryption_key_path)

          FileUtils.mkdir_p(File.dirname(entity_statement_path)) if File.dirname(entity_statement_path) != "."
          File.write(entity_statement_path, entity_statement)
          File.chmod(0o600, entity_statement_path) if File.exist?(entity_statement_path)

          config.signing_key = signing_key
          config.encryption_key = encryption_key
          config.private_key = signing_key

          OmniauthOpenidFederation::Logger.info(
            "[FederationEndpoint] Generated fresh keys and wrote entity statement to: #{OmniauthOpenidFederation::Utils.sanitize_path(entity_statement_path)}"
          )
          OmniauthOpenidFederation::Logger.info(
            "[FederationEndpoint] Private keys stored in: #{OmniauthOpenidFederation::Utils.sanitize_path(keys_dir)}"
          )
          jwks
        else
          OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Cannot generate entity statement: issuer missing")
          nil
        end
      rescue => e
        OmniauthOpenidFederation::Logger.error("[FederationEndpoint] Failed to generate fresh keys: #{e.message}")
        nil
      end

      def rotate_keys_if_needed(config)
        return unless config.key_rotation_period && config.entity_statement_path

        entity_statement_path = config.entity_statement_path
        return unless File.exist?(entity_statement_path)

        file_mtime = File.mtime(entity_statement_path)
        rotation_period_seconds = config.key_rotation_period.to_i
        time_since_rotation = Time.zone.now - file_mtime

        if time_since_rotation >= rotation_period_seconds
          OmniauthOpenidFederation::Logger.info(
            "[FederationEndpoint] Key rotation period elapsed (#{time_since_rotation.to_i}s >= #{rotation_period_seconds}s), " \
            "generating new keys"
          )

          keys_dir = File.dirname(entity_statement_path)
          jwks = generate_fresh_keys(
            entity_statement_path: entity_statement_path,
            issuer: config.issuer,
            subject: config.subject,
            metadata: config.metadata,
            keys_output_dir: keys_dir
          )

          if jwks
            config.jwks = jwks
            keys = jwks[:keys] || jwks["keys"] || []
            signing_key_jwk = keys.find { |k| (k[:use] || k["use"]) == "sig" } || keys.first
            config.kid = signing_key_jwk&.dig(:kid) || signing_key_jwk&.dig("kid")

            OmniauthOpenidFederation::Logger.info("[FederationEndpoint] Keys rotated successfully")
          else
            OmniauthOpenidFederation::Logger.warn("[FederationEndpoint] Key rotation failed, using existing keys")
          end
        else
          OmniauthOpenidFederation::Logger.debug(
            "[FederationEndpoint] Keys still valid (#{time_since_rotation.to_i}s < #{rotation_period_seconds}s), " \
            "no rotation needed"
          )
        end
      end

      def ensure_jwks_endpoints(metadata, issuer, entity_type)
        metadata = metadata.dup
        entity_type ||= detect_entity_type(metadata)

        section = if entity_type == :openid_provider
          metadata[:openid_provider] || metadata["openid_provider"] || {}
        else
          metadata[:openid_relying_party] || metadata["openid_relying_party"] || {}
        end

        section = section.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }

        section[:jwks_uri] ||= "#{issuer}/.well-known/jwks.json"
        section[:signed_jwks_uri] ||= "#{issuer}/.well-known/signed-jwks.json"

        if entity_type == :openid_provider
          section[:federation_fetch_endpoint] ||= "#{issuer}/.well-known/openid-federation/fetch"
        end

        if entity_type == :openid_provider
          metadata[:openid_provider] = section
          metadata.delete("openid_provider") if metadata.key?("openid_provider")
        else
          metadata[:openid_relying_party] = section
          metadata.delete("openid_relying_party") if metadata.key?("openid_relying_party")
        end

        metadata
      end

      def get_subordinate_statement(subject_entity_id)
        config = configuration
        validate_configuration(config)

        entity_type = detect_entity_type(config.metadata)
        unless entity_type == :openid_provider
          OmniauthOpenidFederation::Logger.debug("[FederationEndpoint] Fetch endpoint called for non-OP entity (#{entity_type}), returning nil")
          return nil
        end

        if config.subordinate_statements_proc
          return config.subordinate_statements_proc.call(subject_entity_id)
        end

        if config.subordinate_statements && config.subordinate_statements[subject_entity_id]
          subordinate_config = config.subordinate_statements[subject_entity_id]
          return generate_subordinate_statement(
            subject_entity_id: subject_entity_id,
            subject_metadata: subordinate_config[:metadata] || subordinate_config["metadata"],
            metadata_policy: subordinate_config[:metadata_policy] || subordinate_config["metadata_policy"],
            constraints: subordinate_config[:constraints] || subordinate_config["constraints"]
          )
        end

        nil
      end

      private

      def detect_entity_type(metadata)
        return :openid_relying_party if StringHelpers.blank?(metadata)

        if metadata.key?(:openid_relying_party) || metadata.key?("openid_relying_party")
          return :openid_relying_party
        end

        if metadata.key?(:openid_provider) || metadata.key?("openid_provider")
          return :openid_provider
        end

        :openid_relying_party
      end

      def validate_configuration(config)
        raise ConfigurationError, "Issuer is required. Configure with OmniauthOpenidFederation::FederationEndpoint.configure" if StringHelpers.blank?(config.issuer)
        raise ConfigurationError, "Private key is required. Configure with OmniauthOpenidFederation::FederationEndpoint.configure" if config.private_key.nil?
        raise ConfigurationError, "JWKS is required. Configure with OmniauthOpenidFederation::FederationEndpoint.configure" if StringHelpers.blank?(config.jwks)
        raise ConfigurationError, "Metadata is required. Configure with OmniauthOpenidFederation::FederationEndpoint.configure" if StringHelpers.blank?(config.metadata)
      end

      def resolve_current_jwks(config)
        return config.current_jwks if config.current_jwks
        return config.current_jwks_proc.call if config.current_jwks_proc
        config.jwks # Fall back to entity statement JWKS
      end

      def resolve_signed_jwks_payload(config)
        return config.signed_jwks_payload if config.signed_jwks_payload
        return config.signed_jwks_payload_proc.call if config.signed_jwks_payload_proc
        config.jwks # Fall back to entity statement JWKS
      end

      def extract_kid_from_jwks(jwks)
        keys = jwks["keys"] || jwks[:keys] || []
        return nil if keys.empty?
        first_key = keys.first
        first_key["kid"] || first_key[:kid]
      end

      def generate_subordinate_statement(subject_entity_id:, subject_metadata: nil, metadata_policy: nil, constraints: nil, source_endpoint: nil)
        config = configuration
        validate_configuration(config)

        entity_type = detect_entity_type(config.metadata)
        unless entity_type == :openid_provider
          raise ConfigurationError, "Subordinate statements can only be generated by openid_provider entities. Current entity type: #{entity_type}"
        end

        op_metadata = config.metadata[:openid_provider] || config.metadata["openid_provider"] || {}
        fetch_endpoint = op_metadata[:federation_fetch_endpoint] || op_metadata["federation_fetch_endpoint"] ||
          "#{config.issuer}/.well-known/openid-federation/fetch"

        metadata = subject_metadata || {}

        builder = Federation::EntityStatementBuilder.new(
          issuer: config.issuer,
          subject: subject_entity_id,
          private_key: config.private_key,
          jwks: config.jwks,
          metadata: metadata,
          expiration_seconds: config.expiration_seconds || 86400,
          kid: config.kid,
          metadata_policy: metadata_policy,
          constraints: constraints,
          source_endpoint: source_endpoint || fetch_endpoint
        )

        builder.build
      end

      # Configuration class for FederationEndpoint
      # Supports automatic key provisioning with separate signing and encryption keys
      # Supports both openid_provider (OP) and openid_relying_party (RP) entity types
      class Configuration
        attr_accessor :issuer, :subject, :private_key, :jwks, :metadata, :expiration_seconds, :kid
        # Entity type configuration
        attr_accessor :entity_type # :openid_provider or :openid_relying_party
        # Automatic key provisioning configuration
        attr_accessor :signing_key, :encryption_key, :auto_provision_keys, :entity_statement_path, :key_rotation_period
        # JWKS endpoint configuration
        attr_accessor :current_jwks, :current_jwks_proc
        # Signed JWKS endpoint configuration
        attr_accessor :signed_jwks_payload, :signed_jwks_payload_proc, :signed_jwks_expiration_seconds, :signed_jwks_signing_kid
        # Caching configuration
        attr_accessor :jwks_cache_ttl
        # Fetch Endpoint configuration (for serving Subordinate Statements)
        attr_accessor :subordinate_statements, :subordinate_statements_proc
        # Authority hints configuration (for Entity Configuration)
        attr_accessor :authority_hints

        def initialize
          @issuer = nil
          @subject = nil
          @private_key = nil # Signing key (DEV/TESTING: can be same as encryption, PRODUCTION: use separate signing_key)
          @jwks = nil
          @metadata = nil
          @expiration_seconds = 86400 # 24 hours
          @kid = nil
          # Entity type configuration
          @entity_type = :openid_relying_party # Default to RP (primary use case)
          # Automatic key provisioning defaults
          @signing_key = nil # RECOMMENDED: Separate signing key for production
          @encryption_key = nil # RECOMMENDED: Separate encryption key for production
          @auto_provision_keys = true # Enable automatic key provisioning
          @entity_statement_path = nil # Path to cached entity statement (supports automatic key rotation)
          @key_rotation_period = nil # Key rotation period in seconds (nil = no automatic rotation)
          # JWKS endpoint defaults
          @current_jwks = nil
          @current_jwks_proc = nil
          # Signed JWKS endpoint defaults
          @signed_jwks_payload = nil
          @signed_jwks_payload_proc = nil
          @signed_jwks_expiration_seconds = 86400 # 24 hours
          @signed_jwks_signing_kid = nil
          # Caching defaults
          @jwks_cache_ttl = 3600 # 1 hour
          # Fetch Endpoint defaults
          @subordinate_statements = nil # Hash of subject_entity_id => {metadata, metadata_policy, constraints}
          @subordinate_statements_proc = nil # Proc that takes subject_entity_id and returns Subordinate Statement JWT
        end
      end
    end
  end
end
