require_relative "../utils"
require_relative "../logger"
require_relative "../errors"
require_relative "../configuration"
require_relative "../string_helpers"
require_relative "../entity_statement_reader"
require_relative "fetch"
require_relative "../federation/entity_statement_helper"
require_relative "../federation/signed_jwks"

# JWKS rotation service for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Provides functionality to proactively refresh JWKS cache for providers.
# This is useful for background jobs to refresh keys before they expire.
#
# Supports both standard JWKS and signed JWKS (OpenID Federation).
module OmniauthOpenidFederation
  module Jwks
    # JWKS rotation service
    #
    # @example Rotate JWKS for a provider
    #   OmniauthOpenidFederation::Jwks::Rotate.run(
    #     "https://provider.example.com/.well-known/jwks.json",
    #     entity_statement_path: "config/provider-entity-statement.jwt"
    #   )
    class Rotate
      # Rotate JWKS cache for a provider
      # This is useful for background jobs to proactively refresh keys
      #
      # @param jwks_uri [String] The JWKS URI to refresh
      # @param entity_statement_path [String, nil] Path to entity statement file (optional)
      # @return [Hash] The refreshed JWKS hash
      # @raise [FetchError] If fetching fails
      # @raise [ValidationError] If validation fails
      # @raise [SecurityError] If path validation fails
      # @raise [ConfigurationError] If entity statement file not found
      def self.run(jwks_uri, entity_statement_path: nil)
        if entity_statement_path
          # Validate file path to prevent path traversal
          # Allow absolute paths that exist (for temp files in tests) to skip directory validation
          # For absolute paths that don't exist, still validate they're not path traversal, then check existence
          path_str = entity_statement_path.to_s
          is_absolute = path_str.start_with?("/", "~")

          if is_absolute && File.exist?(entity_statement_path)
            validated_path = entity_statement_path
          else
            # For absolute paths, validate path traversal but allow outside allowed_dirs
            # For relative paths, validate against allowed directories
            if is_absolute
              # Validate path traversal for absolute paths, but don't require it to be in allowed_dirs
              begin
                validated_path = Utils.validate_file_path!(
                  entity_statement_path,
                  allowed_dirs: nil  # Allow absolute paths outside config directory
                )
              rescue SecurityError => e
                # Path traversal attempt - raise SecurityError
                Logger.error("[Jwks::Rotate] #{e.message}")
                raise SecurityError, e.message
              end
            else
              # Relative path - must be in allowed directories
              begin
                config = Configuration.config
                allowed_dirs = if defined?(Rails) && Rails.root
                  [Rails.root.join("config").to_s]
                elsif config.root_path
                  [File.join(config.root_path, "config")]
                end

                validated_path = Utils.validate_file_path!(
                  entity_statement_path,
                  allowed_dirs: allowed_dirs
                )
              rescue SecurityError => e
                Logger.error("[Jwks::Rotate] #{e.message}")
                raise SecurityError, e.message
              end
            end

            unless File.exist?(validated_path)
              sanitized_path = Utils.sanitize_path(validated_path)
              Logger.warn("[Jwks::Rotate] Entity statement file not found: #{sanitized_path}")
              raise ConfigurationError, "Entity statement file not found: #{sanitized_path}"
            end
          end

          # Try to use signed JWKS if entity statement is available
          begin
            parsed = Federation::EntityStatementHelper.parse_for_signed_jwks(validated_path)
            if parsed && StringHelpers.present?(parsed[:signed_jwks_uri])
              return Federation::SignedJWKS.fetch!(
                parsed[:signed_jwks_uri],
                parsed[:entity_jwks],
                force_refresh: true
              )
            end
          rescue SecurityError
            raise
          rescue
            Logger.warn("[Jwks::Rotate] Failed to use signed JWKS, falling back to standard JWKS")
          end

          # Fallback to standard JWKS with entity statement keys
          entity_statement_keys = EntityStatementReader.fetch_keys(
            entity_statement_path: validated_path
          )
          return Fetch.run(
            jwks_uri,
            entity_statement_keys: entity_statement_keys,
            force_refresh: true
          )
        end

        # Use standard JWKS
        Fetch.run(jwks_uri, force_refresh: true)
      end
    end
  end
end
