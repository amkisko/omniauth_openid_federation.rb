require "jwt"
require "digest"
require "base64"
require_relative "key_extractor"
require_relative "utils"
require_relative "configuration"
require_relative "logger"

# Entity Statement Reader for OpenID Federation 1.0
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.net/specs/openid-federation-1_0.html#section-3 Section 3: Entity Statement
#
# Entity statements are self-signed JWTs that contain provider metadata and JWKS.
# This class provides utilities for:
# - Extracting JWKS from entity statements for validating signed JWKS
# - Parsing provider metadata from entity statements
# - Validating entity statement fingerprints (SHA-256 hash)
#
# Entity statements are typically fetched from /.well-known/openid-federation endpoint
# and stored locally for use in validating signed JWKS and extracting provider configuration.
module OmniauthOpenidFederation
  class EntityStatementReader
    # Standard JWT has 3 parts: header.payload.signature
    JWT_PARTS_COUNT = 3

    class << self
      # Fetch JWKS keys from entity statement
      #
      # @param entity_statement_path [String, nil] Path to entity statement file
      # @return [Array<Hash>] Array of JWK hash objects
      def fetch_keys(entity_statement_path: nil)
        entity_statement = load_entity_statement(entity_statement_path)
        return [] if entity_statement.nil? || entity_statement.empty?

        # Decode self-signed entity statement
        # Entity statements are self-signed, so we validate using their own JWKS
        # First, decode without validation to get the JWKS
        jwt_parts = entity_statement.split(".")
        return [] if jwt_parts.length != JWT_PARTS_COUNT

        # Decode payload (second part)
        payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))

        # Extract JWKS from entity statement claims
        payload.fetch("jwks", {}).fetch("keys", [])

        # Return JWK hashes directly (no need to convert to objects)
      end

      # Parse provider metadata from entity statement
      #
      # @param entity_statement_path [String, nil] Path to entity statement file
      # @return [Hash, nil] Hash with provider metadata or nil if not found
      def parse_metadata(entity_statement_path: nil)
        entity_statement = load_entity_statement(entity_statement_path)
        return nil if entity_statement.nil? || entity_statement.empty?

        # Decode JWT payload
        jwt_parts = entity_statement.split(".")
        return nil if jwt_parts.length != JWT_PARTS_COUNT

        claims = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))

        # Extract provider metadata
        metadata = claims.fetch("metadata", {})
        provider_metadata = metadata.fetch("openid_provider", {})

        {
          issuer: provider_metadata["issuer"],
          authorization_endpoint: provider_metadata["authorization_endpoint"],
          token_endpoint: provider_metadata["token_endpoint"],
          userinfo_endpoint: provider_metadata["userinfo_endpoint"],
          jwks_uri: provider_metadata["jwks_uri"],
          signed_jwks_uri: provider_metadata["signed_jwks_uri"],
          entity_issuer: claims["iss"],
          entity_jwks: claims.fetch("jwks", {})
        }
      end

      # Validate entity statement fingerprint
      #
      # @param entity_statement_content [String] The entity statement content
      # @param expected_fingerprint [String] The expected SHA-256 fingerprint
      # @return [Boolean] true if fingerprints match
      def validate_fingerprint(entity_statement_content, expected_fingerprint)
        calculated = Digest::SHA256.hexdigest(entity_statement_content).downcase
        expected = expected_fingerprint.downcase
        calculated == expected
      end

      private

      def load_entity_statement(entity_statement_path)
        return nil if entity_statement_path.nil? || entity_statement_path.to_s.empty?

        # Determine allowed directories for file path validation
        config = OmniauthOpenidFederation::Configuration.config
        allowed_dirs = if defined?(Rails) && Rails.root
          [Rails.root.join("config").to_s]
        elsif config.root_path
          [File.join(config.root_path, "config")]
        end

        begin
          # Validate file path to prevent path traversal attacks
          validated_path = Utils.validate_file_path!(
            entity_statement_path,
            allowed_dirs: allowed_dirs
          )

          return nil unless File.exist?(validated_path)

          File.read(validated_path)
        rescue SecurityError => e
          # Log security error but return nil to maintain backward compatibility
          Logger.warn("[EntityStatementReader] Security error: #{e.message}")
          nil
        rescue Errno::EACCES, Errno::EISDIR, Errno::ENOENT => e
          # Handle file system errors gracefully to avoid exposing file system structure
          # EACCES: Permission denied
          # EISDIR: Is a directory
          # ENOENT: No such file or directory (race condition after File.exist?)
          Logger.warn("[EntityStatementReader] File access error: #{Utils.sanitize_path(entity_statement_path)}")
          nil
        end
      end
    end
  end
end
