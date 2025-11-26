require_relative "../utils"
require_relative "../logger"
require_relative "../errors"
require_relative "../configuration"
require_relative "entity_statement"

# Helper methods for entity statement operations
module OmniauthOpenidFederation
  module Federation
    module EntityStatementHelper
      # Parse entity statement and extract signed_jwks_uri and entity_jwks
      # This is a common operation used in multiple places
      #
      # @param entity_statement_path [String] Path to entity statement file
      # @return [Hash] Hash with :signed_jwks_uri and :entity_jwks keys, or nil if not found
      # @raise [SecurityError] If path validation fails
      # @raise [ValidationError] If parsing fails
      def self.parse_for_signed_jwks(entity_statement_path)
        # Determine allowed directories for file path validation
        config = Configuration.config
        allowed_dirs = if defined?(Rails) && Rails.root
          [Rails.root.join("config").to_s]
        elsif config.root_path
          [File.join(config.root_path, "config")]
        end

        # Validate file path to prevent path traversal
        validated_path = Utils.validate_file_path!(
          entity_statement_path,
          allowed_dirs: allowed_dirs
        )

        unless File.exist?(validated_path)
          sanitized_path = Utils.sanitize_path(validated_path)
          OmniauthOpenidFederation::Logger.warn("[EntityStatementHelper] Entity statement file not found: #{sanitized_path}")
          return nil
        end

        begin
          entity_statement_content = File.read(validated_path)
          entity_statement = EntityStatement.new(entity_statement_content)
          metadata = entity_statement.parse

          signed_jwks_uri = metadata.dig(:metadata, :openid_provider, :signed_jwks_uri)
          entity_jwks = metadata[:jwks]

          {
            signed_jwks_uri: signed_jwks_uri,
            entity_jwks: entity_jwks,
            metadata: metadata
          }
        rescue => e
          sanitized_path = Utils.sanitize_path(validated_path)
          OmniauthOpenidFederation::Logger.error("[EntityStatementHelper] Failed to parse entity statement from #{sanitized_path}: #{e.class} - #{e.message}")
          raise ValidationError, "Failed to parse entity statement: #{e.message}", e.backtrace
        end
      end

      # Parse entity statement from content string (JWT)
      # This is used when entity statement is fetched from URL and cached in memory
      #
      # @param entity_statement_content [String] Entity statement JWT string
      # @return [Hash] Hash with :signed_jwks_uri and :entity_jwks keys, or nil if not found
      # @raise [ValidationError] If parsing fails
      def self.parse_for_signed_jwks_from_content(entity_statement_content)
        return nil unless entity_statement_content&.is_a?(String)

        begin
          entity_statement = EntityStatement.new(entity_statement_content)
          metadata = entity_statement.parse

          signed_jwks_uri = metadata.dig(:metadata, :openid_provider, :signed_jwks_uri)
          entity_jwks = metadata[:jwks]

          {
            signed_jwks_uri: signed_jwks_uri,
            entity_jwks: entity_jwks,
            metadata: metadata
          }
        rescue => e
          OmniauthOpenidFederation::Logger.error("[EntityStatementHelper] Failed to parse entity statement from content: #{e.class} - #{e.message}")
          raise ValidationError, "Failed to parse entity statement: #{e.message}", e.backtrace
        end
      end
    end
  end
end
