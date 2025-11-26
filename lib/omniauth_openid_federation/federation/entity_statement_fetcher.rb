require_relative "entity_statement"
require_relative "../logger"
require_relative "../errors"
require_relative "../http_client"
require_relative "../utils"

# Entity Statement Fetcher abstraction for OpenID Federation
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Provides a pluggable interface for fetching entity statements from various sources.
# This abstraction improves testability and allows different fetching strategies.
module OmniauthOpenidFederation
  module Federation
    module EntityStatementFetcher
      # Base class for entity statement fetchers
      # Subclasses must implement #fetch_entity_statement
      class Base
        # Get the entity statement (cached)
        #
        # @return [EntityStatement] The entity statement instance
        def entity_statement
          @entity_statement ||= begin
            content = fetch_entity_statement
            EntityStatement.new(content)
          end
        end

        # Reload the entity statement (clear cache)
        #
        # @return [void]
        def reload!
          @entity_statement = nil
        end

        private

        # Fetch the entity statement content
        # Must be implemented by subclasses
        #
        # @return [String] The entity statement JWT string
        # @raise [NotImplementedError] If not implemented by subclass
        def fetch_entity_statement
          raise NotImplementedError, "#{self.class} must implement #fetch_entity_statement"
        end
      end

      # Fetches entity statement from a federation URL
      class UrlFetcher < Base
        attr_reader :entity_statement_url, :fingerprint, :timeout

        # Initialize URL fetcher
        #
        # @param entity_statement_url [String] The URL to fetch from
        # @param fingerprint [String, nil] Expected SHA-256 fingerprint for verification
        # @param timeout [Integer] HTTP timeout in seconds (default: 10)
        def initialize(entity_statement_url, fingerprint: nil, timeout: 10)
          @entity_statement_url = entity_statement_url
          @fingerprint = fingerprint
          @timeout = timeout
        end

        private

        def fetch_entity_statement
          OmniauthOpenidFederation::Logger.debug("[EntityStatementFetcher::UrlFetcher] Fetching entity statement from #{Utils.sanitize_uri(@entity_statement_url)}")

          begin
            response = HttpClient.get(@entity_statement_url, timeout: @timeout)
          rescue OmniauthOpenidFederation::NetworkError => e
            sanitized_uri = Utils.sanitize_uri(@entity_statement_url)
            OmniauthOpenidFederation::Logger.error("[EntityStatementFetcher::UrlFetcher] Failed to fetch entity statement from #{sanitized_uri}: #{e.message}")
            raise FetchError, "Failed to fetch entity statement from #{sanitized_uri}: #{e.message}", e.backtrace
          end

          unless response.status.success?
            sanitized_uri = Utils.sanitize_uri(@entity_statement_url)
            error_msg = "Failed to fetch entity statement from #{sanitized_uri}: HTTP #{response.status}"
            OmniauthOpenidFederation::Logger.error("[EntityStatementFetcher::UrlFetcher] #{error_msg}")
            raise FetchError, error_msg
          end

          entity_statement_content = response.body.to_s

          # Validate fingerprint if provided
          if @fingerprint
            temp_statement = EntityStatement.new(entity_statement_content)
            calculated_fingerprint = temp_statement.calculate_fingerprint
            unless calculated_fingerprint == @fingerprint
              error_msg = "Entity statement fingerprint mismatch. Expected: #{@fingerprint}, Got: #{calculated_fingerprint}"
              OmniauthOpenidFederation::Logger.error("[EntityStatementFetcher::UrlFetcher] #{error_msg}")
              # Instrument fingerprint mismatch
              OmniauthOpenidFederation::Instrumentation.notify_fingerprint_mismatch(
                entity_statement_url: @entity_statement_url,
                expected_fingerprint: @fingerprint,
                calculated_fingerprint: calculated_fingerprint
              )
              raise ValidationError, error_msg
            end
          end

          entity_statement_content
        end
      end

      # Fetches entity statement from a local file
      class FileFetcher < Base
        attr_reader :file_path

        # Initialize file fetcher
        #
        # @param file_path [String] Path to the entity statement file
        # @param allowed_dirs [Array<String>, nil] Allowed directories for path validation (default: Rails.root/config if Rails available)
        def initialize(file_path, allowed_dirs: nil)
          @file_path = file_path
          @allowed_dirs = allowed_dirs || ((defined?(Rails) && Rails.root) ? [Rails.root.join("config").to_s] : nil)
        end

        private

        def fetch_entity_statement
          # Validate file path to prevent path traversal
          validated_path = Utils.validate_file_path!(
            @file_path,
            allowed_dirs: @allowed_dirs
          )

          unless File.exist?(validated_path)
            sanitized_path = Utils.sanitize_path(validated_path)
            OmniauthOpenidFederation::Logger.warn("[EntityStatementFetcher::FileFetcher] Entity statement file not found: #{sanitized_path}")
            raise FetchError, "Entity statement file not found: #{sanitized_path}"
          end

          OmniauthOpenidFederation::Logger.debug("[EntityStatementFetcher::FileFetcher] Loading entity statement from file: #{Utils.sanitize_path(validated_path)}")
          File.read(validated_path).strip
        rescue SecurityError => e
          OmniauthOpenidFederation::Logger.error("[EntityStatementFetcher::FileFetcher] #{e.message}")
          raise FetchError, e.message, e.backtrace
        end
      end
    end
  end
end
