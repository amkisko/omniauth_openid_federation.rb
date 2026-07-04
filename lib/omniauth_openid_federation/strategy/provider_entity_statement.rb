module OmniauthOpenidFederation
  module Strategy
    module ProviderEntityStatement
      private

      def resolve_entity_statement_path(path)
        if path.start_with?("/")
          path
        elsif defined?(Rails) && Rails.root
          Rails.root.join(path).to_s
        else
          File.expand_path(path)
        end
      end

      def load_provider_entity_statement
        # Priority 1: Use file path if provided
        if OmniauthOpenidFederation::StringHelpers.present?(options.entity_statement_path)
          path = resolve_entity_statement_path(options.entity_statement_path)
          if File.exist?(path)
            OmniauthOpenidFederation::Logger.debug("[Strategy] Loading provider entity statement from file: #{path}")
            return File.read(path).strip
          else
            OmniauthOpenidFederation::Logger.warn("[Strategy] Provider entity statement file not found: #{path}, will try to fetch from URL")
          end
        end

        # Priority 2: Fetch from URL if provided
        if OmniauthOpenidFederation::StringHelpers.present?(options.entity_statement_url)
          return fetch_and_cache_entity_statement(
            options.entity_statement_url,
            fingerprint: options.entity_statement_fingerprint
          )
        end

        # Priority 3: Fetch from issuer if provided (only if issuer is a valid URL)
        if OmniauthOpenidFederation::StringHelpers.present?(options.issuer)
          # Check that issuer is a valid URL format before trying to fetch
          # Note: Config values are trusted, only basic format check needed
          begin
            parsed_issuer = URI.parse(options.issuer)
            unless parsed_issuer.is_a?(URI::HTTP) || parsed_issuer.is_a?(URI::HTTPS)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Issuer is not a valid HTTP/HTTPS URL, skipping entity statement fetch from URL: #{options.issuer}")
              return nil
            end
          rescue URI::InvalidURIError
            OmniauthOpenidFederation::Logger.debug("[Strategy] Issuer is not a valid URL, skipping entity statement fetch from URL: #{options.issuer}")
            return nil
          end

          entity_statement_url = OmniauthOpenidFederation::Utils.build_entity_statement_url(options.issuer)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Building entity statement URL from issuer: #{entity_statement_url}")
          return fetch_and_cache_entity_statement(
            entity_statement_url,
            fingerprint: options.entity_statement_fingerprint
          )
        end

        nil
      end

      def fetch_and_cache_entity_statement(url, fingerprint: nil)
        cache_key = "federation:provider_entity_statement:#{Digest::SHA256.hexdigest(url)}"

        # Check cache first (if Rails.cache is available)
        if defined?(Rails) && Rails.cache
          begin
            cached = Rails.cache.read(cache_key)
            if cached
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using cached provider entity statement from: #{url}")
              return cached
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Cache read failed, fetching fresh: #{e.message}")
          end
        end

        # Fetch from URL
        OmniauthOpenidFederation::Logger.info("[Strategy] Fetching provider entity statement from: #{url}")
        begin
          statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            url,
            fingerprint: fingerprint,
            timeout: 10
          )

          entity_statement_content = statement.entity_statement

          # Cache the fetched statement (if Rails.cache is available)
          if defined?(Rails) && Rails.cache
            begin
              # Cache for 1 hour (entity statements typically expire after 24 hours)
              Rails.cache.write(cache_key, entity_statement_content, expires_in: 3600)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Cached provider entity statement from: #{url}")
            rescue => e
              OmniauthOpenidFederation::Logger.debug("[Strategy] Cache write failed: #{e.message}")
            end
          end

          entity_statement_content
        rescue OmniauthOpenidFederation::FetchError, OmniauthOpenidFederation::ValidationError => e
          error_msg = "Failed to fetch provider entity statement from #{url}: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end
      end

      def load_metadata_for_key_extraction
        entity_statement_content = load_provider_entity_statement
        return nil unless entity_statement_content

        begin
          # Parse entity statement to extract metadata and JWKS from content
          parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
            entity_statement_content
          )

          return nil unless parsed && parsed[:metadata]

          # Return metadata in format expected by KeyExtractor
          # KeyExtractor expects metadata hash that may contain JWKS
          metadata = parsed[:metadata]
          entity_jwks = parsed[:entity_jwks] || metadata[:jwks] || {}

          # Return metadata with JWKS included
          metadata.merge(jwks: entity_jwks)
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to load metadata from entity statement for key extraction: #{e.message}")
          nil
        end
      end
    end
  end
end
