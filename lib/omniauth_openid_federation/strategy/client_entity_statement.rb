module OmniauthOpenidFederation
  module Strategy
    module ClientEntityStatement
      private

      def load_client_entity_statement(entity_statement_path = nil, entity_statement_url = nil)
        # Priority 1: Use file path if provided (for manual cache, development, debugging)
        if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
          return load_client_entity_statement_from_file(entity_statement_path)
        end

        # Priority 2: Check cache (if Rails.cache is available)
        # This respects background job cache refresh and key rotation
        if defined?(Rails) && Rails.cache
          cache_key = "federation:entity_statement"
          config = OmniauthOpenidFederation::FederationEndpoint.configuration

          # Use cache TTL based on entity statement expiration or default to 1 hour
          # The entity statement JWT itself has an expiration, but we cache it for performance
          # Cache TTL should be shorter than JWT expiration to ensure fresh keys
          cache_ttl = config.jwks_cache_ttl || 3600 # Default to 1 hour, same as JWKS cache

          begin
            cached_statement = Rails.cache.fetch(cache_key, expires_in: cache_ttl) do
              # Generate and cache if not in cache
              entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
              OmniauthOpenidFederation::Logger.debug("[Strategy] Generated and cached client entity statement")
              entity_statement
            end

            if cached_statement
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using cached client entity statement")
              return cached_statement
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Cache fetch failed, generating fresh entity statement: #{e.message}")
            # Fall through to generate dynamically
          end
        end

        # Priority 3: Generate dynamically (always available)
        # The entity statement is always generated via FederationEndpoint
        begin
          entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
          OmniauthOpenidFederation::Logger.debug("[Strategy] Generated client entity statement dynamically")
          entity_statement
        rescue OmniauthOpenidFederation::ConfigurationError => e
          # FederationEndpoint not configured - provide helpful error message
          error_msg = "Failed to generate client entity statement: #{e.message}. " \
                      "Either configure OmniauthOpenidFederation::FederationEndpoint.configure " \
                      "or provide client_entity_statement_path for manual cache/dev/debug."
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        rescue => e
          error_msg = "Failed to generate client entity statement: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end
      end

      def load_client_entity_statement_from_file(entity_statement_path)
        # Resolve path (relative to Rails root if available)
        path = if entity_statement_path.start_with?("/")
          entity_statement_path
        elsif defined?(Rails) && Rails.root
          Rails.root.join(entity_statement_path).to_s
        else
          File.expand_path(entity_statement_path)
        end

        unless File.exist?(path)
          error_msg = "Client entity statement file not found: #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement = File.read(path)
        unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement)
          error_msg = "Client entity statement file is empty: #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        # Validate it's a JWT (has 3 parts)
        jwt_parts = entity_statement.strip.split(".")
        unless jwt_parts.length == 3
          error_msg = "Client entity statement is not a valid JWT (expected 3 parts, got #{jwt_parts.length}): #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement.strip
      end

      def load_client_entity_statement_from_url(entity_statement_url)
        response = HttpClient.get(entity_statement_url)
        unless response.status.success?
          error_msg = "Failed to fetch client entity statement from #{entity_statement_url}: HTTP #{response.status}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement = response.body.to_s
        unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement)
          error_msg = "Client entity statement from URL is empty: #{entity_statement_url}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        # Validate it's a JWT (has 3 parts)
        jwt_parts = entity_statement.strip.split(".")
        unless jwt_parts.length == 3
          error_msg = "Client entity statement from URL is not a valid JWT (expected 3 parts, got #{jwt_parts.length}): #{entity_statement_url}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement.strip
      rescue OmniauthOpenidFederation::NetworkError => e
        error_msg = "Failed to fetch client entity statement from #{entity_statement_url}: #{e.message}"
        OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
        raise OmniauthOpenidFederation::ConfigurationError, error_msg
      end

      def extract_client_jwk_signing_key
        # Access raw options hash to avoid recursion (don't call options method which triggers extraction)
        raw_opts = @options || {}

        # If explicit JWKS is provided, use it
        return raw_opts[:client_jwk_signing_key] if OmniauthOpenidFederation::StringHelpers.present?(raw_opts[:client_jwk_signing_key])

        # Entity statement is always available (either from file or generated dynamically)
        begin
          entity_statement_content = load_client_entity_statement(
            raw_opts[:client_entity_statement_path],
            raw_opts[:client_entity_statement_url]
          )
          return nil unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement_content)

          # Extract JWKS from client entity statement
          jwt_parts = entity_statement_content.split(".")
          return nil if jwt_parts.length != 3

          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          entity_jwks = payload.fetch("jwks", {})
          return nil if entity_jwks.empty?

          # Return JWKS as JSON string (format expected by openid_connect gem)
          JSON.dump(entity_jwks)
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to extract client JWKS from entity statement: #{e.message}")
          nil
        end
      end

      def extract_entity_identifier_from_statement(entity_statement, configured_identifier = nil)
        # Use configured identifier if provided
        return configured_identifier if OmniauthOpenidFederation::StringHelpers.present?(configured_identifier)

        # Extract from entity statement
        begin
          jwt_parts = entity_statement.split(".")
          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          entity_identifier = payload["sub"] || payload[:sub]
          return entity_identifier if OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)

          # Fallback to issuer if sub is not present
          entity_identifier = payload["iss"] || payload[:iss]
          return entity_identifier if OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)

          OmniauthOpenidFederation::Logger.warn("[Strategy] Could not extract entity identifier from entity statement (no 'sub' or 'iss' claim)")
          nil
        rescue => e
          OmniauthOpenidFederation::Logger.error("[Strategy] Failed to extract entity identifier from entity statement: #{e.message}")
          nil
        end
      end

      def load_provider_metadata_for_encryption
        entity_statement_content = load_provider_entity_statement
        return nil unless entity_statement_content

        begin
          # Decode entity statement payload to get all provider metadata fields
          # EntityStatement.parse only extracts specific fields, so we need to access raw payload
          jwt_parts = entity_statement_content.split(".")
          return nil if jwt_parts.length != 3

          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          metadata_section = payload.fetch("metadata", {})
          provider_metadata = metadata_section.fetch("openid_provider", {})
          entity_jwks = payload.fetch("jwks", {})

          # Combine provider metadata with entity JWKS for encryption
          # Note: Provider's encryption requirements would be in their discovery document,
          # but we can also check client metadata as a fallback
          {
            "request_object_encryption_alg" => provider_metadata["request_object_encryption_alg"] ||
              provider_metadata[:request_object_encryption_alg],
            "request_object_encryption_enc" => provider_metadata["request_object_encryption_enc"] ||
              provider_metadata[:request_object_encryption_enc],
            "jwks" => entity_jwks
          }
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not load provider metadata for encryption: #{e.message}")
          nil
        end
      end
    end
  end
end
