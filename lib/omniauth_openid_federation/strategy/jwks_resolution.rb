module OmniauthOpenidFederation
  module Strategy
    module JwksResolution
      private

      def resolve_jwks_for_validation(normalized_options)
        entity_statement_content = load_provider_entity_statement

        # 1. Extract JWKS directly from entity statement (we already have it - no HTTP request needed)
        if entity_statement_content
          begin
            entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
            parsed = entity_statement.parse
            if parsed && parsed[:jwks]
              entity_jwks = parsed[:jwks]
              # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
              if entity_jwks.is_a?(Hash) && entity_jwks.key?("keys")
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return entity_jwks
              elsif entity_jwks.is_a?(Hash) && entity_jwks.key?(:keys)
                # Convert symbol keys to string keys
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return {"keys" => entity_jwks[:keys]}
              elsif entity_jwks.is_a?(Array)
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return {"keys" => entity_jwks}
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not extract JWKS from entity statement: #{e.message}")
          end
        end

        # 2. Try to fetch from signed JWKS (if entity statement has signed_jwks_uri)
        if entity_statement_content
          begin
            parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
              entity_statement_content
            )
            if parsed && parsed[:signed_jwks_uri] && parsed[:entity_jwks]
              OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching signed JWKS for ID token validation")
              signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
                parsed[:signed_jwks_uri],
                parsed[:entity_jwks]
              )
              # Ensure it's in the format expected by JWT.decode
              if signed_jwks.is_a?(Hash) && signed_jwks.key?("keys")
                return signed_jwks
              elsif signed_jwks.is_a?(Hash) && signed_jwks.key?(:keys)
                return {"keys" => signed_jwks[:keys]}
              elsif signed_jwks.is_a?(Array)
                return {"keys" => signed_jwks}
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not fetch signed JWKS: #{e.message}")
          end
        end

        # 3. Fallback: Fetch from standard JWKS URI (only if entity statement doesn't have JWKS)
        jwks_uri = resolve_jwks_uri(normalized_options)
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching JWKS from URI: #{OmniauthOpenidFederation::Utils.sanitize_uri(jwks_uri)}")
          begin
            return fetch_jwks(jwks_uri)
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to fetch JWKS from URI: #{e.message}")
          end
        end

        # No JWKS found
        nil
      end

      def resolve_jwks_for_validation_with_kid(normalized_options, kid)
        entity_statement_content = load_provider_entity_statement
        first_valid_jwks = nil # Track first valid JWKS in case kid is not found

        # 1. Try entity statement JWKS first (fastest, no HTTP request)
        if entity_statement_content
          begin
            entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
            parsed = entity_statement.parse
            if parsed && parsed[:jwks]
              entity_jwks = parsed[:jwks]
              # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
              jwks_hash = if entity_jwks.is_a?(Hash) && entity_jwks.key?("keys")
                entity_jwks
              elsif entity_jwks.is_a?(Hash) && entity_jwks.key?(:keys)
                {"keys" => entity_jwks[:keys]}
              elsif entity_jwks.is_a?(Array)
                {"keys" => entity_jwks}
              end

              keys = jwks_hash&.dig("keys")
              if keys&.is_a?(Array) && !keys.empty?
                # Track first valid JWKS
                first_valid_jwks ||= jwks_hash
                # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
                if kid.nil?
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning entity statement JWKS for validation attempt")
                  return jwks_hash
                end
                # Check if kid is in this JWKS
                key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
                if key_data
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in entity statement JWKS")
                  return jwks_hash
                else
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in entity statement JWKS, trying signed JWKS")
                end
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not extract JWKS from entity statement: #{e.message}")
          end
        end

        # 2. Try signed JWKS (if entity statement has signed_jwks_uri)
        # This is more likely to have the latest keys during key rotation
        if entity_statement_content
          begin
            parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
              entity_statement_content
            )
            if parsed && parsed[:signed_jwks_uri] && parsed[:entity_jwks]
              OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching signed JWKS for ID token validation (kid: #{kid})")
              signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
                parsed[:signed_jwks_uri],
                parsed[:entity_jwks]
              )
              # Ensure it's in the format expected by JWT.decode
              jwks_hash = if signed_jwks.is_a?(Hash) && signed_jwks.key?("keys")
                signed_jwks
              elsif signed_jwks.is_a?(Hash) && signed_jwks.key?(:keys)
                {"keys" => signed_jwks[:keys]}
              elsif signed_jwks.is_a?(Array)
                {"keys" => signed_jwks}
              end

              keys = jwks_hash&.dig("keys")
              if keys&.is_a?(Array) && !keys.empty?
                # Track first valid JWKS
                first_valid_jwks ||= jwks_hash
                # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
                if kid.nil?
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning signed JWKS for validation attempt")
                  return jwks_hash
                end
                # Check if kid is in this JWKS
                key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
                if key_data
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in signed JWKS")
                  return jwks_hash
                else
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in signed JWKS, trying standard JWKS URI")
                end
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not fetch signed JWKS: #{e.message}")
          end
        end

        # 3. Fallback: Fetch from standard JWKS URI
        jwks_uri = resolve_jwks_uri(normalized_options)
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching JWKS from URI for kid '#{kid}': #{OmniauthOpenidFederation::Utils.sanitize_uri(jwks_uri)}")
          begin
            jwks_hash = fetch_jwks(jwks_uri)
            keys = jwks_hash&.dig("keys")
            if keys&.is_a?(Array) && !keys.empty?
              # Track first valid JWKS
              first_valid_jwks ||= jwks_hash
              # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
              if kid.nil?
                OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning standard JWKS URI for validation attempt")
                return jwks_hash
              end
              # Check if kid is in this JWKS
              key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
              if key_data
                OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in standard JWKS URI")
                return jwks_hash
              else
                OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in standard JWKS URI")
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to fetch JWKS from URI: #{e.message}")
          end
        end

        # If we found valid JWKS but kid was not found, return it anyway
        # This allows the decoding to fail with "kid not found" instead of "JWKS not available"
        if first_valid_jwks && kid
          OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in any JWKS source, but returning first valid JWKS for validation attempt")
          return first_valid_jwks
        end

        # No JWKS found
        nil
      end

      def resolve_jwks_uri(normalized_options)
        # 1. Try client_options first
        jwks_uri = normalized_options[:jwks_uri] || normalized_options["jwks_uri"]
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          # Build full URL if it's a path
          if jwks_uri.start_with?("http://", "https://")
            return jwks_uri
          else
            base_url = build_base_url(normalized_options)
            return build_endpoint(base_url, jwks_uri) if base_url
          end
        end

        # 2. Try to resolve from entity statement
        if options.entity_statement_path
          begin
            resolved_endpoints = resolve_endpoints_from_metadata(normalized_options)
            jwks_uri = resolved_endpoints[:jwks_uri] if resolved_endpoints[:jwks_uri]
            if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved JWKS URI from entity statement: #{jwks_uri}")
              return jwks_uri
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get JWKS URI from entity statement: #{e.message}")
          end
        end

        # 3. Try to get from OpenID Connect client
        begin
          if client.respond_to?(:jwks_uri) && client.jwks_uri
            jwks_uri = client.jwks_uri.to_s
            if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS URI from client: #{jwks_uri}")
              return jwks_uri
            end
          end
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get JWKS URI from client: #{e.message}")
        end

        # No JWKS URI found
        nil
      end

      def fetch_jwks(jwks_uri)
        # Use our JWKS fetching logic
        # Returns a hash with "keys" array that JWT.decode can use directly
        jwks = OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)

        # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
        if jwks.is_a?(Hash) && jwks.key?("keys")
          # Already in correct format - JWT.decode accepts this directly
          jwks
        elsif jwks.is_a?(Array)
          # If it's an array of keys, wrap it in a hash
          {"keys" => jwks}
        else
          # Fallback: wrap in keys array
          {"keys" => [jwks].compact}
        end
      end
    end
  end
end
