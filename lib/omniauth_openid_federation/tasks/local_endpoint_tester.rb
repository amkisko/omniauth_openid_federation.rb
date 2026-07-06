require "uri"
require_relative "../http_client"
require_relative "../errors"
require_relative "../federation/entity_statement"
require_relative "../jwks/fetch"
require_relative "../federation/signed_jwks"

module OmniauthOpenidFederation
  module Tasks
    module LocalEndpointTester
      def self.run(base_url:)
        entity_statement_url = "#{base_url}/.well-known/openid-federation"
        validation_warnings = []

        # Fetch and parse entity statement
        begin
          entity_statement = Federation::EntityStatement.fetch!(
            entity_statement_url,
            fingerprint: nil # Don't validate fingerprint for local testing
          )
        rescue ValidationError => e
          # Don't block execution - treat validation errors as warnings
          validation_warnings << e.message
          # Try to parse anyway for diagnostic purposes
          begin
            require "json"
            require "base64"
            response = HttpClient.get(entity_statement_url)
            entity_statement = Federation::EntityStatement.new(response.body.to_s)
          rescue
            raise FetchError, "Failed to fetch entity statement: #{e.message}"
          end
        end

        begin
          metadata = entity_statement.parse
        rescue ValidationError => e
          validation_warnings << e.message
          # Try to extract basic info even if validation fails
          begin
            require "json"
            require "base64"
            jwt_parts = entity_statement.entity_statement.split(".")
            payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
            # Preserve original structure (string keys from JSON)
            metadata = {
              issuer: payload["iss"],
              sub: payload["sub"],
              exp: payload["exp"],
              iat: payload["iat"],
              jwks: payload["jwks"],
              metadata: payload["metadata"] || {}
            }
          rescue
            raise FetchError, "Failed to parse entity statement: #{e.message}"
          end
        end

        # Extract endpoints - handle both provider and relying party entity types
        metadata_section = metadata[:metadata] || {}
        provider_metadata = metadata_section[:openid_provider] || metadata_section["openid_provider"] || {}
        rp_metadata = metadata_section[:openid_relying_party] || metadata_section["openid_relying_party"] || {}

        endpoints = {}

        # Provider endpoints
        if provider_metadata.any?
          endpoints["Authorization Endpoint"] = provider_metadata[:authorization_endpoint] || provider_metadata["authorization_endpoint"]
          endpoints["Token Endpoint"] = provider_metadata[:token_endpoint] || provider_metadata["token_endpoint"]
          endpoints["UserInfo Endpoint"] = provider_metadata[:userinfo_endpoint] || provider_metadata["userinfo_endpoint"]
          endpoints["JWKS URI"] = provider_metadata[:jwks_uri] || provider_metadata["jwks_uri"]
          endpoints["Signed JWKS URI"] = provider_metadata[:signed_jwks_uri] || provider_metadata["signed_jwks_uri"]
          endpoints["End Session Endpoint"] = provider_metadata[:end_session_endpoint] || provider_metadata["end_session_endpoint"]
        end

        # Relying Party endpoints (JWKS only)
        if rp_metadata.any?
          endpoints["JWKS URI"] ||= rp_metadata[:jwks_uri] || rp_metadata["jwks_uri"]
          endpoints["Signed JWKS URI"] ||= rp_metadata[:signed_jwks_uri] || rp_metadata["signed_jwks_uri"]
        end

        endpoints.compact!

        # Detect key configuration status
        key_status = detect_key_status(metadata[:jwks])

        # Test endpoints
        results = {}
        entity_jwks = metadata[:jwks]

        endpoints.each do |name, url|
          next unless url

          begin
            case name
            when "JWKS URI"
              jwks = Jwks::Fetch.run(url)
              key_count = jwks["keys"]&.length || 0
              results[name] = {status: :success, keys: key_count}

            when "Signed JWKS URI"
              signed_jwks = Federation::SignedJWKS.fetch!(
                url,
                entity_jwks,
                force_refresh: true
              )
              key_count = signed_jwks["keys"]&.length || 0
              results[name] = {status: :success, keys: key_count}

            else
              begin
                URI.parse(url)
              rescue URI::InvalidURIError => error
                results[name] = {status: :error, message: "Invalid URL: #{error.message}"}
                next
              end

              response = HttpClient.get(url, max_retries: 0)

              results[name] = if response.status.code < 400
                {status: :success, code: response.status.code.to_s}
              else
                {status: :warning, code: response.status.code.to_s, body: response.body.to_s}
              end
            end
          rescue FetchError, Federation::SignedJWKS::FetchError => e
            results[name] = {status: :error, message: e.message}
          rescue Federation::SignedJWKS::ValidationError => e
            results[name] = {status: :error, message: e.message}
          rescue => e
            results[name] = {status: :error, message: e.message}
          end
        end

        {
          success: true,
          entity_statement: entity_statement,
          metadata: metadata,
          results: results,
          key_status: key_status,
          validation_warnings: validation_warnings
        }
      end

      def self.detect_key_status(jwks)
        return {type: :unknown, count: 0, recommendation: "No keys found in entity statement"} unless jwks

        keys = jwks.is_a?(Hash) ? (jwks["keys"] || jwks[:keys] || []) : []
        return {type: :unknown, count: 0, recommendation: "No keys found in entity statement"} if keys.empty?

        # Check for duplicate kids (indicates single key used for both signing and encryption)
        kids = keys.map { |k| k["kid"] || k[:kid] }.compact
        duplicate_kids = kids.length != kids.uniq.length

        # Check use fields
        uses = keys.map { |k| k["use"] || k[:use] }.compact.uniq
        has_sig = uses.include?("sig")
        has_enc = uses.include?("enc")
        has_both_uses = has_sig && has_enc

        if duplicate_kids
          {
            type: :single,
            count: keys.length,
            recommendation: "⚠️  Single key detected (duplicate Key IDs). This is NOT RECOMMENDED for production. Use separate signing and encryption keys for better security. Generate with: rake openid_federation:prepare_client_keys[separate]"
          }
        elsif has_both_uses && keys.length >= 2
          {
            type: :separate,
            count: keys.length,
            recommendation: "✅ Separate keys detected (recommended for production)"
          }
        elsif keys.length == 1
          {
            type: :single,
            count: 1,
            recommendation: "⚠️  Single key detected. This is NOT RECOMMENDED for production. Use separate signing and encryption keys for better security. Generate with: rake openid_federation:prepare_client_keys[separate]"
          }
        else
          {
            type: :unknown,
            count: keys.length,
            recommendation: "Key configuration unclear. Ensure keys have unique Key IDs and proper 'use' fields ('sig' for signing, 'enc' for encryption)"
          }
        end
      end
    end
  end
end
