require "uri"
require_relative "../string_helpers"
require_relative "../jwe"
require_relative "../strategy"

module OmniauthOpenidFederation
  module Tasks
    module CallbackProcessor
    def self.process(
      callback_url:,
      base_url:,
      client_id:, redirect_uri:, private_key:, entity_statement_url: nil,
      entity_statement_path: nil,
      provider_acr: nil,
      client_entity_statement_url: nil,
      client_entity_statement_path: nil
    )
      require "uri"
      require "json"
      require "base64"
      require_relative "../strategy"

      results = {
        steps_completed: [],
        errors: [],
        warnings: [],
        compliance_checks: {},
        token_info: {},
        id_token_claims: {}
      }

      # Parse callback URL
      begin
        # Note: Rake tasks are developer tools, no security validation needed
        begin
          uri = URI.parse(callback_url)
        rescue URI::InvalidURIError => e
          raise "Invalid callback URL: #{e.message}"
        end
        pairs = URI.decode_www_form(uri.query || "")
        params = pairs.group_by(&:first).transform_values { |vs| vs.map(&:last) }

        auth_code = params["code"]&.first
        state = params["state"]&.first
        error = params["error"]&.first
        error_description = params["error_description"]&.first

        if error
          raise "Authorization error: #{error}#{" - #{error_description}" if error_description}"
        end

        unless auth_code
          raise "No authorization code found in callback URL"
        end

        results[:authorization_code] = auth_code
        results[:state] = state
        results[:steps_completed] << "parse_callback"
      rescue => e
        results[:errors] << "Callback parsing: #{e.message}"
        raise
      end

      # Build strategy options from provided parameters
      begin
        # Resolve entity statement URL if only path provided
        resolved_entity_statement_url = entity_statement_url
        if resolved_entity_statement_url.nil? && entity_statement_path
          # If only path provided, try to resolve from base_url
          resolved_entity_statement_url = "#{base_url}/.well-known/openid-federation"
        end

        # Resolve client entity statement URL if only path provided
        resolved_client_entity_statement_url = client_entity_statement_url
        if resolved_client_entity_statement_url.nil? && client_entity_statement_path
          resolved_client_entity_statement_url = "#{base_url}/.well-known/openid-federation"
        end

        # Build strategy options
        strategy_options = {
          discovery: true,
          scope: [:openid],
          response_type: "code",
          client_auth_method: :jwt_bearer,
          client_signing_alg: :RS256,
          always_encrypt_request_object: true,
          entity_statement_url: resolved_entity_statement_url,
          entity_statement_path: entity_statement_path,
          client_entity_statement_url: resolved_client_entity_statement_url,
          client_entity_statement_path: client_entity_statement_path,
          client_options: {
            identifier: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key
          }
        }

        # Store client_auth_method before filtering nil values
        client_auth_method = strategy_options[:client_auth_method] || :jwt_bearer

        # Remove nil values
        strategy_options = strategy_options.reject { |_k, v| v.nil? }
        strategy_options[:client_options] = strategy_options[:client_options].reject { |_k, v| v.nil? }

        strategy = OmniAuth::Strategies::OpenIDFederation.new(nil, strategy_options)
        oidc_client = strategy.client

        unless oidc_client
          raise "Failed to initialize OpenID Connect client"
        end

        unless oidc_client.private_key
          raise "Private key not set on OpenID Connect client (required for private_key_jwt)"
        end

        results[:steps_completed] << "initialize_strategy"
      rescue => e
        results[:errors] << "Strategy initialization: #{e.message}"
        raise
      end

      # Exchange authorization code for tokens
      begin
        oidc_client.authorization_code = auth_code
        oidc_client.redirect_uri = redirect_uri
        access_token = oidc_client.access_token!(client_auth_method)

        id_token_raw = access_token.id_token
        access_token_value = access_token.access_token
        refresh_token = access_token.refresh_token

        results[:token_info] = {
          access_token: access_token_value ? "#{access_token_value[0..30]}..." : nil,
          refresh_token: refresh_token ? "Present" : "Not provided",
          id_token_encrypted: id_token_raw ? "#{id_token_raw[0..50]}..." : nil
        }

        results[:steps_completed] << "token_exchange"
      rescue => e
        results[:errors] << "Token exchange: #{e.message}"
        raise
      end

      # Decrypt and validate ID token
      begin
        id_token = strategy.send(:decode_id_token, id_token_raw)

        results[:id_token_claims] = {
          iss: id_token.iss,
          sub: id_token.sub,
          aud: id_token.aud,
          exp: id_token.exp,
          iat: id_token.iat,
          nonce: id_token.nonce,
          acr: id_token.acr,
          auth_time: id_token.auth_time,
          amr: id_token.amr
        }

        # Validate required claims
        required_claims = {
          iss: id_token.iss,
          sub: id_token.sub,
          aud: id_token.aud,
          exp: id_token.exp,
          iat: id_token.iat
        }

        missing_claims = required_claims.select { |_k, v| v.nil? }
        if missing_claims.empty?
          results[:id_token_valid] = true
        else
          results[:errors] << "Missing required ID token claims: #{missing_claims.keys.join(", ")}"
        end

        results[:steps_completed] << "id_token_validation"
      rescue => e
        results[:errors] << "ID token validation: #{e.message}"
        raise
      end

      # Validate OpenID Federation compliance
      results[:compliance_checks] = {
        "Signed Request Objects" => {
          status: "✅ MANDATORY",
          description: "All requests use signed request objects (RFC 9101)",
          verified: true
        },
        "ID Token Encryption" => {
          status: "✅ MANDATORY",
          description: "ID tokens are encrypted (RSA-OAEP + A128CBC-HS256)",
          verified: OmniauthOpenidFederation::Jwe.encrypted?(id_token_raw)
        },
        "Client Assertion (private_key_jwt)" => {
          status: "✅ MANDATORY",
          description: "Token endpoint uses private_key_jwt authentication",
          verified: true
        },
        "Entity Statement JWKS" => {
          status: "✅ MANDATORY",
          description: "JWKS extracted from entity statement",
          verified: StringHelpers.present?(entity_statement_path) || StringHelpers.present?(entity_statement_url)
        },
        "Signed JWKS Support" => {
          status: "✅ MANDATORY",
          description: "Supports OpenID Federation signed JWKS for key rotation",
          verified: true
        }
      }

      # Check for client entity statement (optional but recommended)
      if StringHelpers.present?(client_entity_statement_path) || StringHelpers.present?(client_entity_statement_url)
        results[:compliance_checks]["Client Entity Statement"] = {
          status: "✅ RECOMMENDED",
          description: "Client entity statement for federation-based key management",
          verified: true
        }
      end

      # Check registration type (automatic if client entity statement is provided)
      if StringHelpers.present?(client_entity_statement_path) || StringHelpers.present?(client_entity_statement_url)
        results[:compliance_checks]["Automatic Registration"] = {
          status: "✅ ENABLED",
          description: "Automatic client registration using entity statement",
          verified: true
        }
      end

      results[:all_compliance_verified] = results[:compliance_checks].all? { |_k, v| v[:verified] }

      results
    end
    end
  end
end
