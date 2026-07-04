require "omniauth-oauth2"
require "openid_connect"
require "jwt"
require "base64"
require "securerandom"
require "rack/utils"
require "tempfile"
require "digest"
require_relative "string_helpers"
require_relative "logger"
require_relative "errors"
require_relative "constants"
require_relative "configuration"
require_relative "validators"
require_relative "http_client"
require_relative "jws"
require_relative "jwks/fetch"
require_relative "endpoint_resolver"
require_relative "federation/trust_chain_resolver"
require_relative "federation/metadata_policy_merger"
require_relative "strategy/id_token_decoding"
require_relative "strategy/userinfo_decoding"
require_relative "strategy/provider_entity_statement"
require_relative "strategy/endpoint_resolution"
require_relative "strategy/jwks_resolution"
require_relative "strategy/client_entity_statement"
require_relative "strategy/client_construction"
require_relative "strategy/authorization_request"
require_relative "strategy/callback_handling"
require_relative "strategy/failure_handling"

# OpenID Federation strategy for OAuth 2.0 / OpenID Connect providers
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.github.io/federation/main.html OpenID Federation Documentation
# @see https://datatracker.ietf.org/doc/html/rfc9101 RFC 9101 - OAuth 2.0 Authorization Request
#
# This strategy implements OpenID Federation features for providers requiring
# compliance with regulatory requirements and security best practices.
#
# Features implemented:
# - Signed Request Objects (RFC 9101, Section 12.1.1.1.1) - Required for secure authorization requests
# - ID Token Encryption/Decryption (RSA-OAEP + A128CBC-HS256) - Required for token security
# - Client Assertion (private_key_jwt) - Required for token endpoint authentication
# - OpenID Federation Entity Statements (Section 3) - Optional but recommended
# - Signed JWKS Support (Section 5.2.1.1) - Required for key rotation compliance
#
# Features implemented:
# - Trust Chain Resolution (Section 10) - Resolves trust chains when trust_anchors configured
# - Metadata Policy Merging (Section 5.1) - Applies metadata policies from trust chain
# - Automatic Client Registration (Section 11.1) - Uses Entity ID as client_id
#
# Features NOT implemented (optional):
# - Trust marks (Section 7) - Optional feature (parsed but not validated)
# - Federation endpoints (Section 8) - Server-side feature (Fetch Endpoint implemented separately)
#
# This strategy uses the openid_connect gem and extends it with federation-specific features.
module OmniAuth
  module Strategies
    class OpenIDFederation < OmniAuth::Strategies::OAuth2
      include OmniauthOpenidFederation::Strategy::ClientConstruction
      include OmniauthOpenidFederation::Strategy::AuthorizationRequest
      include OmniauthOpenidFederation::Strategy::CallbackHandling
      include OmniauthOpenidFederation::Strategy::FailureHandling
      include OmniauthOpenidFederation::Strategy::ProviderEntityStatement
      include OmniauthOpenidFederation::Strategy::EndpointResolution
      include OmniauthOpenidFederation::Strategy::JwksResolution
      include OmniauthOpenidFederation::Strategy::ClientEntityStatement
      include OmniauthOpenidFederation::Strategy::IdTokenDecoding
      include OmniauthOpenidFederation::Strategy::UserinfoDecoding

      # Override the name option from the base class
      option :name, "openid_federation"

      # Constants for token format validation
      JWT_PARTS_COUNT = 3 # Standard JWT has 3 parts: header.payload.signature
      # Constants for random value generation
      STATE_BYTES = 32 # Number of hex bytes for state parameter (CSRF protection)
      NONCE_BYTES = 32 # Number of hex bytes for nonce parameter (replay protection)

      # Additional options for OpenID Federation
      option :scope, "openid"
      option :response_type, "code"
      option :discovery, true
      option :send_nonce, true
      option :client_auth_method, :jwt_bearer
      option :client_signing_alg, :RS256
      option :audience, nil # Audience for JWT request objects (defaults to token_endpoint)
      option :fetch_userinfo, true # Whether to fetch userinfo endpoint (default: true for backward compatibility, set to false if ID token contains all needed data)
      option :key_source, :local # Key source: :local (use local static private_key) or :federation (use federation/JWKS) - used as default for both signing and decryption
      option :signing_key_source, nil # Signing key source: :local, :federation, or nil (uses key_source)
      option :decryption_key_source, nil # Decryption key source: :local, :federation, or nil (uses key_source)
      option :entity_statement_path, nil # Path to provider entity statement JWT file (cached copy)
      option :entity_statement_url, nil # URL to provider entity statement (source of truth, Section 9)
      option :entity_statement_fingerprint, nil # Expected SHA-256 fingerprint for verification
      option :issuer, nil # Provider issuer URI (used to build entity statement URL if entity_statement_url not provided)
      option :always_encrypt_request_object, false # Always encrypt request objects if encryption keys available (default: false, only encrypts if provider requires)
      option :client_registration_type, :explicit # Client registration type: :explicit (default) or :automatic (requires client_entity_statement_path)
      option :client_entity_statement_path, nil # Path to client's entity statement JWT file (for automatic registration and client_jwk_signing_key)
      option :client_entity_statement_url, nil # URL to client's entity statement (for dynamic federation endpoints)
      option :client_entity_identifier, nil # Client's entity identifier (required for automatic registration, defaults to entity statement 'sub' claim)
      option :client_jwk_signing_key, nil # Client JWKS for token endpoint authentication (auto-extracted from client entity statement if available)
      option :trust_anchors, [] # Array of Trust Anchor configurations for trust chain resolution: [{entity_id: "...", jwks: {...}}]
      option :enable_trust_chain_resolution, true # Enable trust chain resolution when issuer/client_id is an Entity ID
      option :request_object_params, nil # Array of parameter names to include in signed request object from request.params (allow-list)
      option :prepare_request_object_params, nil # Proc to modify params before adding to signed request object: proc { |params| modified_params }

      # Override request_phase to use signed request objects (RFC 9101)
      def request_phase
        redirect authorize_uri
      end

      def auth_hash
        OmniAuth::AuthHash.new(
          provider: "openid_federation",
          uid: uid,
          info: info,
          credentials: {
            token: @access_token&.access_token,
            refresh_token: @access_token&.refresh_token,
            expires_at: @access_token&.expires_in ? Time.now.to_i + @access_token.expires_in : nil,
            expires: @access_token&.expires_in ? true : false
          },
          extra: extra
        )
      end


      uid do
        raw_info["sub"] || raw_info[:sub]
      end

      info do
        {
          name: raw_info["name"] || raw_info[:name],
          email: raw_info["email"] || raw_info[:email],
          first_name: raw_info["given_name"] || raw_info[:given_name],
          last_name: raw_info["family_name"] || raw_info[:family_name],
          nickname: raw_info["preferred_username"] || raw_info[:preferred_username] || raw_info["nickname"] || raw_info[:nickname],
          image: raw_info["picture"] || raw_info[:picture]
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def raw_info
        @raw_info ||= begin
          # Use access token from callback_phase (already exchanged)
          # If not available, exchange it now (fallback for direct calls)
          access_token = @access_token
          access_token ||= exchange_authorization_code(request.params["code"])

          id_token = decode_id_token(access_token.id_token)
          id_token_claims = id_token.raw_attributes || {}

          if options.fetch_userinfo
            begin
              userinfo = access_token.userinfo!
              userinfo_hash = decode_userinfo(userinfo)
              id_token_claims.merge(userinfo_hash)
            rescue => e
              error_msg = "Failed to fetch or decode userinfo: #{e.class} - #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              OmniauthOpenidFederation::Logger.warn("[Strategy] Falling back to ID token claims only")
              id_token_claims
            end
          else
            OmniauthOpenidFederation::Logger.debug("[Strategy] Userinfo fetching disabled, using ID token claims only")
            id_token_claims
          end
        end
      end
    end
  end
end
