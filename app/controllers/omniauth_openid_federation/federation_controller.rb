# Federation Controller for serving entity statements and JWKS
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Serves four endpoints:
# - /.well-known/openid-federation - Entity statement JWT
# - /.well-known/openid-federation/fetch - Fetch endpoint for Subordinate Statements
# - /.well-known/jwks.json - Standard JWKS (JSON)
# - /.well-known/signed-jwks.json - Signed JWKS (JWT)
#
# This controller is automatically available when the gem is used in a Rails application.
# Uses Rails-conventional naming (OmniauthOpenidFederation) to match natural inflection
require "omniauth_openid_federation/cache_adapter"

module OmniauthOpenidFederation
  class FederationController < ActionController::Base
    # Serve the entity statement
    #
    # GET /.well-known/openid-federation
    #
    # Returns the entity statement JWT as plain text with appropriate content type.
    def show
      entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement

      # Set appropriate headers for entity statement
      # Per OpenID Federation 1.0 Section 9.2, MUST use application/entity-statement+jwt
      response.headers["Content-Type"] = "application/entity-statement+jwt"
      response.headers["Cache-Control"] = "public, max-age=3600" # Cache for 1 hour

      render plain: entity_statement
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render plain: "Federation endpoint not configured", status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error generating entity statement: #{e.class} - #{e.message}")
      render plain: "Internal server error", status: :internal_server_error
    end

    # Serve fetch endpoint (for Subordinate Statements)
    #
    # GET /.well-known/openid-federation/fetch?sub=<subject_entity_id>
    #
    # Returns a Subordinate Statement JWT for the specified subject entity.
    # Per OpenID Federation 1.0 Section 6.1.
    def fetch
      # Extract 'sub' query parameter (required per spec)
      subject_entity_id = params[:sub]

      unless subject_entity_id
        render json: {error: "invalid_request", error_description: "Missing required parameter: sub"}, status: :bad_request
        return
      end

      # Security: Validate entity identifier per OpenID Federation 1.0 spec
      # Entity identifiers must be valid HTTP/HTTPS URIs
      begin
        # Validate and get trimmed value
        subject_entity_id = OmniauthOpenidFederation::Validators.validate_entity_identifier!(subject_entity_id, max_length: 2048)
      rescue SecurityError => e
        render json: {error: "invalid_request", error_description: "Invalid subject entity ID: #{e.message}"}, status: :bad_request
        return
      rescue => e
        render json: {error: "invalid_request", error_description: "Subject entity ID validation failed: #{e.message}"}, status: :bad_request
        return
      end

      # Validate that subject is not the issuer (invalid request per spec)
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      if subject_entity_id == config.issuer
        render json: {error: "invalid_request", error_description: "Subject cannot be the issuer"}, status: :bad_request
        return
      end

      # Get Subordinate Statement
      subordinate_statement = OmniauthOpenidFederation::FederationEndpoint.get_subordinate_statement(subject_entity_id)

      unless subordinate_statement
        render json: {error: "not_found", error_description: "Subordinate Statement not found for subject: #{subject_entity_id}"}, status: :not_found
        return
      end

      # Set appropriate headers per spec (application/entity-statement+jwt)
      response.headers["Content-Type"] = "application/entity-statement+jwt"
      response.headers["Cache-Control"] = "public, max-age=3600" # Cache for 1 hour

      render plain: subordinate_statement
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render json: {error: "Federation endpoint not configured"}, status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error fetching subordinate statement: #{e.class} - #{e.message}")
      render json: {error: "Internal server error"}, status: :internal_server_error
    end

    # Serve standard JWKS
    #
    # GET /.well-known/jwks.json
    #
    # Returns the current JWKS in JSON format.
    # Uses config.current_jwks or config.current_jwks_proc if configured,
    # otherwise falls back to entity statement JWKS.
    def jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration

      # Get current JWKS (may differ from entity statement JWKS)
      jwks_to_serve = OmniauthOpenidFederation::FederationEndpoint.current_jwks

      # Apply server-side caching if available
      cache_key = "federation:jwks:#{Digest::SHA256.hexdigest(jwks_to_serve.to_json)}"
      cache_ttl = config.jwks_cache_ttl || 3600

      jwks_json = if OmniauthOpenidFederation::CacheAdapter.available?
        OmniauthOpenidFederation::CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          jwks_to_serve.to_json
        end
      else
        jwks_to_serve.to_json
      end

      response.headers["Content-Type"] = "application/json"
      response.headers["Cache-Control"] = "public, max-age=3600" # Client-side cache for 1 hour

      render json: JSON.parse(jwks_json)
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render json: {error: "Federation endpoint not configured"}, status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error serving JWKS: #{e.class} - #{e.message}")
      render json: {error: "Internal server error"}, status: :internal_server_error
    end

    # Serve signed JWKS
    #
    # GET /.well-known/signed-jwks.json
    #
    # Returns the current JWKS wrapped in a JWT, signed with entity statement key.
    # Note: Despite the .json extension (per OpenID Federation spec), this endpoint returns
    # application/jwt (a JWT), not plain JSON. The Content-Type header correctly indicates application/jwt.
    # Uses config.signed_jwks_payload or config.signed_jwks_payload_proc if configured,
    # otherwise falls back to entity statement JWKS.
    def signed_jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration

      # Generate signed JWKS JWT
      signed_jwks_jwt = OmniauthOpenidFederation::FederationEndpoint.generate_signed_jwks

      # Apply server-side caching if available
      cache_key = "federation:signed_jwks:#{Digest::SHA256.hexdigest(signed_jwks_jwt)}"
      cache_ttl = config.jwks_cache_ttl || 3600

      cached_jwt = if OmniauthOpenidFederation::CacheAdapter.available?
        OmniauthOpenidFederation::CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          signed_jwks_jwt
        end
      else
        signed_jwks_jwt
      end

      response.headers["Content-Type"] = "application/jwt"
      response.headers["Cache-Control"] = "public, max-age=3600" # Client-side cache for 1 hour

      render plain: cached_jwt
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render plain: "Federation endpoint not configured", status: :service_unavailable
    rescue OmniauthOpenidFederation::SignatureError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Signature error: #{e.message}")
      render plain: "Internal server error", status: :internal_server_error
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error generating signed JWKS: #{e.class} - #{e.message}")
      render plain: "Internal server error", status: :internal_server_error
    end
  end
end
