# Federation Controller for serving entity statements and JWKS
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
#
# Serves endpoints:
# - /.well-known/openid-federation - Entity statement JWT
# - /.well-known/openid-federation/fetch - Fetch endpoint for Subordinate Statements
# - /.well-known/jwks.json - Standard JWKS (JSON)
# - /.well-known/signed-jwks.json|.jwt|.jose - Signed JWKS (JWT)
#
# Parent class is OmniauthOpenidFederation.base_controller (default ApplicationController,
# or ActionController::API when ApplicationController is absent). Set before load:
#   OmniauthOpenidFederation.base_controller = "ActionController::API"
require "omniauth_openid_federation/cache_adapter"
require "omniauth_openid_federation/controller"
require "omniauth_openid_federation/constants"

module OmniauthOpenidFederation
  class FederationController < OmniauthOpenidFederation.base_controller_class
    if respond_to?(:skip_before_action)
      skip_before_action :verify_authorized, raise: false
      skip_after_action :verify_policy_scoped, raise: false if respond_to?(:skip_after_action)
    end

    def show
      entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement

      response.headers["Content-Type"] = Constants::CONTENT_TYPE_ENTITY_STATEMENT_JWT
      response.headers["Cache-Control"] = "public, max-age=3600"

      render plain: entity_statement
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render plain: "Federation endpoint not configured", status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error generating entity statement: #{e.class} - #{e.message}")
      render plain: "Internal server error", status: :internal_server_error
    end

    def fetch
      subject_entity_id = params[:sub]

      unless subject_entity_id
        render json: {error: "invalid_request", error_description: "Missing required parameter: sub"}, status: :bad_request
        return
      end

      begin
        subject_entity_id = OmniauthOpenidFederation::Validators.validate_entity_identifier!(subject_entity_id, max_length: 2048)
      rescue SecurityError => e
        render json: {error: "invalid_request", error_description: "Invalid subject entity ID: #{e.message}"}, status: :bad_request
        return
      rescue => e
        render json: {error: "invalid_request", error_description: "Subject entity ID validation failed: #{e.message}"}, status: :bad_request
        return
      end

      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      if subject_entity_id == config.issuer
        render json: {error: "invalid_request", error_description: "Subject cannot be the issuer"}, status: :bad_request
        return
      end

      subordinate_statement = OmniauthOpenidFederation::FederationEndpoint.get_subordinate_statement(subject_entity_id)

      unless subordinate_statement
        render json: {error: "not_found", error_description: "Subordinate Statement not found for subject: #{subject_entity_id}"}, status: :not_found
        return
      end

      response.headers["Content-Type"] = Constants::CONTENT_TYPE_ENTITY_STATEMENT_JWT
      response.headers["Cache-Control"] = "public, max-age=3600"

      render plain: subordinate_statement
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render json: {error: "Federation endpoint not configured"}, status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error fetching subordinate statement: #{e.class} - #{e.message}")
      render json: {error: "Internal server error"}, status: :internal_server_error
    end

    def jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      jwks_to_serve = OmniauthOpenidFederation::FederationEndpoint.current_jwks

      cache_key = OmniauthOpenidFederation::Cache.key_for_served_jwks(config.issuer)
      cache_ttl = config.jwks_cache_ttl || 3600

      jwks_json = if OmniauthOpenidFederation::CacheAdapter.available?
        OmniauthOpenidFederation::CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          jwks_to_serve.to_json
        end
      else
        jwks_to_serve.to_json
      end

      response.headers["Content-Type"] = Constants::CONTENT_TYPE_JSON
      response.headers["Cache-Control"] = "public, max-age=3600"

      render json: JSON.parse(jwks_json)
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Configuration error: #{e.message}")
      render json: {error: "Federation endpoint not configured"}, status: :service_unavailable
    rescue => e
      OmniauthOpenidFederation::Logger.error("[FederationController] Error serving JWKS: #{e.class} - #{e.message}")
      render json: {error: "Internal server error"}, status: :internal_server_error
    end

    def signed_jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      signed_jwks_jwt = OmniauthOpenidFederation::FederationEndpoint.generate_signed_jwks

      cache_key = OmniauthOpenidFederation::Cache.key_for_served_signed_jwks(config.issuer)
      cache_ttl = config.jwks_cache_ttl || 3600

      cached_jwt = if OmniauthOpenidFederation::CacheAdapter.available?
        OmniauthOpenidFederation::CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          signed_jwks_jwt
        end
      else
        signed_jwks_jwt
      end

      response.headers["Content-Type"] = Constants::CONTENT_TYPE_JWT
      response.headers["Cache-Control"] = "public, max-age=3600"

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
