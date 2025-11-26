# Rack-compatible endpoint handler for federation endpoints
# Provides framework-agnostic HTTP endpoint handling
#
# @example Using with Rack
#   require "rack"
#   require "omniauth_openid_federation"
#
#   app = Rack::Builder.new do
#     map "/.well-known" do
#       run OmniauthOpenidFederation::RackEndpoint.new
#     end
#   end
#
#   Rack::Handler::WEBrick.run app, Port: 9292
#
# @example Using with Sinatra
#   require "sinatra"
#   require "omniauth_openid_federation"
#
#   use OmniauthOpenidFederation::RackEndpoint
#
#   get "/" do
#     "Hello"
#   end
require "rack"
require "json"
require "digest"
require_relative "cache_adapter"
require_relative "federation_endpoint"
require_relative "logger"

module OmniauthOpenidFederation
  class RackEndpoint
    # Rack call interface
    #
    # @param env [Hash] Rack environment
    # @return [Array] [status, headers, body] Rack response
    def call(env)
      request = Rack::Request.new(env)
      path = request.path_info

      case path
      when "/openid-federation"
        handle_entity_statement
      when "/openid-federation/fetch"
        handle_fetch(request)
      when "/jwks.json"
        handle_jwks
      when "/signed-jwks.json"
        handle_signed_jwks
      else
        not_found
      end
    rescue OmniauthOpenidFederation::ConfigurationError => e
      OmniauthOpenidFederation::Logger.error("[RackEndpoint] Configuration error: #{e.message}")
      error_response(503, "Federation endpoint not configured")
    rescue OmniauthOpenidFederation::SignatureError => e
      OmniauthOpenidFederation::Logger.error("[RackEndpoint] Signature error: #{e.message}")
      error_response(500, "Internal server error")
    rescue => e
      OmniauthOpenidFederation::Logger.error("[RackEndpoint] Error: #{e.class} - #{e.message}")
      error_response(500, "Internal server error")
    end

    private

    # Handle entity statement endpoint
    #
    # @return [Array] Rack response
    def handle_entity_statement
      entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement

      headers = {
        "Content-Type" => "application/jwt",
        "Cache-Control" => "public, max-age=3600"
      }

      [200, headers, [entity_statement]]
    end

    # Handle JWKS endpoint
    #
    # @return [Array] Rack response
    def handle_jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      jwks_to_serve = OmniauthOpenidFederation::FederationEndpoint.current_jwks

      # Apply server-side caching if available
      cache_key = "federation:jwks:#{Digest::SHA256.hexdigest(jwks_to_serve.to_json)}"
      cache_ttl = config.jwks_cache_ttl || 3600

      jwks_json = if CacheAdapter.available?
        CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          jwks_to_serve.to_json
        end
      else
        jwks_to_serve.to_json
      end

      headers = {
        "Content-Type" => "application/json",
        "Cache-Control" => "public, max-age=3600"
      }

      [200, headers, [JSON.parse(jwks_json).to_json]]
    end

    # Handle fetch endpoint (for Subordinate Statements)
    #
    # @param request [Rack::Request] The Rack request
    # @return [Array] Rack response
    def handle_fetch(request)
      # Extract 'sub' query parameter (required per spec)
      subject_entity_id = request.params["sub"]

      unless subject_entity_id
        return error_response(400, {error: "invalid_request", error_description: "Missing required parameter: sub"}.to_json)
      end

      # Validate that subject is not the issuer (invalid request per spec)
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      if subject_entity_id == config.issuer
        return error_response(400, {error: "invalid_request", error_description: "Subject cannot be the issuer"}.to_json)
      end

      # Get Subordinate Statement
      subordinate_statement = OmniauthOpenidFederation::FederationEndpoint.get_subordinate_statement(subject_entity_id)

      unless subordinate_statement
        return error_response(404, {error: "not_found", error_description: "Subordinate Statement not found for subject: #{subject_entity_id}"}.to_json)
      end

      headers = {
        "Content-Type" => "application/entity-statement+jwt",
        "Cache-Control" => "public, max-age=3600"
      }

      [200, headers, [subordinate_statement]]
    end

    # Handle signed JWKS endpoint
    #
    # @return [Array] Rack response
    def handle_signed_jwks
      config = OmniauthOpenidFederation::FederationEndpoint.configuration
      signed_jwks_jwt = OmniauthOpenidFederation::FederationEndpoint.generate_signed_jwks

      # Apply server-side caching if available
      cache_key = "federation:signed_jwks:#{Digest::SHA256.hexdigest(signed_jwks_jwt)}"
      cache_ttl = config.jwks_cache_ttl || 3600

      cached_jwt = if CacheAdapter.available?
        CacheAdapter.fetch(cache_key, expires_in: cache_ttl) do
          signed_jwks_jwt
        end
      else
        signed_jwks_jwt
      end

      headers = {
        "Content-Type" => "application/jwt",
        "Cache-Control" => "public, max-age=3600"
      }

      [200, headers, [cached_jwt]]
    end

    # Return 404 Not Found
    #
    # @return [Array] Rack response
    def not_found
      [404, {"Content-Type" => "text/plain"}, ["Not Found"]]
    end

    # Return error response
    #
    # @param status [Integer] HTTP status code
    # @param message [String] Error message
    # @return [Array] Rack response
    def error_response(status, message)
      content_type = (status == 503) ? "text/plain" : "application/json"
      body = (status == 503) ? message : {error: message}.to_json

      [status, {"Content-Type" => content_type}, [body]]
    end
  end
end
