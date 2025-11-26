#!/usr/bin/env ruby
# frozen_string_literal: true

# Mock Relying Party (RP) Server for OpenID Federation Testing
#
# This is a standalone Webrick server that acts as a mock RP server
# for testing OpenID Federation flows. It supports:
# - Entity Configuration endpoint (/.well-known/openid-federation)
# - Fetch Endpoint (/.well-known/openid-federation/fetch)
# - Callback endpoint for authorization responses
# - Full OpenID Federation flow simulation
#
# Usage:
#   ruby examples/mock_rp_server.rb
#
# Access:
#   http://localhost:9293/.well-known/openid-federation
#   http://localhost:9293/login?provider=<op_entity_id>
#   http://localhost:9293/callback - Authorization callback

require "bundler/setup"
require "webrick"
require "yaml"
require "json"
require "jwt"
require "openssl"
require "base64"
require "uri"
require "cgi"
require "securerandom"
require "net/http"

# Add the gem to the load path
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "omniauth_openid_federation"

class MockRPServer
  # Load configuration
  def self.load_config
    config_path = File.expand_path("../config/mock_rp.yml", __dir__)
    if File.exist?(config_path)
      YAML.load_file(config_path)
    else
      {
        "entity_id" => ENV["RP_ENTITY_ID"] || "http://localhost:9293",
        "server_host" => ENV["RP_SERVER_HOST"] || "localhost:9293",
        "signing_key" => ENV["RP_SIGNING_KEY"],
        "encryption_key" => ENV["RP_ENCRYPTION_KEY"],
        "trust_anchors" => parse_trust_anchors(ENV["RP_TRUST_ANCHORS"]),
        "authority_hints" => parse_array(ENV["RP_AUTHORITY_HINTS"]),
        "redirect_uris" => parse_array(ENV["RP_REDIRECT_URIS"]) || ["http://localhost:9293/callback"]
      }
    end
  end

  def self.parse_trust_anchors(str)
    return [] unless str
    JSON.parse(str)
  rescue JSON::ParserError
    []
  end

  def self.parse_array(str)
    return [] unless str
    str.split(",").map(&:strip)
  end

  def self.load_signing_key(key_data)
    if key_data.nil? || key_data.empty?
      OpenSSL::PKey::RSA.new(2048)
    elsif key_data.is_a?(String)
      if key_data.include?("BEGIN")
        OpenSSL::PKey::RSA.new(key_data)
      else
        OpenSSL::PKey::RSA.new(Base64.decode64(key_data))
      end
    else
      raise "Invalid signing key format"
    end
  end

  def self.load_encryption_key(key_data)
    return nil if key_data.nil? || key_data.empty?
    load_signing_key(key_data)
  end

  # Initialize configuration
  CONFIG = load_config
  ENTITY_ID = CONFIG["entity_id"] || "http://localhost:9293"
  SERVER_HOST = CONFIG["server_host"] || "localhost:9293"
  SIGNING_KEY = load_signing_key(CONFIG["signing_key"])
  ENCRYPTION_KEY = load_encryption_key(CONFIG["encryption_key"]) || SIGNING_KEY
  TRUST_ANCHORS = CONFIG["trust_anchors"] || []
  AUTHORITY_HINTS = CONFIG["authority_hints"] || []
  REDIRECT_URIS = CONFIG["redirect_uris"] || ["http://localhost:9293/callback"]

  # Store for authorization state
  AUTHORIZATION_STATE = {}

  # Configure FederationEndpoint (deferred until server starts)
  def self.configure_federation_endpoint
    base_url = base_url_static
    # Use localhost URLs if entity_id is localhost (for isolation)
    redirect_uris = if ENTITY_ID.include?("localhost")
      REDIRECT_URIS.map { |uri| uri.include?("localhost") ? uri : "#{base_url}/callback" }
    else
      REDIRECT_URIS.map { |uri| uri.gsub("https://rp.example.com", base_url) }
    end

    OmniauthOpenidFederation::FederationEndpoint.auto_configure(
      issuer: ENTITY_ID,
      private_key: SIGNING_KEY,
      metadata: {
        openid_relying_party: {
          "redirect_uris" => redirect_uris,
          "client_name" => "Mock RP Server",
          "application_type" => "web"
        }
      }
    )

    # Set authority_hints if provided (must be done after auto_configure)
    if AUTHORITY_HINTS.any?
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.authority_hints = AUTHORITY_HINTS
      end
    end
  end

  def self.base_url_static
    "http://#{SERVER_HOST}"
  end

  # Webrick servlet to handle requests
  class Servlet < WEBrick::HTTPServlet::AbstractServlet
    def service(req, res)
      path = req.path
      method = req.request_method
      params = parse_query(req.query_string)

      case [method, path]
      when ["GET", "/"]
        handle_health_check(req, res)
      when ["GET", "/.well-known/openid-federation"]
        handle_entity_configuration(req, res)
      when ["GET", "/.well-known/openid-federation/fetch"]
        handle_fetch(req, res, params)
      when ["GET", "/.well-known/jwks.json"]
        handle_jwks(req, res)
      when ["GET", "/login"]
        handle_login(req, res, params)
      when ["GET", "/callback"]
        handle_callback(req, res, params)
      else
        res.status = 404
        res.content_type = "application/json"
        res.body = {error: "not_found", error_description: "Endpoint not found"}.to_json
      end
    end

    private

    def parse_query(query_string)
      return {} unless query_string
      CGI.parse(query_string).transform_values { |v| v.first }
    end

    def base_url(req)
      scheme = req.request_uri.scheme || "http"
      host = req.host
      port = req.port
      port_str = ((port == 80 && scheme == "http") || (port == 443 && scheme == "https")) ? "" : ":#{port}"
      "#{scheme}://#{host}#{port_str}"
    end

    def json_response(res, data, status: 200)
      res.status = status
      res.content_type = "application/json"
      res.body = data.to_json
    end

    def handle_health_check(req, res)
      json_response(res, {
        status: "ok",
        entity_id: MockRPServer::ENTITY_ID,
        endpoints: {
          entity_configuration: "#{base_url(req)}/.well-known/openid-federation",
          login: "#{base_url(req)}/login?provider=<op_entity_id>",
          callback: "#{base_url(req)}/callback"
        }
      })
    end

    def handle_entity_configuration(req, res)
      entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
      res.status = 200
      res.content_type = "application/jwt"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = entity_statement
    end

    def handle_fetch(req, res, params)
      subject_entity_id = params["sub"]
      unless subject_entity_id
        return json_response(res, {error: "invalid_request", error_description: "Missing required parameter: sub"}, status: 400)
      end

      subordinate_statement = OmniauthOpenidFederation::FederationEndpoint.get_subordinate_statement(subject_entity_id)
      unless subordinate_statement
        return json_response(res, {error: "not_found", error_description: "Subordinate Statement not found"}, status: 404)
      end

      res.status = 200
      res.content_type = "application/entity-statement+jwt"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = subordinate_statement
    end

    def handle_jwks(req, res)
      jwks = OmniauthOpenidFederation::FederationEndpoint.current_jwks
      res.status = 200
      res.content_type = "application/json"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = jwks.to_json
    end

    def handle_login(req, res, params)
      # Default to localhost OP if not specified (for isolation)
      provider_entity_id = params["provider"] || ENV["OP_ENTITY_ID"] || "http://localhost:9292"
      redirect_uri = "#{base_url(req)}/callback"

      # Step 1: Fetch provider's entity statement
      provider_url = if provider_entity_id.include?("localhost")
        port = provider_entity_id.match(/:(\d+)/)&.captures&.first || "9292"
        "http://localhost:#{port}/.well-known/openid-federation"
      else
        "#{provider_entity_id}/.well-known/openid-federation"
      end

      begin
        provider_statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
          provider_url
        )
        provider_metadata = provider_statement.parse
      rescue => e
        return json_response(res, {error: "provider_error", error_description: "Failed to fetch provider entity statement: #{e.message}"}, status: 500)
      end

      # Step 2: Extract authorization endpoint
      op_metadata = provider_metadata[:metadata][:openid_provider] || provider_metadata["metadata"]["openid_provider"]
      authorization_endpoint = op_metadata[:authorization_endpoint] || op_metadata["authorization_endpoint"]

      unless authorization_endpoint
        return json_response(res, {error: "provider_error", error_description: "Provider metadata missing authorization_endpoint"}, status: 500)
      end

      # Step 3: Build signed request object
      state = SecureRandom.hex(32)
      nonce = SecureRandom.hex(32)

      begin
        jws = OmniauthOpenidFederation::Jws.new(
          client_id: MockRPServer::ENTITY_ID,
          redirect_uri: redirect_uri,
          scope: "openid profile email",
          audience: provider_entity_id,
          state: state,
          nonce: nonce,
          private_key: MockRPServer::SIGNING_KEY
        )

        # Check if provider requires encryption
        request_object_encryption_alg = op_metadata[:request_object_encryption_alg] || op_metadata["request_object_encryption_alg"]
        if request_object_encryption_alg
          provider_jwks_uri = op_metadata[:jwks_uri] || op_metadata["jwks_uri"]
          if provider_jwks_uri
            provider_jwks = OmniauthOpenidFederation::Jwks::Fetch.run(provider_jwks_uri)
            encryption_key_data = provider_jwks["keys"]&.find { |k| (k["use"] || k[:use]) == "enc" } || provider_jwks["keys"]&.first
            if encryption_key_data
              OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(encryption_key_data)
              request_object = jws.sign(provider_metadata: op_metadata, always_encrypt: true)
            else
              request_object = jws.sign(provider_metadata: op_metadata)
            end
          else
            request_object = jws.sign(provider_metadata: op_metadata)
          end
        else
          request_object = jws.sign(provider_metadata: op_metadata)
        end
      rescue => e
        return json_response(res, {error: "request_error", error_description: "Failed to generate request object: #{e.message}"}, status: 500)
      end

      # Step 4: Store state
      MockRPServer::AUTHORIZATION_STATE[state] = {
        provider_entity_id: provider_entity_id,
        redirect_uri: redirect_uri,
        nonce: nonce,
        created_at: Time.now
      }

      # Step 5: Redirect to provider
      auth_url = URI.parse(authorization_endpoint)
      auth_url.query = URI.encode_www_form({
        "request" => request_object
      })

      res.status = 302
      res["Location"] = auth_url.to_s
    end

    def handle_callback(req, res, params)
      code = params["code"]
      state = params["state"]
      error = params["error"]
      error_description = params["error_description"]

      if error
        return json_response(res, {error: error, error_description: error_description}, status: 400)
      end

      unless code && state
        return json_response(res, {error: "invalid_request", error_description: "Missing code or state"}, status: 400)
      end

      state_data = MockRPServer::AUTHORIZATION_STATE.delete(state)
      unless state_data
        return json_response(res, {error: "invalid_state", error_description: "Invalid or expired state"}, status: 400)
      end

      provider_entity_id = state_data[:provider_entity_id]

      # Step 6: Exchange authorization code for tokens
      begin
        provider_url = if provider_entity_id.include?("localhost")
          port = provider_entity_id.match(/:(\d+)/)&.captures&.first || "9292"
          "http://localhost:#{port}/.well-known/openid-federation"
        else
          "#{provider_entity_id}/.well-known/openid-federation"
        end

        provider_statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
          provider_url
        )
        provider_metadata = provider_statement.parse
        op_metadata = provider_metadata[:metadata][:openid_provider] || provider_metadata["metadata"]["openid_provider"]
        token_endpoint = op_metadata[:token_endpoint] || op_metadata["token_endpoint"]

        # Exchange code for tokens
        uri = URI.parse(token_endpoint)
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Post.new(uri.path)
        request.set_form_data({
          "grant_type" => "authorization_code",
          "code" => code,
          "redirect_uri" => state_data[:redirect_uri]
        })

        response = http.request(request)
        token_response = JSON.parse(response.body)

        if response.code != "200"
          return json_response(res, token_response, status: response.code.to_i)
        end

        id_token = token_response["id_token"]

        # Step 7: Validate ID token
        provider_jwks_uri = op_metadata[:jwks_uri] || op_metadata["jwks_uri"]
        OmniauthOpenidFederation::Jwks::Fetch.run(provider_jwks_uri)

        decoded = OmniauthOpenidFederation::Jwks::Decode.jwt(id_token, provider_jwks_uri)
        id_token_payload = decoded.first

        # Validate claims
        unless id_token_payload["iss"] == provider_entity_id
          return json_response(res, {error: "invalid_token", error_description: "Invalid issuer"}, status: 400)
        end

        unless id_token_payload["aud"] == MockRPServer::ENTITY_ID
          return json_response(res, {error: "invalid_token", error_description: "Invalid audience"}, status: 400)
        end

        unless id_token_payload["nonce"] == state_data[:nonce]
          return json_response(res, {error: "invalid_token", error_description: "Invalid nonce"}, status: 400)
        end

        json_response(res, {
          status: "success",
          user: {
            sub: id_token_payload["sub"],
            iss: id_token_payload["iss"]
          },
          id_token: id_token_payload
        })
      rescue => e
        json_response(res, {error: "token_error", error_description: "Failed to exchange code or validate token: #{e.message}"}, status: 500)
      end
    end
  end

  def self.run!
    port = ENV["RP_PORT"]&.to_i || 9293
    bind = ENV["RP_BIND"] || "localhost"

    server = WEBrick::HTTPServer.new(Port: port, BindAddress: bind)
    server.mount("/", Servlet)

    trap("INT") { server.shutdown }
    trap("TERM") { server.shutdown }

    server.start
  end
end

# Run the server
if __FILE__ == $0
  # Configure federation endpoint before starting
  MockRPServer.configure_federation_endpoint

  puts "Starting Mock RP Server..."
  puts "Entity ID: #{MockRPServer::ENTITY_ID}"
  puts "Server: http://#{MockRPServer::SERVER_HOST}"
  puts ""
  puts "Endpoints:"
  puts "  GET  /.well-known/openid-federation - Entity Configuration"
  puts "  GET  /.well-known/openid-federation/fetch?sub=<entity_id> - Fetch Subordinate Statement"
  puts "  GET  /.well-known/jwks.json - JWKS"
  puts "  GET  /login?provider=<op_entity_id> - Initiate login flow"
  puts "  GET  /callback - Authorization callback"
  puts ""

  MockRPServer.run!
end
