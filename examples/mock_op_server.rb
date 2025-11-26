#!/usr/bin/env ruby
# frozen_string_literal: true

# Enhanced Mock OpenID Provider (OP) Server for OpenID Federation Testing
#
# This is a comprehensive standalone Webrick server that acts as a mock OP server
# for testing OpenID Federation flows. It supports:
# - Entity Configuration endpoint (/.well-known/openid-federation)
# - Fetch Endpoint (/.well-known/openid-federation/fetch)
# - Authorization Endpoint (/auth) with trust chain resolution and request object validation
# - Token Endpoint (/token) with ID Token signing
# - Request object validation (signed and optionally encrypted)
# - Error injection modes for testing failure scenarios
#
# Configuration:
#   - Load from YAML file: config/mock_op.yml
#   - Or set environment variables
#
# Usage:
#   ruby examples/mock_op_server.rb
#
# Access:
#   http://localhost:9292/.well-known/openid-federation
#   http://localhost:9292/auth?request=<signed_jwt>
#   http://localhost:9292/token (POST with code)
#
# Error Injection Modes (via query param ?error_mode=<mode>):
#   - invalid_statement: Return invalid entity statement
#   - wrong_keys: Return wrong JWKS keys
#   - invalid_request: Reject request object
#   - invalid_signature: Return invalid signature
#   - expired_statement: Return expired entity statement
#   - missing_metadata: Return statement without metadata

require "bundler/setup"
require "webrick"
require "yaml"
require "json"
require "jwt"
require "jwe"
require "openssl"
require "base64"
require "uri"
require "cgi"
require "securerandom"

# Add the gem to the load path
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "omniauth_openid_federation"

class MockOPServer
  # Load configuration from YAML or environment
  def self.load_config
    config_path = File.expand_path("../config/mock_op.yml", __dir__)
    if File.exist?(config_path)
      YAML.load_file(config_path)
    else
      # Fall back to environment variables
      {
        "entity_id" => ENV["OP_ENTITY_ID"] || "http://localhost:9292",
        "server_host" => ENV["OP_SERVER_HOST"] || "localhost:9292",
        "signing_key" => ENV["OP_SIGNING_KEY"],
        "encryption_key" => ENV["OP_ENCRYPTION_KEY"],
        "trust_anchors" => parse_trust_anchors(ENV["OP_TRUST_ANCHORS"]),
        "authority_hints" => parse_array(ENV["OP_AUTHORITY_HINTS"]),
        "op_metadata" => parse_json(ENV["OP_METADATA"]) || default_op_metadata,
        "require_request_encryption" => ENV["OP_REQUIRE_ENCRYPTION"] == "true",
        "validate_request_objects" => ENV["OP_VALIDATE_REQUESTS"] != "false"
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

  def self.parse_json(str)
    return nil unless str
    JSON.parse(str)
  rescue JSON::ParserError
    nil
  end

  def self.default_op_metadata
    {
      "issuer" => "http://localhost:9292",
      "authorization_endpoint" => "http://localhost:9292/auth",
      "token_endpoint" => "http://localhost:9292/token",
      "userinfo_endpoint" => "http://localhost:9292/userinfo",
      "jwks_uri" => "http://localhost:9292/.well-known/jwks.json",
      "signed_jwks_uri" => "http://localhost:9292/.well-known/signed-jwks.json",
      "client_registration_types_supported" => ["automatic", "explicit"],
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code"],
      "id_token_signing_alg_values_supported" => ["RS256"],
      "id_token_encryption_alg_values_supported" => ["RSA-OAEP"],
      "id_token_encryption_enc_values_supported" => ["A128CBC-HS256"],
      "request_object_signing_alg_values_supported" => ["RS256"],
      "request_object_encryption_alg_values_supported" => ["RSA-OAEP"],
      "request_object_encryption_enc_values_supported" => ["A128CBC-HS256"],
      "scopes_supported" => ["openid", "profile", "email"]
    }
  end

  def self.load_signing_key(key_data)
    if key_data.nil? || key_data.empty?
      # Generate a new key for testing
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

  def self.normalize_trust_anchors(trust_anchors)
    trust_anchors.map do |ta|
      {
        entity_id: ta["entity_id"] || ta[:entity_id],
        jwks: ta["jwks"] || ta[:jwks]
      }
    end
  end

  # Initialize configuration
  CONFIG = load_config
  ENTITY_ID = CONFIG["entity_id"] || "http://localhost:9292"
  SERVER_HOST = CONFIG["server_host"] || "localhost:9292"
  SIGNING_KEY = load_signing_key(CONFIG["signing_key"])
  ENCRYPTION_KEY = load_encryption_key(CONFIG["encryption_key"]) || SIGNING_KEY
  TRUST_ANCHORS = CONFIG["trust_anchors"] || []
  AUTHORITY_HINTS = CONFIG["authority_hints"] || []
  OP_METADATA = CONFIG["op_metadata"] || default_op_metadata
  REQUIRE_REQUEST_ENCRYPTION = CONFIG["require_request_encryption"] || false
  VALIDATE_REQUEST_OBJECTS = CONFIG["validate_request_objects"] != false

  # Store for authorization codes (in production, use a database)
  AUTHORIZATION_CODES = {}

  # Store for registered RPs (for testing)
  REGISTERED_RPS = {}

  # Configure FederationEndpoint (deferred until server starts)
  def self.configure_federation_endpoint
    base_url = base_url_static
    # Use localhost URLs if entity_id is localhost (for isolation)
    if ENTITY_ID.include?("localhost")
      # Override metadata to use localhost URLs
      metadata = OP_METADATA.dup
      metadata["issuer"] = ENTITY_ID
      metadata["authorization_endpoint"] = "#{base_url}/auth"
      metadata["token_endpoint"] = "#{base_url}/token"
      metadata["userinfo_endpoint"] = "#{base_url}/userinfo"
      metadata["jwks_uri"] = "#{base_url}/.well-known/jwks.json"
      metadata["signed_jwks_uri"] = "#{base_url}/.well-known/signed-jwks.json"
    else
      metadata = OP_METADATA.merge(
        "issuer" => ENTITY_ID,
        "authorization_endpoint" => "#{base_url}/auth",
        "token_endpoint" => "#{base_url}/token",
        "userinfo_endpoint" => "#{base_url}/userinfo",
        "jwks_uri" => "#{base_url}/.well-known/jwks.json",
        "signed_jwks_uri" => "#{base_url}/.well-known/signed-jwks.json"
      )
    end

    OmniauthOpenidFederation::FederationEndpoint.auto_configure(
      issuer: ENTITY_ID,
      private_key: SIGNING_KEY,
      metadata: {
        openid_provider: metadata
      }
    )

    # Set authority_hints if provided (must be done after auto_configure)
    if AUTHORITY_HINTS.any?
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.authority_hints = AUTHORITY_HINTS
      end
    end
  end

  # Configure subordinate statements if provided
  def self.configure_subordinate_statements
    if CONFIG["subordinate_statements"]
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.subordinate_statements = CONFIG["subordinate_statements"]
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
      error_mode = params["error_mode"] || req.header["x-error-mode"]&.first

      # Parse body for POST requests
      body_params = {}
      if method == "POST" && req.body && !req.body.empty?
        body_params = if req.content_type&.include?("application/json")
          begin
            JSON.parse(req.body)
          rescue
            {}
          end
        else
          parse_form_data(req.body)
        end
      end

      # Merge query params and body params
      all_params = params.merge(body_params)

      case [method, path]
      when ["GET", "/"]
        handle_health_check(req, res)
      when ["GET", "/.well-known/openid-federation"]
        handle_entity_configuration(req, res, error_mode)
      when ["GET", "/.well-known/openid-federation/fetch"]
        handle_fetch(req, res, params, error_mode)
      when ["GET", "/.well-known/jwks.json"]
        handle_jwks(req, res, error_mode)
      when ["GET", "/.well-known/signed-jwks.json"]
        handle_signed_jwks(req, res, error_mode)
      when ["GET", "/auth"]
        handle_authorization(req, res, all_params, error_mode)
      when ["POST", "/token"]
        handle_token(req, res, all_params)
      when ["GET", "/userinfo"]
        handle_userinfo(req, res)
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

    def parse_form_data(body)
      return {} unless body
      CGI.parse(body).transform_values { |v| v.first }
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

    def error_response(res, error, description, status: 400)
      json_response(res, {error: error, error_description: description}, status: status)
    end

    def handle_health_check(req, res)
      json_response(res, {
        status: "ok",
        entity_id: MockOPServer::ENTITY_ID,
        endpoints: {
          entity_configuration: "#{base_url(req)}/.well-known/openid-federation",
          fetch: "#{base_url(req)}/.well-known/openid-federation/fetch",
          authorization: "#{base_url(req)}/auth",
          token: "#{base_url(req)}/token",
          userinfo: "#{base_url(req)}/userinfo"
        },
        error_modes: [
          "invalid_statement",
          "wrong_keys",
          "invalid_request",
          "invalid_signature",
          "expired_statement",
          "missing_metadata"
        ]
      })
    end

    def handle_entity_configuration(req, res, error_mode)
      if error_mode == "invalid_statement"
        res.status = 200
        res.content_type = "application/jwt"
        res.body = "invalid.entity.statement"
        return
      end

      if error_mode == "expired_statement"
        res.status = 200
        res.content_type = "application/jwt"
        res.body = generate_expired_entity_statement
        return
      end

      if error_mode == "wrong_keys"
        res.status = 200
        res.content_type = "application/jwt"
        res.body = generate_entity_statement_with_wrong_keys
        return
      end

      if error_mode == "missing_metadata"
        res.status = 200
        res.content_type = "application/jwt"
        res.body = generate_entity_statement_without_metadata
        return
      end

      entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
      res.status = 200
      res.content_type = "application/jwt"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = entity_statement
    end

    def handle_fetch(req, res, params, error_mode)
      subject_entity_id = params["sub"]

      unless subject_entity_id
        return error_response(res, "invalid_request", "Missing required parameter: sub")
      end

      if subject_entity_id == MockOPServer::ENTITY_ID
        return error_response(res, "invalid_request", "Subject cannot be the issuer")
      end

      if error_mode == "invalid_statement"
        res.status = 200
        res.content_type = "application/entity-statement+jwt"
        res.body = "invalid.subordinate.statement"
        return
      end

      subordinate_statement = OmniauthOpenidFederation::FederationEndpoint.get_subordinate_statement(subject_entity_id)

      unless subordinate_statement
        return error_response(res, "not_found", "Subordinate Statement not found for subject: #{subject_entity_id}", status: 404)
      end

      res.status = 200
      res.content_type = "application/entity-statement+jwt"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = subordinate_statement
    end

    def handle_jwks(req, res, error_mode)
      if error_mode == "wrong_keys"
        wrong_key = OpenSSL::PKey::RSA.new(2048)
        jwk = JWT::JWK.new(wrong_key.public_key)
        jwks = {keys: [jwk.export]}
        return json_response(res, jwks)
      end

      jwks = OmniauthOpenidFederation::FederationEndpoint.current_jwks
      res.status = 200
      res.content_type = "application/json"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = jwks.to_json
    end

    def handle_signed_jwks(req, res, error_mode)
      if error_mode == "invalid_signature"
        res.status = 200
        res.content_type = "application/jwt"
        res.body = generate_invalid_signed_jwks
        return
      end

      signed_jwks = OmniauthOpenidFederation::FederationEndpoint.generate_signed_jwks
      res.status = 200
      res.content_type = "application/jwt"
      res["Cache-Control"] = "public, max-age=3600"
      res.body = signed_jwks
    end

    def handle_authorization(req, res, params, error_mode)
      request_object = params["request"]
      client_id = params["client_id"]
      redirect_uri = params["redirect_uri"]
      state = params["state"]
      nonce = params["nonce"]

      # Validate request object if present
      if request_object
        if error_mode == "invalid_request"
          return error_response(res, "invalid_request_object", "Request object validation failed")
        end

        begin
          validated_request = validate_request_object(request_object, error_mode)
          client_id = validated_request[:client_id] || validated_request["client_id"] || client_id
          redirect_uri = validated_request[:redirect_uri] || validated_request["redirect_uri"] || redirect_uri
          state = validated_request[:state] || validated_request["state"] || state
          nonce = validated_request[:nonce] || validated_request["nonce"] || nonce
        rescue OmniauthOpenidFederation::DecryptionError => e
          return error_response(res, "invalid_request_object", "Request object decryption failed: #{e.message}")
        rescue => e
          return error_response(res, "invalid_request_object", "Request object validation failed: #{e.message}")
        end
      end

      unless client_id && redirect_uri
        return error_response(res, "invalid_request", "Missing required parameters: client_id, redirect_uri")
      end

      # Resolve RP's trust chain if client_id is an Entity ID
      rp_effective_metadata = nil
      if is_entity_id?(client_id) && MockOPServer::TRUST_ANCHORS.any?
        begin
          resolver = OmniauthOpenidFederation::Federation::TrustChainResolver.new(
            leaf_entity_id: client_id,
            trust_anchors: MockOPServer.normalize_trust_anchors(MockOPServer::TRUST_ANCHORS)
          )
          trust_chain = resolver.resolve!

          # Extract RP metadata from trust chain
          leaf_statement = trust_chain.first
          leaf_parsed = leaf_statement.is_a?(Hash) ? leaf_statement : leaf_statement.parse
          leaf_metadata = extract_metadata_from_parsed(leaf_parsed)

          # Merge metadata policies
          merger = OmniauthOpenidFederation::Federation::MetadataPolicyMerger.new(trust_chain: trust_chain)
          rp_effective_metadata = merger.merge_and_apply(leaf_metadata)
        rescue => e
          return error_response(res, "invalid_client", "Failed to resolve client trust chain: #{e.message}")
        end
      end

      # Extract redirect_uri from effective metadata if available
      if rp_effective_metadata
        rp_metadata = rp_effective_metadata[:openid_relying_party] || rp_effective_metadata["openid_relying_party"]
        if rp_metadata
          allowed_redirect_uris = rp_metadata[:redirect_uris] || rp_metadata["redirect_uris"] || []
          unless allowed_redirect_uris.include?(redirect_uri)
            return error_response(res, "invalid_request", "redirect_uri not in client's allowed redirect_uris")
          end
        end
      end

      # Generate authorization code
      code = SecureRandom.hex(32)
      MockOPServer::AUTHORIZATION_CODES[code] = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        state: state,
        nonce: nonce,
        created_at: Time.now
      }

      # Redirect back to RP with authorization code
      redirect_uri_with_code = URI.parse(redirect_uri)
      query_params = redirect_uri_with_code.query ? CGI.parse(redirect_uri_with_code.query) : {}
      query_params["code"] = [code]
      query_params["state"] = [state] if state
      query_params["iss"] = [MockOPServer::ENTITY_ID]

      redirect_uri_with_code.query = URI.encode_www_form(query_params.flatten.map { |k, v| [k, v] }.flatten)
      res.status = 302
      res["Location"] = redirect_uri_with_code.to_s
    end

    def handle_token(req, res, params)
      grant_type = params["grant_type"]
      code = params["code"]
      redirect_uri = params["redirect_uri"]
      params["client_id"]

      unless grant_type == "authorization_code"
        return error_response(res, "unsupported_grant_type", "Only authorization_code grant type is supported")
      end

      unless code
        return error_response(res, "invalid_request", "Missing authorization code")
      end

      code_data = MockOPServer::AUTHORIZATION_CODES.delete(code)
      unless code_data
        return error_response(res, "invalid_grant", "Invalid or expired authorization code", status: 401)
      end

      # Validate redirect_uri matches
      if redirect_uri && redirect_uri != code_data[:redirect_uri]
        return error_response(res, "invalid_grant", "redirect_uri mismatch", status: 401)
      end

      # Generate ID Token
      id_token = generate_id_token(
        client_id: code_data[:client_id],
        nonce: code_data[:nonce]
      )

      # Generate Access Token (mock)
      access_token = SecureRandom.hex(32)

      json_response(res, {
        access_token: access_token,
        token_type: "Bearer",
        expires_in: 3600,
        id_token: id_token
      })
    end

    def handle_userinfo(req, res)
      json_response(res, {
        sub: "user123",
        name: "Test User",
        email: "test@example.com"
      })
    end

    def is_entity_id?(str)
      str.is_a?(String) && str.start_with?("http://", "https://")
    end

    def extract_metadata_from_parsed(parsed)
      metadata = parsed[:metadata] || parsed["metadata"] || {}
      result = {}
      metadata.each do |entity_type, entity_metadata|
        result[entity_type.to_sym] = entity_metadata
      end
      result
    end

    def validate_request_object(request_jwt, error_mode = nil)
      # Check if it's encrypted (JWE - 5 parts)
      parts_count = request_jwt.split(".").length
      if parts_count == 5
        # Error injection: malformed encrypted request (triggered by error_mode)
        if error_mode == "malformed_encryption"
          raise OmniauthOpenidFederation::DecryptionError, "Malformed encrypted request object"
        end

        # Try to decrypt - will fail if wrong key was used
        begin
          request_jwt = JWE.decrypt(request_jwt, MockOPServer::ENCRYPTION_KEY)
        rescue => e
          raise OmniauthOpenidFederation::DecryptionError, "Failed to decrypt request object: #{e.message}"
        end
      elsif parts_count != 3 && error_mode == "malformed_encryption"
        # Not a valid JWT or JWE format
        raise OmniauthOpenidFederation::DecryptionError, "Malformed encrypted request object"
      end

      # Decode and validate the request object
      parts = request_jwt.split(".")
      raise OmniauthOpenidFederation::ValidationError, "Invalid JWT format" if parts.length != 3

      header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

      # Validate algorithm
      alg = header["alg"] || header[:alg]
      unless alg == "RS256"
        raise OmniauthOpenidFederation::ValidationError, "Unsupported algorithm: #{alg}"
      end

      # Extract client_id to get their JWKS
      client_id = payload["client_id"] || payload[:client_id]
      unless client_id
        raise OmniauthOpenidFederation::ValidationError, "Missing client_id in request object"
      end

      # Fetch client's entity statement to get their JWKS
      if is_entity_id?(client_id)
        begin
          # If client_id is localhost, use direct localhost URL (for isolation)
          client_url = if client_id.include?("localhost")
            port = client_id.match(/:(\d+)/)&.captures&.first || "9293"
            "http://localhost:#{port}/.well-known/openid-federation"
          else
            "#{client_id}/.well-known/openid-federation"
          end

          client_statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            client_url
          )
          client_parsed = client_statement.parse
          client_jwks = client_parsed[:jwks] || client_parsed["jwks"] || {}
          client_keys = client_jwks[:keys] || client_jwks["keys"] || []

          # Find the key used for signing
          kid = header["kid"] || header[:kid]
          signing_key_data = client_keys.find { |k| (k["kid"] || k[:kid]) == kid }

          unless signing_key_data
            raise OmniauthOpenidFederation::ValidationError, "Signing key not found in client JWKS"
          end

          # Convert JWK to OpenSSL key
          public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(signing_key_data)

          # Verify signature
          JWT.decode(request_jwt, public_key, true, {algorithm: "RS256"})
        rescue => e
          raise OmniauthOpenidFederation::ValidationError, "Request object validation failed: #{e.message}"
        end
      end

      payload
    end

    def generate_id_token(client_id:, nonce: nil)
      now = Time.now.to_i
      jwks = OmniauthOpenidFederation::FederationEndpoint.current_jwks
      signing_key = OmniauthOpenidFederation::FederationEndpoint.configuration.private_key
      kid = jwks["keys"]&.first&.dig("kid") || jwks[:keys]&.first&.dig(:kid)

      payload = {
        iss: MockOPServer::ENTITY_ID,
        sub: "user123",
        aud: client_id,
        exp: now + 3600,
        iat: now,
        nonce: nonce
      }

      header = {
        alg: "RS256",
        typ: "JWT",
        kid: kid
      }

      JWT.encode(payload, signing_key, "RS256", header)
    end

    def generate_expired_entity_statement
      jwk = JWT::JWK.new(MockOPServer::SIGNING_KEY.public_key)
      jwk_export = jwk.export
      jwk_export[:kid] = jwk_export[:kid] || SecureRandom.hex(16)

      payload = {
        iss: MockOPServer::ENTITY_ID,
        sub: MockOPServer::ENTITY_ID,
        iat: Time.now.to_i - 7200,
        exp: Time.now.to_i - 3600,
        jwks: {keys: [jwk_export]},
        metadata: {
          openid_provider: MockOPServer::OP_METADATA
        }
      }

      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      JWT.encode(payload, MockOPServer::SIGNING_KEY, "RS256", header)
    end

    def generate_entity_statement_with_wrong_keys
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      jwk = JWT::JWK.new(wrong_key.public_key)
      jwk_export = jwk.export
      jwk_export[:kid] = jwk_export[:kid] || SecureRandom.hex(16)

      payload = {
        iss: MockOPServer::ENTITY_ID,
        sub: MockOPServer::ENTITY_ID,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {keys: [jwk_export]},
        metadata: {
          openid_provider: MockOPServer::OP_METADATA
        }
      }

      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      JWT.encode(payload, MockOPServer::SIGNING_KEY, "RS256", header)
    end

    def generate_entity_statement_without_metadata
      jwk = JWT::JWK.new(MockOPServer::SIGNING_KEY.public_key)
      jwk_export = jwk.export
      jwk_export[:kid] = jwk_export[:kid] || SecureRandom.hex(16)

      payload = {
        iss: MockOPServer::ENTITY_ID,
        sub: MockOPServer::ENTITY_ID,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {keys: [jwk_export]}
      }

      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      JWT.encode(payload, MockOPServer::SIGNING_KEY, "RS256", header)
    end

    def generate_invalid_signed_jwks
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      jwk = JWT::JWK.new(wrong_key.public_key)
      jwk_export = jwk.export

      payload = {
        keys: [jwk_export]
      }

      header = {alg: "RS256", typ: "JWT", kid: jwk_export[:kid]}
      JWT.encode(payload, wrong_key, "RS256", header)
    end
  end

  def self.run!
    port = ENV["PORT"]&.to_i || 9292
    bind = ENV["BIND"] || "localhost"

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
  MockOPServer.configure_federation_endpoint
  MockOPServer.configure_subordinate_statements

  puts "Starting Enhanced Mock OP Server..."
  puts "Entity ID: #{MockOPServer::ENTITY_ID}"
  puts "Server: http://#{MockOPServer::SERVER_HOST}"
  puts ""
  puts "Endpoints:"
  puts "  GET  /.well-known/openid-federation - Entity Configuration"
  puts "  GET  /.well-known/openid-federation/fetch?sub=<entity_id> - Fetch Subordinate Statement"
  puts "  GET  /.well-known/jwks.json - JWKS"
  puts "  GET  /.well-known/signed-jwks.json - Signed JWKS"
  puts "  GET  /auth?request=<signed_jwt> - Authorization (with request object validation)"
  puts "  POST /token - Token Exchange"
  puts "  GET  /userinfo - UserInfo (mock)"
  puts ""
  puts "Error Injection Modes (add ?error_mode=<mode> to any endpoint):"
  puts "  - invalid_statement: Return invalid entity statement"
  puts "  - wrong_keys: Return wrong JWKS keys"
  puts "  - invalid_request: Reject request object"
  puts "  - invalid_signature: Return invalid signature"
  puts "  - expired_statement: Return expired entity statement"
  puts "  - missing_metadata: Return statement without metadata"
  puts ""

  MockOPServer.run!
end
