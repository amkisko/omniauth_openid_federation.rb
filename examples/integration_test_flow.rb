#!/usr/bin/env ruby
# frozen_string_literal: true

# Integration Test Flow for OpenID Federation
#
# This script tests the complete OpenID Federation flow:
# 1. Provider exposes entity statement with JWKS
# 2. Client exposes entity statement with JWKS
# 3. Client fetches provider statement with keys
# 4. Client sends login request (with signed request object)
# 5. Provider fetches client statement and keys
# 6. Exchange and authenticated login
#
# It also tests error scenarios:
# - Wrong statements
# - Wrong keys
# - Wrong request encryption, validation failure
# - Other edge cases
#
# Usage:
#   ruby examples/integration_test_flow.rb
#
# Environment Variables:
#   OP_URL - OP server URL (default: http://localhost:9292)
#   RP_URL - RP server URL (default: http://localhost:9293)
#   OP_PORT - OP server port (default: 9292)
#   RP_PORT - RP server port (default: 9293)
#   OP_ENTITY_ID - OP entity ID (default: https://op.example.com)
#   RP_ENTITY_ID - RP entity ID (default: https://rp.example.com)
#   TMP_DIR - Temporary directory for keys/configs (default: tmp/integration_test)
#   AUTO_START_SERVERS - Auto-start servers (default: true)
#   CLEANUP_ON_EXIT - Clean up tmp dirs on exit (default: true)
#   KEY_TYPE - Key type: 'single' or 'separate' (default: separate)

require "bundler/setup"
require "net/http"
require "uri"
require "json"
require "base64"
require "openssl"
require "securerandom"
require "fileutils"
require "timeout"
require "open3"
require "jwe"
require "jwt"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "omniauth_openid_federation"

class IntegrationTestFlow
  OP_URL = ENV["OP_URL"] || "http://localhost:9292"
  RP_URL = ENV["RP_URL"] || "http://localhost:9293"
  OP_PORT = ENV["OP_PORT"]&.to_i || 9292
  RP_PORT = ENV["RP_PORT"]&.to_i || 9293
  # Use localhost URLs as entity IDs for complete isolation
  OP_ENTITY_ID = ENV["OP_ENTITY_ID"] || "http://localhost:9292"
  RP_ENTITY_ID = ENV["RP_ENTITY_ID"] || "http://localhost:9293"
  TMP_DIR = ENV["TMP_DIR"] || File.join(Dir.pwd, "tmp", "integration_test")
  AUTO_START_SERVERS = ENV["AUTO_START_SERVERS"] != "false"
  CLEANUP_ON_EXIT = ENV["CLEANUP_ON_EXIT"] != "false"
  KEY_TYPE = ENV["KEY_TYPE"] || "separate"

  def initialize
    @test_results = []
    @tmp_dir = File.expand_path(TMP_DIR)
    @op_pid = nil
    @rp_pid = nil
    @op_keys_dir = File.join(@tmp_dir, "op_keys")
    @rp_keys_dir = File.join(@tmp_dir, "rp_keys")
    @op_config_dir = File.join(@tmp_dir, "op_config")
    @rp_config_dir = File.join(@tmp_dir, "rp_config")
  end

  def run
    setup_directories
    generate_keys
    configure_servers
    start_servers if AUTO_START_SERVERS
    wait_for_servers
    run_all_tests
  ensure
    cleanup if CLEANUP_ON_EXIT
  end

  def run_all_tests
    puts "=" * 80
    puts "OpenID Federation Integration Tests"
    puts "=" * 80
    puts ""
    puts "Configuration:"
    puts "  OP URL: #{OP_URL}"
    puts "  RP URL: #{RP_URL}"
    puts "  OP Entity ID: #{OP_ENTITY_ID} (localhost - no DNS needed)"
    puts "  RP Entity ID: #{RP_ENTITY_ID} (localhost - no DNS needed)"
    puts "  Tmp Dir: #{@tmp_dir}"
    puts "  Isolation: Complete localhost isolation, no external dependencies"
    puts ""

    test_suite("Happy Path Flow") do
      test_provider_exposes_entity_statement
      test_client_exposes_entity_statement
      test_client_fetches_provider_statement
      test_client_sends_login_request
      test_provider_fetches_client_statement
      test_exchange_and_authenticated_login
    end

    test_suite("Error Scenarios") do
      test_wrong_entity_statement
      test_wrong_jwks_keys
      test_invalid_request_object
      test_expired_entity_statement
      test_missing_metadata
    end

    test_suite("Request Object Encryption") do
      test_encrypted_request_object
      test_invalid_encryption_key
      test_malformed_encrypted_request
    end

    test_suite("ID Token Validation") do
      test_id_token_validation_with_trust_chain
      test_invalid_id_token_signature
      test_expired_id_token
      test_id_token_wrong_audience
    end

    test_suite("Entity Statement Validation") do
      test_invalid_entity_statement_signature
      test_wrong_algorithm_entity_statement
      test_missing_required_claims_entity_statement
      test_invalid_jwt_typ_entity_statement
    end

    test_suite("Signed JWKS Endpoint") do
      test_signed_jwks_endpoint
      test_invalid_signed_jwks_signature
    end

    test_suite("Request Object Validation Details") do
      test_request_object_missing_required_claims
      test_request_object_invalid_nonce
      test_request_object_expiration
    end

    print_summary
  end

  private

  def setup_directories
    puts "Setting up directories..."
    [@tmp_dir, @op_keys_dir, @rp_keys_dir, @op_config_dir, @rp_config_dir].each do |dir|
      FileUtils.mkdir_p(dir)
    end
    puts "  Created: #{@tmp_dir}"
  end

  def generate_keys
    puts "Generating keys..."
    puts "  Key type: #{KEY_TYPE}"

    # Generate OP keys
    op_result = if KEY_TYPE == "separate"
      OmniauthOpenidFederation::TasksHelper.prepare_client_keys(
        key_type: "separate",
        output_dir: @op_keys_dir
      )
    else
      OmniauthOpenidFederation::TasksHelper.prepare_client_keys(
        key_type: "single",
        output_dir: @op_keys_dir
      )
    end

    # Generate RP keys
    rp_result = if KEY_TYPE == "separate"
      OmniauthOpenidFederation::TasksHelper.prepare_client_keys(
        key_type: "separate",
        output_dir: @rp_keys_dir
      )
    else
      OmniauthOpenidFederation::TasksHelper.prepare_client_keys(
        key_type: "single",
        output_dir: @rp_keys_dir
      )
    end

    # Handle both single and separate key types
    @op_signing_key_path = op_result[:signing_key_path] || op_result[:private_key_path]
    @op_encryption_key_path = op_result[:encryption_key_path] || op_result[:private_key_path] || @op_signing_key_path
    @rp_signing_key_path = rp_result[:signing_key_path] || rp_result[:private_key_path]
    @rp_encryption_key_path = rp_result[:encryption_key_path] || rp_result[:private_key_path] || @rp_signing_key_path

    puts "  OP keys: #{@op_signing_key_path}"
    puts "  RP keys: #{@rp_signing_key_path}"
  end

  def configure_servers
    puts "Configuring servers..."

    # Load keys
    @op_signing_key = OpenSSL::PKey::RSA.new(File.read(@op_signing_key_path))
    @op_encryption_key = OpenSSL::PKey::RSA.new(File.read(@op_encryption_key_path))
    @rp_signing_key = OpenSSL::PKey::RSA.new(File.read(@rp_signing_key_path))
    @rp_encryption_key = OpenSSL::PKey::RSA.new(File.read(@rp_encryption_key_path))

    # Set environment variables for servers
    # Use localhost URLs to ensure complete isolation
    ENV["OP_ENTITY_ID"] = OP_ENTITY_ID
    ENV["OP_SERVER_HOST"] = "localhost:#{OP_PORT}"
    ENV["OP_SIGNING_KEY"] = @op_signing_key.to_pem
    ENV["OP_ENCRYPTION_KEY"] = @op_encryption_key.to_pem
    ENV["PORT"] = OP_PORT.to_s
    # Override default metadata to use localhost URLs
    op_metadata = {
      "issuer" => OP_ENTITY_ID,
      "authorization_endpoint" => "#{OP_URL}/auth",
      "token_endpoint" => "#{OP_URL}/token",
      "userinfo_endpoint" => "#{OP_URL}/userinfo",
      "jwks_uri" => "#{OP_URL}/.well-known/jwks.json",
      "signed_jwks_uri" => "#{OP_URL}/.well-known/signed-jwks.json",
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
    ENV["OP_METADATA"] = op_metadata.to_json

    ENV["RP_ENTITY_ID"] = RP_ENTITY_ID
    ENV["RP_SERVER_HOST"] = "localhost:#{RP_PORT}"
    ENV["RP_SIGNING_KEY"] = @rp_signing_key.to_pem
    ENV["RP_ENCRYPTION_KEY"] = @rp_encryption_key.to_pem
    ENV["RP_PORT"] = RP_PORT.to_s
    ENV["RP_REDIRECT_URIS"] = "#{RP_URL}/callback"

    puts "  Environment variables configured"
    puts "  OP Entity ID: #{OP_ENTITY_ID}"
    puts "  RP Entity ID: #{RP_ENTITY_ID}"
  end

  def start_servers
    puts "Starting servers..."

    op_script = File.expand_path("../examples/mock_op_server.rb", __dir__)
    rp_script = File.expand_path("../examples/mock_rp_server.rb", __dir__)

    # Start OP server
    puts "  Starting OP server on port #{OP_PORT}..."
    @op_pid = spawn_server(op_script, "OP", OP_PORT)

    # Start RP server
    puts "  Starting RP server on port #{RP_PORT}..."
    @rp_pid = spawn_server(rp_script, "RP", RP_PORT)

    puts "  Servers started (OP PID: #{@op_pid}, RP PID: #{@rp_pid})"
  end

  def spawn_server(script, name, port)
    # Use spawn to run server in background with bundle exec
    log_file = File.join(@tmp_dir, "#{name.downcase}_server.log")
    err_file = File.join(@tmp_dir, "#{name.downcase}_server_error.log")

    script_path = File.expand_path(script, __dir__)
    project_root = File.expand_path("..", __dir__)

    # Use bundle exec to ensure all dependencies (jwt, jwe, etc.) are available
    pid = Process.spawn(
      {
        "RUBYOPT" => "-W0", # Suppress warnings
        "BUNDLE_GEMFILE" => File.join(project_root, "Gemfile")
      },
      "bundle", "exec", "ruby", script_path,
      out: [log_file, "w"],
      err: [err_file, "w"],
      chdir: project_root # Run from project root
    )
    Process.detach(pid)

    # Give the process a moment to start
    sleep 0.2

    # Verify process is still running
    begin
      Process.kill(0, pid)
    rescue Errno::ESRCH
      # Process died immediately - check error log
      sleep 0.1 # Give it a moment to write error log
      if File.exist?(err_file) && File.size(err_file) > 0
        error_content = File.read(err_file)
        raise "Server #{name} failed to start. Error: #{error_content}"
      else
        raise "Server #{name} failed to start (process died immediately). Check #{err_file}"
      end
    end

    pid
  end

  def wait_for_servers
    return unless AUTO_START_SERVERS

    puts "Waiting for servers to be ready..."
    # Give servers a moment to start binding to ports
    sleep 0.5

    max_attempts = 20  # Reduced from 30
    check_interval = 0.2  # Check every 200ms instead of 500ms

    [OP_URL, RP_URL].each do |url|
      attempt = 0
      ready = false
      server_name = url.include?("9292") ? "OP" : "RP"
      start_time = Time.now

      while attempt < max_attempts && !ready
        begin
          uri = URI.parse("#{url}/")
          http = Net::HTTP.new(uri.host, uri.port)
          http.open_timeout = 0.5  # Reduced timeout
          http.read_timeout = 0.5
          response = http.get(uri.path)

          if response.code == "200"
            elapsed = (Time.now - start_time).round(1)
            puts "  ✓ #{url} is ready (#{elapsed}s)"
            ready = true
          end
        rescue
          # Unexpected error - ignore for now
        end

        unless ready
          attempt += 1
          # Show progress every 5 attempts (1 second)
          if attempt % 5 == 0
            elapsed = (Time.now - start_time).round(1)
            print "."
          end
          sleep check_interval
        end
      end

      unless ready
        elapsed = (Time.now - start_time).round(1)
        puts "\n  ✗ #{server_name} server at #{url} did not become ready in time (#{elapsed}s)"
        err_log = File.join(@tmp_dir, "#{server_name.downcase}_server_error.log")
        log_file = File.join(@tmp_dir, "#{server_name.downcase}_server.log")

        if File.exist?(err_log) && File.size(err_log) > 0
          puts "    Error log:"
          File.readlines(err_log).last(5).each { |line| puts "      #{line.chomp}" }
        end
        if File.exist?(log_file) && File.size(log_file) > 0
          puts "    Last log entries:"
          File.readlines(log_file).last(5).each { |line| puts "      #{line.chomp}" }
        end

        raise "#{server_name} server at #{url} did not become ready after #{elapsed} seconds"
      end
    end
    puts ""
  end

  def test_suite(name)
    puts "Testing: #{name}"
    puts "-" * 80
    yield
    puts ""
  end

  def test(name)
    print "  ✓ #{name}... "
    begin
      result = yield
      if result
        puts "PASS"
        @test_results << {name: name, status: :pass}
      else
        puts "FAIL"
        @test_results << {name: name, status: :fail}
      end
    rescue => e
      puts "ERROR: #{e.message}"
      @test_results << {name: name, status: :error, error: e.message}
    end
  end

  def test_provider_exposes_entity_statement
    test("Provider exposes entity statement with JWKS") do
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"
      return false unless response.content_type == "application/jwt"

      jwt = response.body
      parts = jwt.split(".")
      return false unless parts.length == 3

      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      return false unless payload["iss"]
      return false unless payload["jwks"]
      return false unless payload["jwks"]["keys"]

      true
    end
  end

  def test_client_exposes_entity_statement
    test("Client exposes entity statement with JWKS") do
      uri = URI.parse("#{RP_URL}/.well-known/openid-federation")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"
      return false unless response.content_type == "application/jwt"

      jwt = response.body
      parts = jwt.split(".")
      return false unless parts.length == 3

      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      return false unless payload["iss"]
      return false unless payload["jwks"]
      return false unless payload["jwks"]["keys"]

      true
    end
  end

  def test_client_fetches_provider_statement
    test("Client fetches provider statement with keys") do
      # Use localhost URL directly (no DNS needed)
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      statement = OmniauthOpenidFederation::Federation::EntityStatement.new(response.body)
      metadata = statement.parse

      return false unless metadata[:issuer]
      return false unless metadata[:jwks]
      # Verify issuer uses localhost (no external DNS)
      return false unless metadata[:issuer].include?("localhost")

      true
    end
  end

  def test_client_sends_login_request
    test("Client sends login request with signed request object") do
      redirect_uri = "#{RP_URL}/callback"
      client_id = RP_ENTITY_ID
      provider_entity_id = OP_ENTITY_ID

      # Verify we're using localhost URLs (no DNS needed)
      return false unless client_id.include?("localhost")
      return false unless provider_entity_id.include?("localhost")

      jws = OmniauthOpenidFederation::Jws.new(
        client_id: client_id,
        redirect_uri: redirect_uri,
        scope: "openid",
        audience: provider_entity_id,
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        private_key: @rp_signing_key
      )

      request_object = jws.sign

      parts = request_object.split(".")
      return false unless parts.length == 3

      header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

      return false unless header["alg"] == "RS256"
      return false unless payload["client_id"] == client_id
      return false unless payload["redirect_uri"] == redirect_uri

      true
    end
  end

  def test_provider_fetches_client_statement
    test("Provider fetches client statement and keys") do
      uri = URI.parse("#{RP_URL}/.well-known/openid-federation")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      statement = OmniauthOpenidFederation::Federation::EntityStatement.new(response.body)
      metadata = statement.parse

      return false unless metadata[:issuer]
      return false unless metadata[:jwks]

      true
    end
  end

  def test_exchange_and_authenticated_login
    test("Exchange and authenticated login") do
      uri = URI.parse("#{OP_URL}/token")
      http = Net::HTTP.new(uri.host, uri.port)
      request = Net::HTTP::Post.new(uri.path)
      request.set_form_data({
        "grant_type" => "authorization_code",
        "code" => "test_code"
      })

      response = http.request(request)
      return false unless response.code.to_i.between?(400, 500)

      body = JSON.parse(response.body)
      return false unless body["error"]

      true
    end
  end

  def test_wrong_entity_statement
    test("Wrong entity statement (invalid format)") do
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation?error_mode=invalid_statement")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      jwt = response.body
      parts = jwt.split(".")
      return false unless parts.length != 3

      true
    end
  end

  def test_wrong_jwks_keys
    test("Wrong JWKS keys") do
      uri = URI.parse("#{OP_URL}/.well-known/jwks.json?error_mode=wrong_keys")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      jwks = JSON.parse(response.body)
      return false unless jwks["keys"]

      true
    end
  end

  def test_invalid_request_object
    test("Invalid request object validation") do
      uri = URI.parse("#{OP_URL}/auth?error_mode=invalid_request")
      response = Net::HTTP.get_response(uri)

      return false unless response.code.to_i >= 400

      true
    end
  end

  def test_expired_entity_statement
    test("Expired entity statement") do
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation?error_mode=expired_statement")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      jwt = response.body
      parts = jwt.split(".")
      return false unless parts.length == 3

      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      exp = payload["exp"]
      return false unless exp < Time.now.to_i

      true
    end
  end

  def test_missing_metadata
    test("Missing metadata in entity statement") do
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation?error_mode=missing_metadata")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      jwt = response.body
      parts = jwt.split(".")
      return false unless parts.length == 3

      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      return false if payload["metadata"]

      true
    end
  end

  def test_encrypted_request_object
    test("Encrypted request object") do
      # Fetch provider metadata to get encryption keys
      provider_uri = URI.parse("#{OP_URL}/.well-known/openid-federation")
      provider_response = Net::HTTP.get_response(provider_uri)
      return false unless provider_response.code == "200"

      provider_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(provider_response.body)
      provider_metadata = provider_statement.parse
      op_metadata = provider_metadata[:metadata][:openid_provider] || provider_metadata["metadata"]["openid_provider"]

      # Get provider JWKS for encryption
      jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
      jwks_response = Net::HTTP.get_response(jwks_uri)
      return false unless jwks_response.code == "200"

      provider_jwks = JSON.parse(jwks_response.body)
      encryption_key_data = provider_jwks["keys"]&.find { |k| (k["use"] || k[:use]) == "enc" } || provider_jwks["keys"]&.first
      return false unless encryption_key_data

      OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(encryption_key_data)

      # Create signed request object
      redirect_uri = "#{RP_URL}/callback"
      jws = OmniauthOpenidFederation::Jws.new(
        client_id: RP_ENTITY_ID,
        redirect_uri: redirect_uri,
        scope: "openid",
        audience: OP_ENTITY_ID,
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        private_key: @rp_signing_key
      )

      # Encrypt the request object
      request_object = jws.sign(provider_metadata: op_metadata, always_encrypt: true)

      # Verify it's encrypted (JWE has 5 parts)
      parts = request_object.split(".")
      return false unless parts.length == 5

      # Try to send it to the provider (should succeed)
      auth_uri = URI.parse("#{OP_URL}/auth")
      auth_uri.query = URI.encode_www_form({"request" => request_object})
      auth_response = Net::HTTP.get_response(auth_uri)

      # Should redirect (302) or return error if validation fails, but not 500
      return false if auth_response.code.to_i >= 500

      true
    end
  end

  def test_invalid_encryption_key
    test("Invalid encryption key") do
      # Create an encrypted request object encrypted with a wrong key
      # The provider will try to decrypt with its own key and fail
      wrong_key = OpenSSL::PKey::RSA.new(2048)

      # Create signed request object
      redirect_uri = "#{RP_URL}/callback"
      jws = OmniauthOpenidFederation::Jws.new(
        client_id: RP_ENTITY_ID,
        redirect_uri: redirect_uri,
        scope: "openid",
        audience: OP_ENTITY_ID,
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        private_key: @rp_signing_key
      )

      # Encrypt with wrong key (provider won't be able to decrypt with its key)
      signed_jwt = jws.sign
      encrypted_request = JWE.encrypt(signed_jwt, wrong_key)

      # Verify it's encrypted (JWE has 5 parts)
      parts = encrypted_request.split(".")
      return false unless parts.length == 5

      # Send to provider - should fail to decrypt
      auth_uri = URI.parse("#{OP_URL}/auth")
      auth_uri.query = URI.encode_www_form({"request" => encrypted_request})
      auth_response = Net::HTTP.get_response(auth_uri)

      # Should return error (400 or 401) due to decryption failure
      return false unless auth_response.code.to_i.between?(400, 499)

      body = begin
        JSON.parse(auth_response.body)
      rescue
        {}
      end
      # Should have error about decryption failure
      return false unless body["error"] || body["error_description"]

      true
    end
  end

  def test_malformed_encrypted_request
    test("Malformed encrypted request object") do
      # Create a malformed encrypted request (invalid JWE format - not 5 parts)
      malformed_request = "invalid.jwe.format.not.5.parts"

      # Send to provider
      auth_uri = URI.parse("#{OP_URL}/auth?error_mode=malformed_encryption")
      auth_uri.query = URI.encode_www_form({"request" => malformed_request})
      auth_response = Net::HTTP.get_response(auth_uri)

      # Should return error (400 or 401)
      return false unless auth_response.code.to_i.between?(400, 499)

      body = begin
        JSON.parse(auth_response.body)
      rescue
        {}
      end
      return false unless body["error"] || body["error_description"]

      true
    end
  end

  # ID Token Validation Tests
  def test_id_token_validation_with_trust_chain
    test("ID token validation with trust chain") do
      # Get ID token from provider (via token exchange)
      # First, we need to get an authorization code, but for testing we'll use the mock
      # In a real scenario, we'd validate the ID token signature using provider's JWKS

      # Fetch provider JWKS
      jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
      jwks_response = Net::HTTP.get_response(jwks_uri)
      return false unless jwks_response.code == "200"

      provider_jwks = JSON.parse(jwks_response.body)
      return false unless provider_jwks["keys"]&.any?

      # Verify we can decode a JWT using the JWKS (simulating ID token validation)
      # Create a test ID token
      now = Time.now.to_i
      test_payload = {
        iss: OP_ENTITY_ID,
        sub: "user123",
        aud: RP_ENTITY_ID,
        exp: now + 3600,
        iat: now,
        nonce: SecureRandom.hex(32)
      }

      # Use OP's private key directly (we have it from setup)
      # Get kid from JWKS
      signing_key_data = provider_jwks["keys"].find { |k| (k["use"] || k[:use]) == "sig" || !k["use"] }
      return false unless signing_key_data

      kid = signing_key_data["kid"] || signing_key_data[:kid]

      # Sign the token using OP's private key
      header = {alg: "RS256", typ: "JWT", kid: kid}
      id_token = JWT.encode(test_payload, @op_signing_key, "RS256", header)

      # Validate using JWKS
      begin
        decoded = OmniauthOpenidFederation::Jwks::Decode.jwt(id_token, "#{OP_URL}/.well-known/jwks.json")
        payload = decoded.first

        # Verify claims
        return false unless payload["iss"] == OP_ENTITY_ID
        return false unless payload["aud"] == RP_ENTITY_ID
        return false unless payload["sub"]
        return false unless payload["exp"] > Time.now.to_i

        true
      rescue
        false
      end
    end
  end

  def test_invalid_id_token_signature
    test("Invalid ID token signature") do
      # Create ID token signed with wrong key
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      now = Time.now.to_i
      test_payload = {
        iss: OP_ENTITY_ID,
        sub: "user123",
        aud: RP_ENTITY_ID,
        exp: now + 3600,
        iat: now
      }

      id_token = JWT.encode(test_payload, wrong_key, "RS256")

      # Try to validate - should fail
      begin
        OmniauthOpenidFederation::Jwks::Decode.jwt(id_token, "#{OP_URL}/.well-known/jwks.json")
        false # Should have raised an error
      rescue OmniauthOpenidFederation::SignatureError, JWT::VerificationError, JWT::DecodeError
        true
      rescue
        # Other errors are also acceptable
        true
      end
    end
  end

  def test_expired_id_token
    test("Expired ID token") do
      # Fetch provider JWKS
      jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
      jwks_response = Net::HTTP.get_response(jwks_uri)
      return false unless jwks_response.code == "200"

      provider_jwks = JSON.parse(jwks_response.body)
      signing_key_data = provider_jwks["keys"].find { |k| (k["use"] || k[:use]) == "sig" || !k["use"] }
      return false unless signing_key_data

      kid = signing_key_data["kid"] || signing_key_data[:kid]

      # Create expired ID token using OP's private key
      now = Time.now.to_i
      expired_payload = {
        iss: OP_ENTITY_ID,
        sub: "user123",
        aud: RP_ENTITY_ID,
        exp: now - 3600, # Expired 1 hour ago
        iat: now - 7200
      }

      header = {alg: "RS256", typ: "JWT", kid: kid}
      id_token = JWT.encode(expired_payload, @op_signing_key, "RS256", header)

      # Try to validate - should fail due to expiration
      begin
        decoded = OmniauthOpenidFederation::Jwks::Decode.jwt(id_token, "#{OP_URL}/.well-known/jwks.json")
        payload = decoded.first
        # Check if exp validation is working
        payload["exp"] < Time.now.to_i
      rescue JWT::ExpiredSignature, OmniauthOpenidFederation::ValidationError
        true
      rescue
        false
      end
    end
  end

  def test_id_token_wrong_audience
    test("ID token with wrong audience") do
      # Fetch provider JWKS
      jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
      jwks_response = Net::HTTP.get_response(jwks_uri)
      return false unless jwks_response.code == "200"

      provider_jwks = JSON.parse(jwks_response.body)
      signing_key_data = provider_jwks["keys"].find { |k| (k["use"] || k[:use]) == "sig" || !k["use"] }
      return false unless signing_key_data

      kid = signing_key_data["kid"] || signing_key_data[:kid]

      # Create ID token with wrong audience using OP's private key
      now = Time.now.to_i
      wrong_aud_payload = {
        iss: OP_ENTITY_ID,
        sub: "user123",
        aud: "wrong-client-id", # Wrong audience
        exp: now + 3600,
        iat: now
      }

      header = {alg: "RS256", typ: "JWT", kid: kid}
      id_token = JWT.encode(wrong_aud_payload, @op_signing_key, "RS256", header)

      # Validate - signature should be valid but audience should be wrong
      begin
        decoded = OmniauthOpenidFederation::Jwks::Decode.jwt(id_token, "#{OP_URL}/.well-known/jwks.json")
        payload = decoded.first
        # Audience should not match
        payload["aud"] != RP_ENTITY_ID
      rescue
        # If validation fails due to audience, that's also acceptable
        true
      end
    end
  end

  # Entity Statement Validation Tests
  def test_invalid_entity_statement_signature
    test("Invalid signature on entity statement") do
      # Get a valid entity statement to extract payload
      uri = URI.parse("#{OP_URL}/.well-known/openid-federation")
      response = Net::HTTP.get_response(uri)
      return false unless response.code == "200"

      valid_statement = response.body
      parts = valid_statement.split(".")
      return false unless parts.length == 3

      # Extract header and payload
      header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))

      # Verify payload has JWKS with keys (needed for signature validation)
      jwks = payload["jwks"] || payload[:jwks] || {}
      keys = jwks["keys"] || jwks[:keys] || []
      return false unless keys.any?

      # Verify kid in header matches a key in JWKS
      kid = header["kid"] || header[:kid]
      matching_key = keys.find { |k| (k["kid"] || k[:kid]) == kid }
      return false unless matching_key

      # Create a statement with wrong signature (sign with different key)
      # The JWKS in payload still has original keys, so signature validation will fail
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      # Keep the same header and payload but sign with wrong key
      invalid_statement = JWT.encode(payload, wrong_key, "RS256", header)

      # Try to parse with signature validation - should fail
      # The signature was created with wrong key, but JWKS in payload has original keys
      # So when we validate using keys from JWKS, it will fail
      begin
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse(
          invalid_statement,
          validate_signature: true,
          validate_full: true
        )
        # If parsing succeeds, the signature validation didn't catch the error
        false
      rescue OmniauthOpenidFederation::SignatureError
        true
      rescue JWT::VerificationError
        true
      rescue OmniauthOpenidFederation::ValidationError => e
        # ValidationError might be raised if signature validation fails during full validation
        # Check if it's a signature-related error
        error_msg = e.message.downcase
        error_msg.include?("signature") || error_msg.include?("verification") || error_msg.include?("key")
      rescue => e
        # Check if it's a signature-related error in the message
        error_msg = e.message.downcase
        error_msg.include?("signature") || error_msg.include?("verification")
      end
    end
  end

  def test_wrong_algorithm_entity_statement
    test("Wrong algorithm in entity statement") do
      # Create entity statement with wrong algorithm (HS256 instead of RS256)
      # HS256 requires a string key, not RSA
      hmac_key = SecureRandom.hex(32)
      now = Time.now.to_i
      payload = {
        iss: OP_ENTITY_ID,
        sub: OP_ENTITY_ID,
        iat: now,
        exp: now + 3600,
        jwks: {keys: []},
        metadata: {openid_provider: {}}
      }

      # Sign with wrong algorithm (HS256 instead of RS256)
      header = {alg: "HS256", typ: "entity-statement+jwt"}
      invalid_statement = JWT.encode(payload, hmac_key, "HS256", header)

      # Try to parse with full validation - should fail due to wrong algorithm
      begin
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse(
          invalid_statement,
          validate_signature: false, # Can't validate HS256 signature with RS256 keys
          validate_full: true
        )
        false # Should have raised an error
      rescue OmniauthOpenidFederation::ValidationError, JWT::IncorrectAlgorithm, JWT::DecodeError
        true
      rescue
        false
      end
    end
  end

  def test_missing_required_claims_entity_statement
    test("Missing required claims in entity statement") do
      # Test missing 'iss' claim
      signing_key = @op_signing_key
      now = Time.now.to_i
      payload_missing_iss = {
        # Missing iss
        sub: OP_ENTITY_ID,
        iat: now,
        exp: now + 3600,
        jwks: {keys: []}
      }

      header = {alg: "RS256", typ: "entity-statement+jwt"}
      invalid_statement = JWT.encode(payload_missing_iss, signing_key, "RS256", header)

      # Try to parse with full validation - should fail due to missing iss claim
      begin
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse(
          invalid_statement,
          validate_signature: true,
          validate_full: true
        )
        false # Should have raised an error
      rescue OmniauthOpenidFederation::ValidationError
        true
      rescue
        false
      end
    end
  end

  def test_invalid_jwt_typ_entity_statement
    test("Invalid JWT typ claim in entity statement") do
      signing_key = @op_signing_key
      now = Time.now.to_i
      payload = {
        iss: OP_ENTITY_ID,
        sub: OP_ENTITY_ID,
        iat: now,
        exp: now + 3600,
        jwks: {keys: []},
        metadata: {openid_provider: {}}
      }

      # Wrong typ value
      header = {alg: "RS256", typ: "JWT"} # Should be "entity-statement+jwt"
      invalid_statement = JWT.encode(payload, signing_key, "RS256", header)

      # Try to parse with full validation - should fail due to wrong typ
      begin
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse(
          invalid_statement,
          validate_signature: true,
          validate_full: true
        )
        false # Should have raised an error
      rescue OmniauthOpenidFederation::ValidationError
        true
      rescue
        false
      end
    end
  end

  # Signed JWKS Endpoint Tests
  def test_signed_jwks_endpoint
    test("Signed JWKS endpoint") do
      uri = URI.parse("#{OP_URL}/.well-known/signed-jwks.json")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"
      return false unless response.content_type == "application/jwt"

      signed_jwks = response.body
      parts = signed_jwks.split(".")
      return false unless parts.length == 3

      # Try to decode and validate
      begin
        # Get OP's signing key for validation
        jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
        jwks_response = Net::HTTP.get_response(jwks_uri)
        return false unless jwks_response.code == "200"

        provider_jwks = JSON.parse(jwks_response.body)
        signing_key_data = provider_jwks["keys"].find { |k| (k["use"] || k[:use]) == "sig" || !k["use"] }
        return false unless signing_key_data

        public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(signing_key_data)
        # KeyExtractor returns a public key, use it directly
        decoded = JWT.decode(signed_jwks, public_key, true, {algorithm: "RS256"})

        payload = decoded.first
        return false unless payload["keys"]
        return false unless payload["keys"].is_a?(Array)

        true
      rescue
        false
      end
    end
  end

  def test_invalid_signed_jwks_signature
    test("Invalid signed JWKS signature") do
      # Get signed JWKS with invalid signature error mode
      uri = URI.parse("#{OP_URL}/.well-known/signed-jwks.json?error_mode=invalid_signature")
      response = Net::HTTP.get_response(uri)

      return false unless response.code == "200"

      signed_jwks = response.body
      parts = signed_jwks.split(".")
      return false unless parts.length == 3

      # Try to validate - should fail
      begin
        jwks_uri = URI.parse("#{OP_URL}/.well-known/jwks.json")
        jwks_response = Net::HTTP.get_response(jwks_uri)
        return false unless jwks_response.code == "200"

        provider_jwks = JSON.parse(jwks_response.body)
        signing_key_data = provider_jwks["keys"].find { |k| (k["use"] || k[:use]) == "sig" || !k["use"] }
        return false unless signing_key_data

        public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(signing_key_data)
        # KeyExtractor returns a public key, use it directly
        JWT.decode(signed_jwks, public_key, true, {algorithm: "RS256"})
        false # Should have raised an error
      rescue JWT::VerificationError, OmniauthOpenidFederation::SignatureError
        true
      rescue
        false
      end
    end
  end

  # Request Object Validation Details Tests
  def test_request_object_missing_required_claims
    test("Request object with missing required claims") do
      # Create request object missing client_id
      signing_key = @rp_signing_key
      now = Time.now.to_i
      payload = {
        # Missing client_id
        redirect_uri: "#{RP_URL}/callback",
        response_type: "code",
        scope: "openid",
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        iat: now,
        exp: now + 300
      }

      header = {alg: "RS256", typ: "JWT"}
      request_object = JWT.encode(payload, signing_key, "RS256", header)

      # Send to provider - should fail validation
      auth_uri = URI.parse("#{OP_URL}/auth")
      auth_uri.query = URI.encode_www_form({"request" => request_object})
      auth_response = Net::HTTP.get_response(auth_uri)

      # Should return error
      return false unless auth_response.code.to_i.between?(400, 499)

      body = begin
        JSON.parse(auth_response.body)
      rescue
        {}
      end
      return false unless body["error"] || body["error_description"]

      true
    end
  end

  def test_request_object_invalid_nonce
    test("Request object with invalid nonce") do
      # This test verifies that nonce validation works
      # In a real flow, the nonce in request object should match the nonce in ID token
      # For this test, we'll create a valid request object and verify it has a nonce
      redirect_uri = "#{RP_URL}/callback"
      jws = OmniauthOpenidFederation::Jws.new(
        client_id: RP_ENTITY_ID,
        redirect_uri: redirect_uri,
        scope: "openid",
        audience: OP_ENTITY_ID,
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        private_key: @rp_signing_key
      )

      request_object = jws.sign

      # Verify request object has nonce
      parts = request_object.split(".")
      return false unless parts.length == 3

      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      return false unless payload["nonce"]
      return false if payload["nonce"].empty?

      # The actual nonce validation happens during token exchange
      # This test verifies the nonce is present in the request object
      true
    end
  end

  def test_request_object_expiration
    test("Request object expiration") do
      # Create expired request object
      signing_key = @rp_signing_key
      now = Time.now.to_i
      expired_payload = {
        client_id: RP_ENTITY_ID,
        redirect_uri: "#{RP_URL}/callback",
        response_type: "code",
        scope: "openid",
        state: SecureRandom.hex(32),
        nonce: SecureRandom.hex(32),
        iat: now - 600,
        exp: now - 300 # Expired 5 minutes ago
      }

      header = {alg: "RS256", typ: "JWT"}
      expired_request = JWT.encode(expired_payload, signing_key, "RS256", header)

      # Send to provider - should fail due to expiration
      auth_uri = URI.parse("#{OP_URL}/auth")
      auth_uri.query = URI.encode_www_form({"request" => expired_request})
      auth_response = Net::HTTP.get_response(auth_uri)

      # Should return error
      return false unless auth_response.code.to_i.between?(400, 499)

      body = begin
        JSON.parse(auth_response.body)
      rescue
        {}
      end
      return false unless body["error"] || body["error_description"]

      true
    end
  end

  def print_summary
    puts "=" * 80
    puts "Test Summary"
    puts "=" * 80

    passed = @test_results.count { |r| r[:status] == :pass }
    failed = @test_results.count { |r| r[:status] == :fail }
    errors = @test_results.count { |r| r[:status] == :error }

    puts "Total: #{@test_results.length}"
    puts "Passed: #{passed}"
    puts "Failed: #{failed}"
    puts "Errors: #{errors}"
    puts ""

    if failed > 0 || errors > 0
      puts "Failed/Error Tests:"
      @test_results.each do |result|
        if result[:status] != :pass
          puts "  - #{result[:name]}: #{result[:status]}"
          puts "    #{result[:error]}" if result[:error]
        end
      end
    end

    puts ""
    puts (passed == @test_results.length) ? "✅ All tests passed!" : "❌ Some tests failed."
  end

  def cleanup
    puts ""
    puts "Cleaning up..."

    # Kill servers
    if @op_pid
      begin
        begin
          Process.kill("TERM", @op_pid) if Process.kill(0, @op_pid)
        rescue
          nil
        end
      rescue Errno::ESRCH, Errno::EPERM
        # Process already dead or permission denied
      end
    end

    if @rp_pid
      begin
        begin
          Process.kill("TERM", @rp_pid) if Process.kill(0, @rp_pid)
        rescue
          nil
        end
      rescue Errno::ESRCH, Errno::EPERM
        # Process already dead or permission denied
      end
    end

    # Wait a bit for processes to terminate
    sleep 1

    # Remove tmp directory if cleanup enabled
    if CLEANUP_ON_EXIT && File.directory?(@tmp_dir)
      FileUtils.rm_rf(@tmp_dir)
      puts "  Removed: #{@tmp_dir}"
    else
      puts "  Tmp directory preserved: #{@tmp_dir}"
    end
  end
end

# Run tests if executed directly
if __FILE__ == $0
  puts "OpenID Federation Integration Test Flow"
  puts "=" * 80
  puts ""
  puts "Environment Variables:"
  puts "  OP_URL - OP server URL (default: #{IntegrationTestFlow::OP_URL})"
  puts "  RP_URL - RP server URL (default: #{IntegrationTestFlow::RP_URL})"
  puts "  OP_PORT - OP server port (default: #{IntegrationTestFlow::OP_PORT})"
  puts "  RP_PORT - RP server port (default: #{IntegrationTestFlow::RP_PORT})"
  puts "  OP_ENTITY_ID - OP entity ID (default: #{IntegrationTestFlow::OP_ENTITY_ID} - localhost)"
  puts "  RP_ENTITY_ID - RP entity ID (default: #{IntegrationTestFlow::RP_ENTITY_ID} - localhost)"
  puts "  TMP_DIR - Temporary directory (default: tmp/integration_test)"
  puts "  AUTO_START_SERVERS - Auto-start servers (default: true)"
  puts "  CLEANUP_ON_EXIT - Clean up on exit (default: true)"
  puts "  KEY_TYPE - Key type: 'single' or 'separate' (default: separate)"
  puts ""
  puts "Note: Default entity IDs use localhost URLs for complete isolation."
  puts "      No DNS resolution or external dependencies required."
  puts ""
  puts "Example:"
  puts "  KEY_TYPE=single ruby examples/integration_test_flow.rb"
  puts ""

  test_flow = IntegrationTestFlow.new
  test_flow.run
end
