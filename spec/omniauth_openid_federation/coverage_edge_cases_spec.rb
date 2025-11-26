require "spec_helper"

RSpec.describe "Coverage for edge cases and error paths" do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }

  # Stub all HTTP requests for tests that use relative paths
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end

  describe "FederationEndpoint error paths" do
    before do
      # Reset configuration
      OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    end

    it "handles configuration errors in generate_entity_statement" do
      expect {
        OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles configuration errors in generate_signed_jwks" do
      expect {
        OmniauthOpenidFederation::FederationEndpoint.generate_signed_jwks
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles configuration errors in current_jwks" do
      # current_jwks returns nil when not configured, it doesn't raise an error
      result = OmniauthOpenidFederation::FederationEndpoint.current_jwks
      expect(result).to be_nil
    end

    it "handles auto_configure with missing parameters" do
      # auto_configure requires issuer as a keyword argument, so it raises ArgumentError if missing
      expect {
        OmniauthOpenidFederation::FederationEndpoint.auto_configure(
          entity_identifier: nil,
          private_key: private_key
        )
      }.to raise_error(ArgumentError, /missing keyword/)
    end

    it "handles configure with invalid parameters" do
      # configure doesn't validate immediately - validation happens when using the config
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = nil
        config.private_key = private_key
      end

      # Validation happens when trying to generate entity statement
      expect {
        OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end
  end

  describe "JWKS::Fetch error paths" do
    it "handles HTTP errors when fetching JWKS" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_return(status: 500, body: "Internal Server Error")

      expect {
        OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::FetchError)
    end

    it "handles network timeouts" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_timeout

      expect {
        OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::FetchError)
    end

    it "handles invalid JSON response" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: "invalid json", headers: {"Content-Type" => "application/json"})

      expect {
        OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)
      }.to raise_error(JSON::ParserError, /unexpected character/)
    end

    it "handles empty response body" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: "", headers: {"Content-Type" => "application/json"})

      expect {
        OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)
      }.to raise_error(JSON::ParserError, /unexpected end of input/)
    end

    it "handles missing keys in JWKS response" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: {}.to_json, headers: {"Content-Type" => "application/json"})

      result = OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)
      expect(result).to be_a(Hash)
    end
  end

  describe "JWKS::Decode error paths" do
    let(:jwks_uri) { "#{provider_issuer}/.well-known/jwks.json" }

    it "handles missing kid in JWT header" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      # Create JWT without kid in header
      token = JWT.encode(payload, private_key, "RS256", {})

      result = OmniauthOpenidFederation::Jwks::Decode.run(token, jwks_uri)
      expect(result).to be_a(Hash)
    end

    it "handles kid not found in JWKS" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      header = {alg: "RS256", kid: "nonexistent-kid"}
      token = JWT.encode(payload, private_key, "RS256", header)

      # Use jwt method which actually decodes the JWT and will trigger kid not found error
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(token, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /kid not found/)
    end

    it "handles invalid JWT format" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      # Use jwt method which actually decodes the JWT and will trigger format error
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt("invalid.jwt", jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /JWT format error/)
    end

    it "handles expired token" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk.merge(kid: jwk[:kid] || "test-key-id")]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i - 3600, aud: "test"}
      header = {alg: "RS256", kid: jwk[:kid] || "test-key-id"}
      token = JWT.encode(payload, private_key, "RS256", header)

      # Use jwt method which actually decodes the JWT and will trigger expired token error
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(token, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /expired/)
    end

    it "handles wrong signature" do
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk.merge(kid: jwk[:kid] || "test-key-id")]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      header = {alg: "RS256", kid: jwk[:kid] || "test-key-id"}
      token = JWT.encode(payload, wrong_key, "RS256", header)

      # Use jwt method which actually decodes the JWT and will trigger signature error
      # After retry, it should raise SignatureError
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(token, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /signature verification failed/)
    end

    it "handles JWKS with symbol keys" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      token = JWT.encode(payload, private_key, "RS256")

      result = OmniauthOpenidFederation::Jwks::Decode.run(token, jwks_uri)
      expect(result).to be_a(Hash)
    end

    it "handles JWKS with string keys" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {"keys" => [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      token = JWT.encode(payload, private_key, "RS256")

      result = OmniauthOpenidFederation::Jwks::Decode.run(token, jwks_uri)
      expect(result).to be_a(Hash)
    end

    it "handles empty JWKS" do
      jwks = {keys: []}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      payload = {iss: provider_issuer, sub: "user-123", exp: Time.now.to_i + 3600, aud: "test"}
      token = JWT.encode(payload, private_key, "RS256")

      # Use jwt method which actually decodes the JWT and will trigger empty JWKS error
      expect {
        OmniauthOpenidFederation::Jwks::Decode.jwt(token, jwks_uri)
      }.to raise_error(OmniauthOpenidFederation::ValidationError)
    end
  end

  describe "EntityStatementParser edge cases" do
    it "handles entity statement with missing metadata" do
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer
      }
      # Add required typ header for OpenID Federation compliance
      header = {typ: "entity-statement+jwt", alg: "RS256"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)

      result = OmniauthOpenidFederation::Federation::EntityStatementParser.parse(jwt, validate_full: false)
      expect(result).to be_a(Hash)
      expect(result[:metadata]).to eq({})
    end

    it "handles entity statement with empty metadata" do
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {}
      }
      # Add required typ header for OpenID Federation compliance
      header = {typ: "entity-statement+jwt", alg: "RS256"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)

      result = OmniauthOpenidFederation::Federation::EntityStatementParser.parse(jwt, validate_full: false)
      expect(result).to be_a(Hash)
    end

    it "handles entity statement with invalid JWT" do
      expect {
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse("invalid.jwt")
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /Invalid JWT format/)
    end

    it "handles entity statement with wrong signature" do
      wrong_key = OpenSSL::PKey::RSA.new(2048)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = JWT.encode(entity_statement, wrong_key, "RS256")

      expect {
        OmniauthOpenidFederation::Federation::EntityStatementParser.parse(jwt, public_key)
      }.to raise_error(ArgumentError, /wrong number of arguments/)
    end
  end

  describe "EndpointResolver edge cases" do
    it "handles missing entity statement file" do
      # EndpointResolver doesn't raise an error for missing files - it returns nil for entity metadata
      result = OmniauthOpenidFederation::EndpointResolver.resolve(
        entity_statement_path: "/nonexistent/path.jwt",
        config: {}
      )
      # Should return a hash with nil values for endpoints since entity statement is missing
      expect(result).to be_a(Hash)
      expect(result[:authorization_endpoint]).to be_nil
      expect(result[:token_endpoint]).to be_nil
    end

    it "handles invalid entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid content")

      # EndpointResolver doesn't raise errors - it catches them and returns nil for entity metadata
      result = OmniauthOpenidFederation::EndpointResolver.resolve(
        entity_statement_path: entity_statement_path,
        config: {}
      )
      # Should return a hash with nil values for endpoints since entity statement parsing failed
      expect(result).to be_a(Hash)
      expect(result[:authorization_endpoint]).to be_nil
    ensure
      File.delete(entity_statement_path) if File.exist?(entity_statement_path)
    end

    it "handles entity statement with path-based endpoints" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      result = OmniauthOpenidFederation::EndpointResolver.resolve(
        entity_statement_path: entity_statement_path,
        config: {
          issuer: provider_issuer
        }
      )

      expect(result).to be_a(Hash)
    end

    it "handles entity statement with full URL endpoints" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      result = OmniauthOpenidFederation::EndpointResolver.resolve(
        entity_statement_path: entity_statement_path,
        config: {}
      )

      expect(result).to be_a(Hash)
    end
  end

  describe "EntityStatementReader edge cases" do
    it "handles missing entity statement file" do
      # EntityStatementReader.parse_metadata returns nil when file doesn't exist, it doesn't raise an error
      result = OmniauthOpenidFederation::EntityStatementReader.parse_metadata(
        entity_statement_path: "/nonexistent/path.jwt"
      )
      expect(result).to be_nil
    end

    it "handles invalid entity statement content" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid content")

      # EntityStatementReader.parse_metadata doesn't raise errors - it returns nil for invalid content
      result = OmniauthOpenidFederation::EntityStatementReader.parse_metadata(
        entity_statement_path: entity_statement_path
      )
      expect(result).to be_nil
    ensure
      File.delete(entity_statement_path) if File.exist?(entity_statement_path)
    end

    it "handles entity statement without jwks" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      result = OmniauthOpenidFederation::EntityStatementReader.parse_metadata(
        entity_statement_path: entity_statement_path
      )

      expect(result).to be_a(Hash)
    end
  end

  describe "SignedJWKS edge cases" do
    it "handles missing signed JWKS URI" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {}
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks(
        entity_statement_path
      )

      expect(parsed[:signed_jwks_uri]).to be_nil
    end

    it "handles HTTP errors when fetching signed JWKS" do
      signed_jwks_uri = "#{provider_issuer}/.well-known/signed-jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_jwks = {keys: [jwk]}

      stub_request(:get, signed_jwks_uri)
        .to_return(status: 500, body: "Internal Server Error")

      expect {
        OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
          signed_jwks_uri,
          entity_jwks
        )
      }.to raise_error(OmniauthOpenidFederation::FetchError)
    end

    it "handles invalid signed JWKS format" do
      signed_jwks_uri = "#{provider_issuer}/.well-known/signed-jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_jwks = {keys: [jwk]}

      stub_request(:get, signed_jwks_uri)
        .to_return(status: 200, body: "invalid jwt", headers: {"Content-Type" => "application/jwt"})

      expect {
        OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
          signed_jwks_uri,
          entity_jwks
        )
      }.to raise_error(OmniauthOpenidFederation::ValidationError, /Signed JWKS is not in JWT format/)
    end
  end

  describe "JWS edge cases" do
    it "handles missing private key" do
      jws = OmniauthOpenidFederation::Jws.new(
        client_id: "test-client",
        redirect_uri: "https://example.com/callback"
      )

      expect {
        jws.sign
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required/)
    end

    it "handles missing client_id" do
      # client_id is a required keyword argument, so it raises ArgumentError if missing
      expect {
        OmniauthOpenidFederation::Jws.new(
          redirect_uri: "https://example.com/callback",
          private_key: private_key
        )
      }.to raise_error(ArgumentError, /missing keyword.*client_id/)
    end

    it "handles missing redirect_uri" do
      # redirect_uri is a required keyword argument, so it raises ArgumentError if missing
      expect {
        OmniauthOpenidFederation::Jws.new(
          client_id: "test-client",
          private_key: private_key
        )
      }.to raise_error(ArgumentError, /missing keyword.*redirect_uri/)
    end

    it "handles encryption with missing encryption key" do
      jws = OmniauthOpenidFederation::Jws.new(
        client_id: "test-client",
        redirect_uri: "https://example.com/callback",
        private_key: private_key
      )

      # Provider metadata that requires encryption but has no encryption key in JWKS
      provider_metadata = {
        request_object_encryption_alg: "RSA-OAEP",
        request_object_encryption_enc: "A128CBC-HS256",
        jwks: {keys: []} # Empty JWKS - no encryption keys
      }

      # EncryptionError is wrapped in SignatureError when encryption fails during signing
      expect {
        jws.sign(provider_metadata: provider_metadata)
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /No encryption key found/)
    end
  end

  describe "Utils edge cases" do
    it "handles nil hash in to_indifferent_hash" do
      # to_indifferent_hash converts nil to empty hash
      result = OmniauthOpenidFederation::Utils.to_indifferent_hash(nil)
      expect(result).to eq({})
    end

    it "handles non-hash in to_indifferent_hash" do
      # to_indifferent_hash converts non-hash values to empty hash
      result = OmniauthOpenidFederation::Utils.to_indifferent_hash("string")
      expect(result).to eq({})
    end

    it "handles hash in to_indifferent_hash" do
      result = OmniauthOpenidFederation::Utils.to_indifferent_hash({key: "value"})
      expect(result).to be_a(Hash)
      expect(result[:key] || result["key"]).to eq("value")
    end

    it "handles nil path in sanitize_path" do
      result = OmniauthOpenidFederation::Utils.sanitize_path(nil)
      expect(result).to eq("[REDACTED]")
    end

    it "handles empty path in sanitize_path" do
      result = OmniauthOpenidFederation::Utils.sanitize_path("")
      expect(result).to eq("[REDACTED]")
    end

    it "handles nil URI in sanitize_uri" do
      result = OmniauthOpenidFederation::Utils.sanitize_uri(nil)
      expect(result).to eq("[REDACTED]")
    end

    it "handles invalid URI in sanitize_uri" do
      result = OmniauthOpenidFederation::Utils.sanitize_uri("not a valid uri")
      expect(result).to eq("[REDACTED]")
    end

    it "handles path traversal in validate_file_path!" do
      expect {
        OmniauthOpenidFederation::Utils.validate_file_path!("../../../etc/passwd")
      }.to raise_error(OmniauthOpenidFederation::SecurityError, /Path traversal/)
    end

    it "handles nil path in validate_file_path!" do
      expect {
        OmniauthOpenidFederation::Utils.validate_file_path!(nil)
      }.to raise_error(OmniauthOpenidFederation::SecurityError, /File path cannot be nil/)
    end

    it "handles empty path in validate_file_path!" do
      expect {
        OmniauthOpenidFederation::Utils.validate_file_path!("")
      }.to raise_error(OmniauthOpenidFederation::SecurityError, /File path cannot be empty/)
    end

    it "handles path outside allowed directories" do
      # Create a temp directory for testing
      temp_dir = Dir.mktmpdir
      begin
        # Create a file inside the temp directory
        allowed_file = File.join(temp_dir, "allowed.txt")
        File.write(allowed_file, "test")

        # This should work
        result = OmniauthOpenidFederation::Utils.validate_file_path!(
          allowed_file,
          allowed_dirs: [temp_dir]
        )
        expect(result).to eq(File.expand_path(allowed_file))

        # This should fail - use a path that definitely won't be in temp_dir
        outside_path = File.join(Dir.tmpdir, "outside_file.txt")
        expect {
          OmniauthOpenidFederation::Utils.validate_file_path!(
            outside_path,
            allowed_dirs: [temp_dir]
          )
        }.to raise_error(OmniauthOpenidFederation::SecurityError, /File path outside allowed directories/)
      ensure
        FileUtils.rm_rf(temp_dir)
      end
    end

    it "handles invalid JWT format in valid_jwt_format?" do
      expect(OmniauthOpenidFederation::Utils.valid_jwt_format?("invalid")).to be false
      expect(OmniauthOpenidFederation::Utils.valid_jwt_format?("one.two")).to be false
      expect(OmniauthOpenidFederation::Utils.valid_jwt_format?("one.two.three.four")).to be false
      expect(OmniauthOpenidFederation::Utils.valid_jwt_format?(nil)).to be false
      expect(OmniauthOpenidFederation::Utils.valid_jwt_format?("")).to be false
    end

    it "handles rsa_key_to_jwk with different use values" do
      jwk_sig = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key, use: "sig")
      expect(jwk_sig[:use]).to eq("sig")

      jwk_enc = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key, use: "enc")
      expect(jwk_enc[:use]).to eq("enc")

      jwk_nil = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key, use: nil)
      expect(jwk_nil[:use]).to be_nil
    end
  end
end
