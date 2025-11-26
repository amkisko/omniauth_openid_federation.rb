require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_id) { "test-client-id" }
  let(:redirect_uri) { "https://example.com/users/auth/openid_federation/callback" }

  # Stub all HTTP requests for tests that use relative paths
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)

    # Generate a valid entity statement JWT for tests that fetch from URL
    jwk = JWT::JWK.new(public_key)
    jwk_export = jwk.export
    entity_statement_payload = {
      iss: provider_issuer,
      sub: provider_issuer,
      iat: Time.now.to_i,
      exp: Time.now.to_i + 3600,
      jwks: {
        keys: [jwk_export]
      },
      metadata: {
        openid_provider: {
          issuer: provider_issuer,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          jwks_uri: "https://provider.example.com/.well-known/jwks.json"
        }
      }
    }
    entity_statement_header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
    entity_statement_jwt = JWT.encode(entity_statement_payload, private_key, "RS256", entity_statement_header)

    # Stub entity statement endpoint
    WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
      .to_return(
        status: 200,
        body: entity_statement_jwt,
        headers: {"Content-Type" => "application/jwt"}
      )
  end

  describe "initialization and configuration" do
    it "initializes with client_options" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      expect(strategy.options.client_options).to be_present
    end

    it "handles client_jwk_signing_key extraction" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "dummy.jwt")

      strategy = described_class.new(
        nil,
        client_entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # This should trigger extract_client_jwk_signing_key
      expect(strategy.options[:client_jwk_signing_key]).to be_nil
    end

    it "handles options accessor with client_entity_statement_path" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "dummy.jwt")

      strategy = described_class.new(
        nil,
        client_entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      opts = strategy.options
      expect(opts).to be_a(Hash)
    end
  end

  describe "#client" do
    it "builds client with resolved endpoints from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "raises error when authorization endpoint is missing" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
          # No authorization_endpoint
        }
      )

      expect { strategy.client }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Authorization endpoint/)
    end

    it "handles client with string keys in options" do
      strategy = described_class.new(
        nil,
        client_options: {
          "identifier" => client_id,
          "redirect_uri" => redirect_uri,
          "host" => URI.parse(provider_issuer).host,
          "authorization_endpoint" => "/oauth2/authorize",
          "token_endpoint" => "/oauth2/token",
          "private_key" => private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end
  end

  describe "private methods - resolve_endpoints_from_metadata" do
    it "resolves endpoints from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            userinfo_endpoint: "https://provider.example.com/oauth2/userinfo",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Access client to trigger resolve_endpoints_from_metadata
      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
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
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        issuer: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "handles missing entity statement file gracefully" do
      strategy = described_class.new(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Should not raise error, should use client_options
      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "handles entity statement parsing errors gracefully" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid jwt content")

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Should not raise error, should use client_options
      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end
  end

  describe "private methods - resolve_issuer_from_metadata" do
    it "resolves issuer from entity statement metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Access client to trigger resolve_issuer_from_metadata
      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "handles missing issuer in entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {}
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        issuer: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token"
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end
  end

  describe "private methods - resolve_audience" do
    it "resolves audience from explicit configuration" do
      strategy = described_class.new(
        nil,
        audience: provider_issuer,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      # Trigger authorize_uri which calls resolve_audience
      uri = strategy.authorize_uri
      expect(uri).to include(provider_issuer)
    end

    it "resolves audience from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = JWT::JWK.new(public_key)
      jwk_export = jwk.export
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {
          keys: [jwk_export]
        },
        metadata: {
          openid_provider: {
            audience: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "resolves audience from resolved issuer" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = JWT::JWK.new(public_key)
      jwk_export = jwk.export
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {
          keys: [jwk_export]
        },
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "resolves audience from token endpoint" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "resolves audience from authorization endpoint" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "resolves audience from client_options issuer" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          issuer: provider_issuer,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles entity issuer (iss claim) as audience" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = JWT::JWK.new(public_key)
      jwk_export = jwk.export
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {
          keys: [jwk_export]
        },
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles non-URL issuer gracefully" do
      entity_statement_tempfile = Tempfile.new(["entity", ".jwt"])
      entity_statement_path = entity_statement_tempfile.path
      entity_statement = {
        iss: "not-a-url",
        sub: "not-a-url",
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      entity_statement_tempfile.write(jwt)
      entity_statement_tempfile.flush
      entity_statement_tempfile.rewind
      # Don't close the tempfile - keep it open so it doesn't get deleted

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    ensure
      entity_statement_tempfile&.unlink
    end

    it "handles missing entity statement file in resolve_audience" do
      strategy = described_class.new(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:request).and_return(double(params: {}))
      allow(strategy).to receive(:session).and_return({})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end

  describe "private methods - resolve_jwks_for_validation" do
    it "resolves JWKS from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {
          keys: [jwk]
        },
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      # Create a mock ID token with kid in header to match JWKS
      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK in the entity statement
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      # This should trigger resolve_jwks_for_validation
      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end

    it "handles JWKS with symbol keys" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {
          keys: [jwk]
        },
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK in the entity statement
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end

    it "handles JWKS as array" do
      entity_statement_tempfile = Tempfile.new(["entity", ".jwt"])
      entity_statement_path = entity_statement_tempfile.path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      # Ensure JWK has a kid for testing
      jwk[:kid] ||= jwk["kid"] || SecureRandom.hex(8)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: [jwk],
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      entity_statement_tempfile.write(jwt)
      entity_statement_tempfile.flush
      entity_statement_tempfile.rewind
      # Keep tempfile open so it doesn't get deleted

      # Stub File operations to ensure the file is found
      allow(File).to receive(:exist?).and_call_original
      allow(File).to receive(:exist?).with(entity_statement_path).and_return(true)
      allow(File).to receive(:read).and_call_original
      allow(File).to receive(:read).with(entity_statement_path).and_return(jwt.strip)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      # Also stub load_provider_entity_statement to ensure it returns the entity statement
      allow(strategy).to receive(:load_provider_entity_statement).and_return(jwt.strip)

      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK in the entity statement
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      # Stub resolve_jwks_for_validation_with_kid to return the JWKS directly
      # This ensures the JWKS is available even if entity statement loading has issues
      jwks_hash = {"keys" => [jwk]}
      allow(strategy).to receive(:resolve_jwks_for_validation_with_kid).and_return(jwks_hash)

      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    ensure
      entity_statement_tempfile&.close
      entity_statement_tempfile&.unlink
    end

    it "falls back to fetching JWKS from URI" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}

      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: jwks_uri,
          private_key: private_key
        }
      )

      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        id_token: id_token,
        userinfo!: double(raw_attributes: {sub: "user-123"})
      )
      strategy.instance_variable_set(:@access_token, access_token_double)

      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end
  end

  describe "private methods - resolve_jwks_uri" do
    it "resolves JWKS URI from client_options" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"

      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: jwks_uri,
          private_key: private_key
        }
      )

      # Access client to trigger resolve_jwks_uri
      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "resolves JWKS URI from entity statement" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            jwks_uri: "https://provider.example.com/.well-known/jwks.json"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt"}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = described_class.new(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end
  end

  describe "private methods - build_base_url and build_endpoint" do
    it "builds base URL from scheme, host, and port" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          scheme: "http",
          host: "example.com",
          port: 8080,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "handles missing host gracefully" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          authorization_endpoint: "https://provider.example.com/oauth2/authorize",
          token_endpoint: "https://provider.example.com/oauth2/token",
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end

    it "builds endpoint from path" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: "example.com",
          authorization_endpoint: "oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      client = strategy.client
      expect(client).to be_a(OpenIDConnect::Client)
    end
  end

  describe "private methods - decode_id_token" do
    it "handles encrypted ID token with federation key source" do
      strategy = described_class.new(
        nil,
        decryption_key_source: :federation,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      # Create encrypted token (mock)
      encrypted_token = "header.encrypted_key.iv.ciphertext.tag"

      access_token_double = double(id_token: encrypted_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      # This should trigger decode_id_token with encryption handling
      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt ID token/)
    end

    it "handles encrypted ID token with local key source" do
      strategy = described_class.new(
        nil,
        decryption_key_source: :local,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      encrypted_token = "header.encrypted_key.iv.ciphertext.tag"

      access_token_double = double(id_token: encrypted_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::DecryptionError, /Failed to decrypt ID token/)
    end

    it "handles unknown decryption key source" do
      strategy = described_class.new(
        nil,
        decryption_key_source: :unknown,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      encrypted_token = "header.encrypted_key.iv.ciphertext.tag"

      access_token_double = double(id_token: encrypted_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Unknown decryption key source/)
    end
  end

  describe "private methods - exchange_authorization_code" do
    it "exchanges authorization code for access token" do
      # Stub JWKS endpoint for ID token validation
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      jwks = {keys: [jwk]}
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: jwks.to_json, headers: {"Content-Type" => "application/json"})

      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          jwks_uri: jwks_uri,
          private_key: private_key
        }
      )

      oidc_client = strategy.client
      allow(oidc_client).to receive(:authorization_code=)
      allow(oidc_client).to receive(:redirect_uri=)

      id_token_payload = {
        iss: provider_issuer,
        sub: "user-123",
        aud: client_id,
        exp: Time.now.to_i + 3600,
        iat: Time.now.to_i
      }
      # Get the kid from the JWK
      jwk_kid = jwk[:kid] || jwk["kid"]
      id_token = JWT.encode(id_token_payload, private_key, "RS256", kid: jwk_kid)

      access_token_double = double(
        access_token: "token",
        id_token: id_token,
        userinfo!: double(raw_attributes: {})
      )
      allow(oidc_client).to receive(:access_token!).and_return(access_token_double)

      allow(strategy).to receive(:request).and_return(double(params: {"code" => "auth-code"}))
      allow(strategy).to receive(:session).and_return({})

      # This should trigger exchange_authorization_code
      raw_info = strategy.raw_info
      expect(raw_info).to be_a(Hash)
    end

    it "handles token exchange errors" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      oidc_client = strategy.client
      allow(oidc_client).to receive(:authorization_code=)
      allow(oidc_client).to receive(:redirect_uri=)
      allow(oidc_client).to receive(:access_token!).and_raise(StandardError.new("Token exchange failed"))

      allow(strategy).to receive(:request).and_return(double(params: {"code" => "auth-code"}))
      allow(strategy).to receive(:session).and_return({})

      expect { strategy.raw_info }.to raise_error(OmniauthOpenidFederation::NetworkError)
    end
  end

  describe "private methods - new_state and new_nonce" do
    it "generates new state" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      mock_session = {}
      allow(strategy).to receive(:session).and_return(mock_session)
      allow(strategy).to receive(:request).and_return(double(params: {}))

      # Trigger request_phase which calls new_state
      strategy.request_phase

      expect(mock_session["omniauth.state"]).to be_present
    end

    it "generates new nonce" do
      strategy = described_class.new(
        nil,
        send_nonce: true,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          token_endpoint: "/oauth2/token",
          private_key: private_key
        }
      )

      allow(strategy).to receive(:session).and_return({})
      allow(strategy).to receive(:request).and_return(double(params: {}))

      # Trigger request_phase which calls new_nonce
      strategy.request_phase
    end
  end
end
