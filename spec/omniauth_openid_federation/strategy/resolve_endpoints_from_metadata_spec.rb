require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do
  include_context "strategy federation endpoint stub"

  describe "resolve_endpoints_from_metadata - all branches" do
    it "returns empty hash when entity_statement_path is nil" do
      strategy = build_strategy(
        nil,
        client_options: relative_path_client_options
      )

      # Behavior: When no entity statement, client should still work with configured endpoints
      client = strategy.client
      expect(client).to be_present
    end

    it "handles entity statement with issuer in metadata" do
      entity_statement_path = write_simple_entity_statement_file({
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {openid_provider: provider_openid_metadata}
      })

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      # Behavior: Client should resolve endpoints from entity statement
      client = strategy.client
      expect(client).to be_present
    end

    it "handles entity statement with entity_issuer fallback" do
      entity_statement_path = write_simple_entity_statement_file({
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {openid_provider: provider_openid_metadata.except(:issuer)}
      })

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      # Behavior: Client should resolve endpoints using entity_issuer fallback
      client = strategy.client
      expect(client).to be_present
    end

    it "handles errors in resolve_endpoints_from_metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      # Behavior: When entity statement parsing fails, should fall back to configured endpoints
      client = strategy.client
      expect(client).to be_present
    end
  end

  describe "resolve_issuer_from_metadata - all branches" do
    it "returns nil when entity_statement_path is nil" do
      strategy = build_strategy(
        nil,
        client_options: relative_path_client_options
      )

      # Behavior: When no entity statement, should use configured issuer or fail gracefully
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "uses entity issuer when metadata is nil" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer
        # No metadata section - this will cause parse_metadata to return metadata with entity_issuer
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      File.write(entity_statement_path, jwt)

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      # Behavior: Should use entity issuer (iss claim) when metadata doesn't have issuer
      uri = strategy.authorize_uri
      # Verify the JWT payload contains the issuer as audience
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["aud"]).to eq(provider_issuer)
      end
    end

    it "handles errors in resolve_issuer_from_metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      # Behavior: When entity statement parsing fails, should fall back to configured issuer or fail
      # Since we have configured endpoints, it should use those
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end

  describe "resolve_audience - all branches" do
    it "handles entity issuer (iss claim) as audience fallback" do
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
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: jwk_export[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles non-URL entity issuer gracefully" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
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
      File.write(entity_statement_path, jwt)

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

      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles token endpoint from resolved endpoints" do
      entity_statement_path = write_simple_entity_statement_file({
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {openid_provider: provider_openid_metadata.except(:issuer)}
      })

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles token endpoint from client" do
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

      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "uses authorization endpoint URL as audience when entity statement is unavailable" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      uri = strategy.authorize_uri
      aggregate_failures do
        expect(uri).to be_present
        expect(uri).to include("/oauth2/authorize")
      end
    end

    it "uses client-provided authorization endpoint for audience resolution" do
      strategy = described_class.new(
        nil,
        client_options: {
          identifier: client_id,
          redirect_uri: redirect_uri,
          host: URI.parse(provider_issuer).host,
          authorization_endpoint: "/oauth2/authorize",
          private_key: private_key
        }
      )

      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      uri = strategy.authorize_uri
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      aggregate_failures do
        expect(uri).to be_present
        expect(query_params).to have_key("request")
      end
    end

    it "handles no audience found scenario" do
      strategy = build_strategy(
        nil
      )

      expect { strategy.authorize_uri }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end
  end

  describe "endpoint path assembly from entity statement metadata" do
    it "resolves relative userinfo and jwks URIs using issuer from metadata" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token",
            userinfo_endpoint: "/oauth2/userinfo",
            jwks_uri: "/.well-known/jwks.json"
          }
        }
      }
      write_entity_statement_jwt(entity_statement_path, entity_statement, encoder: :entity)

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: decode_client_options(host: URI.parse(provider_issuer).host)
      )

      client = strategy.client
      aggregate_failures do
        expect(client.userinfo_endpoint.to_s).to eq("#{provider_issuer}/oauth2/userinfo")
        expect(client.jwks_uri.to_s).to eq("#{provider_issuer}/.well-known/jwks.json")
      end
    end

    it "uses provider issuer from metadata as audience in authorize request" do
      entity_statement_path = write_provider_entity_statement_for_metadata

      strategy = build_decode_strategy_for_authorize(entity_statement_path: entity_statement_path)

      payload = authorize_request_payload(strategy.authorize_uri)
      expect(payload["aud"]).to eq(provider_issuer)
    end

    it "resolves issuer scheme and host from metadata when client_options omit issuer" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token"
          }
        }
      }
      write_entity_statement_jwt(entity_statement_path, entity_statement, encoder: :entity)

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: decode_client_options(host: URI.parse(provider_issuer).host)
      )

      client = strategy.client
      expect(client.authorization_endpoint.to_s).to eq("#{provider_issuer}/oauth2/authorize")
    end

    it "falls back to client_options when entity statement endpoint resolution fails" do
      entity_statement_path = write_provider_entity_statement_for_metadata

      allow(OmniauthOpenidFederation::EndpointResolver).to receive(:resolve)
        .and_raise(StandardError.new("resolution failed"))

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      expect(strategy.client).to be_a(OmniauthOpenidFederation::OidcClient)
    end

    it "skips non-URL issuer values when building endpoint URLs" do
      entity_statement_path = entity_statement_path_under_config
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        metadata: {
          openid_provider: {
            issuer: "relative-issuer",
            authorization_endpoint: "/oauth2/authorize",
            token_endpoint: "/oauth2/token"
          }
        }
      }
      write_entity_statement_jwt(entity_statement_path, entity_statement, encoder: :entity)

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      expect(strategy.authorize_uri).to be_present
    end
  end

  describe "resolve_endpoints_from_trust_chain" do
    it "resolves OpenID provider endpoints from trust chain metadata" do
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      trust_chain_leaf = {
        metadata: {
          openid_provider: provider_openid_metadata(
            userinfo_endpoint: "#{provider_issuer}/oauth2/userinfo",
            jwks_uri: "#{provider_issuer}/.well-known/jwks.json"
          )
        }
      }
      resolver = instance_double(
        OmniauthOpenidFederation::Federation::TrustChainResolver,
        resolve!: [trust_chain_leaf]
      )
      merger = instance_double(
        OmniauthOpenidFederation::Federation::MetadataPolicyMerger,
        merge_and_apply: trust_chain_leaf[:metadata]
      )
      allow(OmniauthOpenidFederation::Federation::TrustChainResolver).to receive(:new).and_return(resolver)
      allow(OmniauthOpenidFederation::Federation::MetadataPolicyMerger).to receive(:new).and_return(merger)

      strategy = build_strategy(
        nil,
        enable_trust_chain_resolution: true,
        issuer: provider_issuer,
        trust_anchors: [{entity_id: "https://ta.example.com", jwks: {keys: [jwk]}}],
        client_options: decode_client_options
      )

      client = strategy.client
      aggregate_failures do
        expect(client.authorization_endpoint.to_s).to include("/oauth2/authorize")
        expect(client.token_endpoint.to_s).to include("/oauth2/token")
        expect(client.userinfo_endpoint.to_s).to include("/oauth2/userinfo")
        expect(client.jwks_uri.to_s).to include("/.well-known/jwks.json")
      end
    end
  end

  describe "load_client_entity_statement - all branches" do
    include_context "automatic client registration"

    let(:client_entity_statement_jwt) do
      JWT.encode(client_entity_statement_payload, private_key, "RS256")
    end

    it "loads from cache when Rails.cache is available" do
      stub_rails_cache_double(fetch: client_entity_statement_jwt)

      strategy = build_automatic_strategy

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles cache fetch errors" do
      stub_rails_cache_double(fetch_raises: StandardError.new("Cache error"))

      strategy = build_automatic_strategy

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "generates dynamically when cache is empty" do
      stub_rails_cache_double(fetch: nil)

      strategy = build_automatic_strategy

      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "generates entity statement inside Rails cache fetch block" do
      rails_cache = double(write: true)
      allow(rails_cache).to receive(:fetch).with("federation:entity_statement", expires_in: anything).and_yield
      stub_const("Rails", double(cache: rails_cache, root: nil))

      strategy = build_strategy(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_registration_type: :automatic
      )

      content = strategy.send(:load_client_entity_statement, nil, nil)
      expect(content.split(".").length).to eq(3)
    end

    it "loads client entity statement from URL" do
      client_url = "https://client.example.com/.well-known/openid-federation"
      jwt = JWT.encode(client_entity_statement_payload, private_key, "RS256")
      stub_request(:get, client_url).to_return(status: 200, body: jwt)

      strategy = build_automatic_strategy
      content = strategy.send(:load_client_entity_statement_from_url, client_url)

      expect(content.split(".").length).to eq(3)
    end

    it "raises when client entity statement URL returns an error" do
      client_url = "https://client.example.com/.well-known/openid-federation"
      stub_request(:get, client_url).to_return(status: 500, body: "error")

      strategy = build_automatic_strategy

      expect { strategy.send(:load_client_entity_statement_from_url, client_url) }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /Failed to fetch client entity statement/)
    end

    it "handles FederationEndpoint configuration errors" do
      OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
      stub_rails_cache_double(fetch: nil)

      strategy = build_strategy(nil, client_registration_type: :automatic)

      expect { strategy.authorize_uri }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end

    it "handles other errors in dynamic generation" do
      stub_rails_cache_double(fetch: nil)
      OmniauthOpenidFederation::FederationEndpoint.configure do |config|
        config.issuer = StrategyTestHelpers::CLIENT_ISSUER
        config.private_key = private_key
      end
      allow(OmniauthOpenidFederation::FederationEndpoint).to receive(:generate_entity_statement)
        .and_raise(StandardError.new("Generation error"))

      strategy = build_strategy(nil, client_registration_type: :automatic)

      expect { strategy.authorize_uri }.to raise_error(OmniauthOpenidFederation::ConfigurationError)
    end
  end

  describe "load_client_entity_statement_from_file - all branches" do
    include_context "automatic client registration"
    it "handles absolute path" do
      strategy = build_automatic_strategy(
        client_entity_statement_path: write_client_entity_statement_file
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "handles relative path with Rails.root" do
      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = write_provider_entity_statement_file

      entity_statement_path = "tmp/test_entity.jwt"
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")

      full_path = if defined?(Rails)
        Rails.root.join(entity_statement_path).to_s
      else
        File.expand_path(entity_statement_path)
      end
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, jwt)

      strategy = build_strategy(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic
      )

      # Behavior: Should load client entity statement from relative path
      uri = strategy.authorize_uri
      expect(uri).to be_present
    ensure
      File.delete(full_path) if File.exist?(full_path)
    end

    it "handles relative path without Rails.root" do
      hide_const("Rails") if defined?(Rails)

      # Provide provider entity statement for audience resolution
      provider_entity_statement_path = write_provider_entity_statement_file

      entity_statement_path = "tmp/test_entity.jwt"
      entity_statement = {
        iss: "https://client.example.com",
        sub: "https://client.example.com",
        jwks: {keys: []}
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
      full_path = File.expand_path(entity_statement_path)
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, jwt)

      strategy = build_strategy(
        nil,
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: entity_statement_path,
        client_registration_type: :automatic
      )

      # Behavior: Should load client entity statement from relative path using File.expand_path
      uri = strategy.authorize_uri
      expect(uri).to be_present
    ensure
      File.delete(full_path) if File.exist?(full_path)
    end
  end

  describe "extract_entity_identifier_from_statement - all branches" do
    include_context "automatic client registration"

    it "uses configured identifier when provided" do
      strategy = build_automatic_strategy(
        client_entity_statement_path: write_client_entity_statement_file,
        client_entity_identifier: "configured-id"
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq("configured-id")
      end
    end

    it "extracts from sub claim" do
      strategy = build_automatic_strategy(
        client_entity_statement_path: write_client_entity_statement_file
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq(StrategyTestHelpers::CLIENT_ISSUER)
      end
    end

    it "falls back to iss claim when sub is missing" do
      strategy = build_automatic_strategy(
        client_entity_statement_path: write_client_entity_statement_file({iss: StrategyTestHelpers::CLIENT_ISSUER, sub: nil, jwks: nil})
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq(StrategyTestHelpers::CLIENT_ISSUER)
      end
    end

    it "handles missing both sub and iss" do
      strategy = build_automatic_strategy(
        client_entity_statement_path: write_simple_entity_statement_file({}),
        client_entity_identifier: "fallback-identifier"
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq("fallback-identifier")
      end
    end

    it "handles errors in extraction" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid.jwt")

      strategy = build_automatic_strategy(
        client_entity_statement_path: entity_statement_path,
        client_entity_identifier: "fallback-identifier"
      )

      # Behavior: Should raise error when client entity statement is invalid
      # Invalid JWT format is caught during loading, before extraction
      expect {
        strategy.authorize_uri
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /not a valid JWT/)
    end
  end

  describe "load_provider_metadata_for_encryption" do
    it "returns nil when entity_statement_path is nil" do
      strategy = build_strategy(
        nil,
        client_options: relative_path_client_options
      )

      # Behavior: When no entity statement, request object should not be encrypted
      uri = strategy.authorize_uri
      # Verify request object is not encrypted (3 parts for JWT, 5 for JWE)
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      aggregate_failures do
        expect(uri).to be_present
        expect(parts.length).to eq(3) # Not encrypted
      end
    end

    it "returns nil when file does not exist" do
      strategy = build_strategy(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: relative_path_client_options
      )

      # Behavior: When file doesn't exist, request object should not be encrypted
      uri = strategy.authorize_uri
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      aggregate_failures do
        expect(uri).to be_present
        expect(parts.length).to eq(3) # Not encrypted
      end
    end

    it "loads metadata with encryption parameters" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      provider_encryption_key = OpenSSL::PKey::RSA.new(2048)
      provider_encryption_jwk = JWT::JWK.new(provider_encryption_key.public_key).export
      provider_encryption_jwk[:use] = "enc"

      # Entity statement needs proper header with typ: "entity-statement+jwt" and kid
      # The kid must match a key in the JWKS
      signing_jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      signing_jwk[:use] = "sig"

      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        iat: Time.now.to_i,
        exp: Time.now.to_i + 3600,
        jwks: {keys: [signing_jwk, provider_encryption_jwk]},
        metadata: {
          openid_provider: {
            issuer: provider_issuer,
            authorization_endpoint: "https://provider.example.com/oauth2/authorize",
            token_endpoint: "https://provider.example.com/oauth2/token",
            request_object_encryption_alg: "RSA-OAEP",
            request_object_encryption_enc: "A128CBC-HS256"
          }
        }
      }
      header = {alg: "RS256", typ: "entity-statement+jwt", kid: signing_jwk[:kid]}
      jwt = JWT.encode(entity_statement, private_key, "RS256", header)
      File.write(entity_statement_path, jwt)

      # Stub HTTP request for entity statement (in case file isn't found)
      WebMock.stub_request(:get, "#{provider_issuer}/.well-known/openid-federation")
        .to_return(status: 200, body: jwt, headers: {"Content-Type" => "application/jwt"})

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path
      )

      # Behavior: When provider requires encryption, request object should be encrypted
      uri = strategy.authorize_uri
      # Verify request object is encrypted (5 parts for JWE)
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      aggregate_failures do
        expect(uri).to be_present
        expect(parts.length).to eq(5) # Encrypted (JWE)
      end
    end

    it "handles errors in loading metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      # Behavior: When metadata loading fails, request object should not be encrypted
      uri = strategy.authorize_uri
      uri_obj = URI.parse(uri)
      query_params = URI.decode_www_form(uri_obj.query || "").to_h
      request_jwt = query_params["request"]
      parts = request_jwt.split(".")
      aggregate_failures do
        expect(uri).to be_present
        expect(parts.length).to eq(3) # Not encrypted
      end
    end
  end

  describe "load_metadata_for_key_extraction" do
    it "returns nil when entity_statement_path is nil" do
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

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      # This is used when extracting signing keys from entity statement
      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      # Behavior: When no entity statement, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "returns nil when file does not exist" do
      strategy = build_strategy(
        nil,
        entity_statement_path: "/nonexistent/path.jwt",
        client_options: relative_path_client_options
      )

      # Behavior: When file doesn't exist, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "loads metadata with JWKS" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      entity_statement = {
        iss: provider_issuer,
        sub: provider_issuer,
        jwks: {keys: [jwk]},
        metadata: {
          openid_provider: {
            authorization_endpoint: "https://provider.example.com/oauth2/authorize"
          }
        }
      }
      jwt = JWT.encode(entity_statement, private_key, "RS256")
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

      # Test through public API: authorize_uri uses load_metadata_for_key_extraction
      # This is used when extracting signing keys from entity statement for federation
      allow(strategy).to receive_messages(request: double(params: {}), session: {})

      # Behavior: Should load metadata with JWKS from entity statement
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end

    it "handles errors in loading metadata" do
      entity_statement_path = Tempfile.new(["entity", ".jwt"]).path
      File.write(entity_statement_path, "invalid")

      strategy = build_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        client_options: relative_path_client_options
      )

      # Behavior: When metadata loading fails, should work with configured private key
      uri = strategy.authorize_uri
      expect(uri).to be_present
    end
  end
end
