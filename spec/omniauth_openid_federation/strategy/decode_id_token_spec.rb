require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, type: :strategy do

  describe "decode_id_token edge cases" do
    it "handles missing JWKS" do
      strategy = build_decode_strategy(
        nil,
        issuer: nil,
        entity_statement_path: nil,
        entity_statement_url: nil,
      )

      id_token = encode_rs256({iss: provider_issuer, sub: "user-123"})
      access_token_double = double(id_token: id_token)
      strategy.instance_variable_set(:@access_token, access_token_double)

      expect { strategy.raw_info }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /JWKS not available/)
    end

    it "handles invalid JWKS format" do
      setup = write_provider_jwks_entity_statement(jwks: "invalid")
      strategy = build_decode_strategy(nil, entity_statement_path: setup[:path])
      attach_access_token(strategy, id_token: encode_rs256({iss: provider_issuer, sub: "user-123"}))

      expect { strategy.raw_info }
        .to raise_error(OmniauthOpenidFederation::ValidationError, /Key with kid/)
    end

    context "with provider JWKS entity statement" do
      include_context "decode with provider jwks"

      it "handles missing kid in JWT header" do
        attach_access_token(
          decode_strategy,
          id_token: JWT.encode(
            {iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i},
            private_key,
            "RS256",
            {}
          )
        )

        expect { decode_strategy.raw_info }
          .to raise_error(OmniauthOpenidFederation::SignatureError, /kid/)
      ensure
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      it "handles kid not found in JWKS" do
        attach_access_token(
          decode_strategy,
          id_token: JWT.encode(
            {iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i},
            private_key,
            "RS256",
            {alg: "RS256", kid: "nonexistent-kid"}
          )
        )

        expect { decode_strategy.raw_info }
          .to raise_error(OmniauthOpenidFederation::ValidationError, /Key with kid/)
      end

      it "decrypts encrypted ID token with local private key" do
        plain_id_token = encode_id_token_for_provider_jwk(provider_jwk)
        encrypted_id_token = OmniauthOpenidFederation::Jwe.encrypt(
          plain_id_token,
          public_key,
          alg: "RSA-OAEP",
          enc: "A128CBC-HS256"
        )

        strategy = build_decode_strategy(
          nil,
          decryption_key_source: :local,
          entity_statement_path: entity_statement_path
        )
        attach_access_token(
          strategy,
          id_token: encrypted_id_token,
          userinfo: double(raw_attributes: {sub: "user-123"})
        )

        expect(strategy.raw_info).to be_a(Hash)
      end

      it "raises ValidationError when JWKS payload is not a hash with keys" do
        strategy = build_decode_strategy(nil, entity_statement_path: entity_statement_path)
        allow(strategy).to receive(:resolve_jwks_for_validation_with_kid).and_return({})

        attach_access_token(strategy, id_token: encode_id_token_for_provider_jwk(provider_jwk))

        expect { strategy.raw_info }
          .to raise_error(OmniauthOpenidFederation::ValidationError, /JWKS format invalid/)
      end

      it "handles missing required claims" do
        attach_access_token(
          decode_strategy,
          id_token: JWT.encode({sub: "user-123"}, private_key, "RS256", {alg: "RS256", kid: provider_jwk[:kid]})
        )

        expect { decode_strategy.raw_info }
          .to raise_error(OmniauthOpenidFederation::ValidationError, /missing required claims/)
      ensure
        File.delete(entity_statement_path) if File.exist?(entity_statement_path)
      end

      it "handles JWT decode errors" do
        wrong_key = OpenSSL::PKey::RSA.new(2048)
        attach_access_token(
          decode_strategy,
          id_token: JWT.encode(
            {iss: provider_issuer, sub: "user-123", aud: client_id, exp: Time.now.to_i + 3600, iat: Time.now.to_i},
            wrong_key,
            "RS256"
          )
        )

        expect { decode_strategy.raw_info }.to raise_error(OmniauthOpenidFederation::SignatureError)
      end
    end
  end

  describe "decode_userinfo edge cases" do
    include_context "decode with provider jwks"

    context "with federation decryption key source" do
      let(:decode_strategy_options) { {decryption_key_source: :federation} }

      it "handles encrypted userinfo with federation key source" do
        attach_access_token(
          decode_strategy,
          id_token: encode_id_token_for_provider_jwk(provider_jwk, {email: "user@example.com"}),
          userinfo: "header.encrypted_key.iv.ciphertext.tag"
        )

        result = decode_strategy.raw_info
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result[:sub]).to eq("user-123")
          expect(result[:email]).to eq("user@example.com")
        end
      end
    end

    it "handles plain JSON string userinfo" do
      attach_access_token(
        decode_strategy,
        id_token: valid_id_token,
        userinfo: '{"email":"user@example.com","name":"Test User"}'
      )

      result = decode_strategy.raw_info
      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result["email"]).to eq("user@example.com")
      end
    end

    it "handles hash userinfo" do
      userinfo_hash = {email: "user@example.com", name: "Test User"}
      attach_access_token(decode_strategy, id_token: valid_id_token, userinfo: userinfo_hash)

      expect(decode_strategy.raw_info).to include(userinfo_hash)
    end

    it "handles userinfo with raw_attributes" do
      attach_access_token(
        decode_strategy,
        id_token: valid_id_token,
        userinfo: double(raw_attributes: {email: "user@example.com"})
      )

      expect(decode_strategy.raw_info[:email]).to eq("user@example.com")
    end

    it "handles userinfo with as_json" do
      userinfo_double = double(raw_attributes: nil, as_json: {email: "user@example.com"})
      allow(userinfo_double).to receive(:respond_to?).with(:raw_attributes).and_return(false)
      allow(userinfo_double).to receive(:respond_to?).with(:as_json).and_return(true)
      attach_access_token(decode_strategy, id_token: valid_id_token, userinfo: userinfo_double)

      expect(decode_strategy.raw_info).to be_a(Hash)
    end

    it "handles userinfo with instance variables" do
      userinfo_obj = Class.new do
        def initialize
          @email = "user@example.com"
          @name = "Test User"
        end
      end.new
      allow(userinfo_obj).to receive(:respond_to?).and_call_original
      allow(userinfo_obj).to receive(:respond_to?).with(:as_json).and_return(false)
      allow(userinfo_obj).to receive(:respond_to?).with(:raw_attributes).and_return(false)
      attach_access_token(decode_strategy, id_token: valid_id_token, userinfo: userinfo_obj)

      result = decode_strategy.raw_info
      aggregate_failures do
        expect(result).to be_a(Hash)
        expect(result[:email]).to eq("user@example.com")
        expect(result[:name]).to eq("Test User")
      end
    end
  end

  describe "load_client_entity_statement" do
    include_context "decode with provider jwks"
    let(:provider_entity_statement_path) { entity_statement_path }

    it "loads from file path" do
      client_path = write_client_entity_statement_under_config
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_registration_type: :automatic
      )

      expect(strategy.authorize_uri).to be_present
    end

    it "handles missing file" do
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: "/nonexistent/path.jwt",
        client_registration_type: :automatic,
        client_options: decode_client_options(audience: "#{provider_issuer}/oauth2/token")
      )

      expect { strategy.authorize_uri }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /not found/)
    end

    it "handles empty file" do
      client_path = entity_statement_path_under_config
      File.write(client_path, "")

      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_registration_type: :automatic
      )

      expect { strategy.authorize_uri }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /is empty/)
    end

    it "handles invalid JWT format" do
      client_path = entity_statement_path_under_config
      File.write(client_path, "invalid.jwt")

      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_registration_type: :automatic
      )

      expect { strategy.authorize_uri }
        .to raise_error(OmniauthOpenidFederation::ConfigurationError, /not a valid JWT/)
    ensure
      File.delete(client_path) if File.exist?(client_path)
    end

    it "handles relative path with Rails.root" do
      provider_entity_statement_path # stub Rails.root before writing under tmp/
      relative_path = "tmp/test_entity.jwt"
      full_path = Rails.root.join(relative_path).to_s
      FileUtils.mkdir_p(File.dirname(full_path))
      File.write(full_path, encode_entity_statement(client_entity_statement_payload))

      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: relative_path,
        client_registration_type: :automatic
      )

      expect(strategy.authorize_uri).to be_present
    ensure
      File.delete(full_path) if defined?(full_path) && File.exist?(full_path)
    end
  end

  describe "extract_client_jwk_signing_key" do
    it "extracts JWKS from client entity statement" do
      entity_statement_path = write_client_entity_statement_under_config(jwks: {keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)]})

      result = build_decode_strategy(nil, client_entity_statement_path: entity_statement_path)
        .options[:client_jwk_signing_key]
      parsed = JSON.parse(result)
      aggregate_failures do
        expect(result).to be_a(String)
        expect(parsed).to have_key("keys")
      end
    end

    it "handles missing jwks in entity statement" do
      entity_statement_path = write_client_entity_statement_under_config(sub: StrategyTestHelpers::CLIENT_ISSUER, iss: StrategyTestHelpers::CLIENT_ISSUER, jwks: nil)

      result = build_decode_strategy(nil, client_entity_statement_path: entity_statement_path)
        .options[:client_jwk_signing_key]
      expect(result).to be_nil
    end
  end

  describe "extract_entity_identifier_from_statement" do
    include_context "decode with provider jwks"
    let(:provider_entity_statement_path) { entity_statement_path }

    it "extracts entity identifier from sub claim" do
      client_path = write_client_entity_statement_under_config({iss: StrategyTestHelpers::CLIENT_ISSUER, sub: StrategyTestHelpers::CLIENT_ISSUER})
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_registration_type: :automatic
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq(StrategyTestHelpers::CLIENT_ISSUER)
      end
    end

    it "falls back to iss claim if sub is missing" do
      client_path = write_client_entity_statement_under_config({iss: StrategyTestHelpers::CLIENT_ISSUER, sub: nil, jwks: nil})
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_registration_type: :automatic
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq(StrategyTestHelpers::CLIENT_ISSUER)
      end
    end

    it "uses configured identifier if provided" do
      client_path = write_client_entity_statement_under_config
      strategy = build_decode_strategy_for_authorize(
        entity_statement_path: provider_entity_statement_path,
        client_entity_statement_path: client_path,
        client_entity_identifier: "configured-id",
        client_registration_type: :automatic
      )

      uri = strategy.authorize_uri
      payload = authorize_request_payload(uri)
      aggregate_failures do
        expect(uri).to be_present
        expect(payload["iss"]).to eq("configured-id")
      end
    end
  end

  describe "normalize_acr_values" do
    def strategy_with_acr_request(params)
      strategy = build_decode_strategy_for_authorize(client_options: relative_path_client_options)
      allow(strategy).to receive_messages(request: double(params: params), session: {})
      strategy
    end

    it "normalizes ACR values from request parameters" do
      payload = authorize_request_payload(strategy_with_acr_request("acr_values" => "level1 level3").authorize_uri)
      expect(payload["acr_values"]).to eq("level1 level3")
    end

    it "handles nil ACR values" do
      payload = authorize_request_payload(strategy_with_acr_request({}).authorize_uri)
      expect(payload).not_to have_key("acr_values")
    end

    it "normalizes array ACR values from request" do
      payload = authorize_request_payload(strategy_with_acr_request("acr_values" => ["level1", "level2"]).authorize_uri)
      expect(payload["acr_values"]).to eq("level1 level2")
    end

    it "normalizes string ACR values from request" do
      payload = authorize_request_payload(strategy_with_acr_request("acr_values" => "level1 level2").authorize_uri)
      expect(payload["acr_values"]).to eq("level1 level2")
    end
  end

  describe "allowed_acr_values validation" do
    include_context "decode with provider jwks"

    it "rejects ID tokens whose acr is not in the configured allow-list" do
      strategy = build_decode_strategy(
        nil,
        entity_statement_path: entity_statement_path,
        allowed_acr_values: ["http://ftn.ficora.fi/2021/loa/substantial"],
        fetch_userinfo: false
      )
      attach_access_token(
        strategy,
        id_token: encode_id_token_for_provider_jwk(
          provider_jwk,
          {acr: "http://ftn.ficora.fi/2021/loa/low"}
        )
      )

      expect { strategy.raw_info }
        .to raise_error(OmniauthOpenidFederation::ValidationError, /acr mismatch/)
    end
  end

  describe "fetch_jwks" do
    it "handles JWKS as array" do
      jwks_uri = "#{provider_issuer}/.well-known/jwks.json"
      jwk = OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)
      stub_request(:get, jwks_uri)
        .to_return(status: 200, body: {keys: [jwk]}.to_json, headers: {"Content-Type" => "application/json"})

      strategy = build_decode_strategy(
        nil,
        client_options: relative_path_client_options(jwks_uri: jwks_uri)
      )
      attach_access_token(
        strategy,
        id_token: encode_id_token_for_provider_jwk(jwk),
        userinfo: {email: "user@example.com"}
      )

      expect(strategy.raw_info).to be_a(Hash)
    end
  end
end
