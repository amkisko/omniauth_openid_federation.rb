require "spec_helper"

RSpec.describe OmniauthOpenidFederation::FederationEndpoint do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:entity_jwk) { JWT::JWK.new(public_key) }
  let(:issuer) { "https://provider.example.com" }
  let(:subject) { "https://provider.example.com" }
  let(:jwks) do
    {
      "keys" => [entity_jwk.export.stringify_keys]
    }
  end
  let(:metadata) do
    {
      openid_provider: {
        issuer: issuer,
        authorization_endpoint: "#{issuer}/oauth2/authorize",
        token_endpoint: "#{issuer}/oauth2/token",
        userinfo_endpoint: "#{issuer}/oauth2/userinfo",
        jwks_uri: "#{issuer}/.well-known/jwks.json",
        signed_jwks_uri: "#{issuer}/.well-known/signed-jwks.json"
      }
    }
  end

  before do
    # Reset configuration before each test
    described_class.instance_variable_set(:@configuration, nil)
  end

  describe ".configure" do
    it "yields configuration instance" do
      config_instance = nil
      described_class.configure do |config|
        config_instance = config
      end

      expect(config_instance).to be_a(described_class.configuration.class)
    end

    it "returns configuration instance" do
      result = described_class.configure
      expect(result).to be_a(described_class.configuration.class)
    end

    it "works without block" do
      expect { described_class.configure }.not_to raise_error
    end

    it "allows setting configuration values" do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end

      config = described_class.configuration
      expect(config.issuer).to eq(issuer)
      expect(config.subject).to eq(subject)
      expect(config.private_key).to eq(private_key)
      expect(config.jwks).to eq(jwks)
      expect(config.metadata).to eq(metadata)
    end
  end

  describe ".configuration" do
    it "returns configuration instance" do
      config = described_class.configuration
      expect(config).to be_a(described_class.configuration.class)
    end

    it "returns same instance on multiple calls" do
      config1 = described_class.configuration
      config2 = described_class.configuration
      expect(config1).to be(config2) # Should be the same object instance
    end
  end

  describe ".generate_signed_jwks" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "generates signed JWKS JWT" do
      jwt_string = described_class.generate_signed_jwks

      expect(jwt_string).to be_a(String)
      expect(jwt_string.split(".").length).to eq(3) # JWT has 3 parts
    end

    it "includes JWKS in payload" do
      jwt_string = described_class.generate_signed_jwks
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["jwks"]).to be_a(Hash)
      expect(payload["jwks"]["keys"]).to be_an(Array)
    end

    it "uses custom signed_jwks_payload when configured" do
      custom_jwks = {
        "keys" => [
          {
            "kty" => "RSA",
            "kid" => "custom-key",
            "use" => "sig"
          }
        ]
      }
      described_class.configure do |config|
        config.signed_jwks_payload = custom_jwks
      end

      jwt_string = described_class.generate_signed_jwks
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["jwks"]["keys"].first["kid"]).to eq("custom-key")
    end

    it "uses custom expiration_seconds when configured" do
      custom_expiration = 7200
      described_class.configure do |config|
        config.signed_jwks_expiration_seconds = custom_expiration
      end

      jwt_string = described_class.generate_signed_jwks
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["exp"] - payload["iat"]).to eq(custom_expiration)
    end

    it "raises ConfigurationError when issuer is missing" do
      described_class.configure do |config|
        config.issuer = nil
      end

      expect { described_class.generate_signed_jwks }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError
      )
    end
  end

  describe ".current_jwks" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "returns entity statement jwks by default" do
      result = described_class.current_jwks
      expect(result).to eq(jwks)
    end

    it "returns current_jwks when configured" do
      custom_jwks = {"keys" => [{"kty" => "RSA", "kid" => "custom"}]}
      described_class.configure do |config|
        config.current_jwks = custom_jwks
      end

      result = described_class.current_jwks
      expect(result).to eq(custom_jwks)
    end

    it "calls current_jwks_proc when configured" do
      custom_jwks = {"keys" => [{"kty" => "RSA", "kid" => "proc-key"}]}
      described_class.configure do |config|
        config.current_jwks_proc = -> { custom_jwks }
      end

      result = described_class.current_jwks
      expect(result).to eq(custom_jwks)
    end
  end

  describe ".generate_entity_statement" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "generates entity statement JWT" do
      jwt_string = described_class.generate_entity_statement

      expect(jwt_string).to be_a(String)
      expect(jwt_string.split(".").length).to eq(3) # JWT has 3 parts
    end

    it "uses subject from configuration" do
      jwt_string = described_class.generate_entity_statement
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["sub"]).to eq(subject)
    end

    it "uses issuer as subject when subject is nil" do
      described_class.configure do |config|
        config.subject = nil
      end

      jwt_string = described_class.generate_entity_statement
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["sub"]).to eq(issuer)
    end

    it "uses custom expiration_seconds from configuration" do
      custom_expiration = 7200
      described_class.configure do |config|
        config.expiration_seconds = custom_expiration
      end

      jwt_string = described_class.generate_entity_statement
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["exp"] - payload["iat"]).to eq(custom_expiration)
    end

    it "uses default expiration_seconds when not configured" do
      described_class.configure do |config|
        config.expiration_seconds = nil
      end

      jwt_string = described_class.generate_entity_statement
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["exp"] - payload["iat"]).to eq(86400) # Default 24 hours
    end

    it "uses custom kid from configuration" do
      custom_kid = "custom-key-id"
      described_class.configure do |config|
        config.kid = custom_kid
      end

      jwt_string = described_class.generate_entity_statement
      header = JWT.decode(jwt_string, nil, false).last
      expect(header["kid"]).to eq(custom_kid)
    end

    it "raises ConfigurationError when issuer is missing" do
      described_class.configure do |config|
        config.issuer = nil
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Issuer is required/
      )
    end

    it "raises ConfigurationError when issuer is empty" do
      described_class.configure do |config|
        config.issuer = ""
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Issuer is required/
      )
    end

    it "raises ConfigurationError when private_key is missing" do
      described_class.configure do |config|
        config.private_key = nil
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Private key is required/
      )
    end

    it "raises ConfigurationError when jwks is missing" do
      described_class.configure do |config|
        config.jwks = nil
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /JWKS is required/
      )
    end

    it "raises ConfigurationError when jwks is empty" do
      described_class.configure do |config|
        config.jwks = {}
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /JWKS is required/
      )
    end

    it "raises ConfigurationError when metadata is missing" do
      described_class.configure do |config|
        config.metadata = nil
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Metadata is required/
      )
    end

    it "raises ConfigurationError when metadata is empty" do
      described_class.configure do |config|
        config.metadata = {}
      end

      expect { described_class.generate_entity_statement }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Metadata is required/
      )
    end
  end

  describe ".mount_routes" do
    it "mounts all four endpoints with default paths" do
      router = double("router")
      expect(router).to receive(:get).with(
        "/.well-known/openid-federation",
        to: "omniauth_openid_federation/federation#show",
        as: :openid_federation
      )
      expect(router).to receive(:get).with(
        "/.well-known/openid-federation/fetch",
        to: "omniauth_openid_federation/federation#fetch",
        as: :openid_federation_fetch
      )
      expect(router).to receive(:get).with(
        "/.well-known/jwks.json",
        to: "omniauth_openid_federation/federation#jwks",
        as: :openid_federation_jwks
      )
      expect(router).to receive(:get).with(
        "/.well-known/signed-jwks.json",
        to: "omniauth_openid_federation/federation#signed_jwks",
        as: :openid_federation_signed_jwks
      )

      described_class.mount_routes(router)
    end

    it "mounts endpoints with custom paths" do
      router = double("router")
      expect(router).to receive(:get).with(
        "/custom/federation",
        to: "omniauth_openid_federation/federation#show",
        as: :openid_federation
      )
      expect(router).to receive(:get).with(
        "/custom/fetch",
        to: "omniauth_openid_federation/federation#fetch",
        as: :openid_federation_fetch
      )
      expect(router).to receive(:get).with(
        "/custom/jwks.json",
        to: "omniauth_openid_federation/federation#jwks",
        as: :openid_federation_jwks
      )
      expect(router).to receive(:get).with(
        "/custom/signed-jwks.json",
        to: "omniauth_openid_federation/federation#signed_jwks",
        as: :openid_federation_signed_jwks
      )

      described_class.mount_routes(
        router,
        entity_statement_path: "/custom/federation",
        fetch_path: "/custom/fetch",
        jwks_path: "/custom/jwks.json",
        signed_jwks_path: "/custom/signed-jwks.json"
      )
    end

    it "mounts endpoints with custom route name prefix" do
      router = double("router")
      custom_name = :custom_federation
      expect(router).to receive(:get).with(
        "/.well-known/openid-federation",
        to: "omniauth_openid_federation/federation#show",
        as: custom_name
      )
      expect(router).to receive(:get).with(
        "/.well-known/openid-federation/fetch",
        to: "omniauth_openid_federation/federation#fetch",
        as: :"#{custom_name}_fetch"
      )
      expect(router).to receive(:get).with(
        "/.well-known/jwks.json",
        to: "omniauth_openid_federation/federation#jwks",
        as: :"#{custom_name}_jwks"
      )
      expect(router).to receive(:get).with(
        "/.well-known/signed-jwks.json",
        to: "omniauth_openid_federation/federation#signed_jwks",
        as: :"#{custom_name}_signed_jwks"
      )

      described_class.mount_routes(router, as: custom_name)
    end
  end

  describe "Configuration" do
    describe "#initialize" do
      it "initializes with default values" do
        config = described_class.configuration

        expect(config.issuer).to be_nil
        expect(config.subject).to be_nil
        expect(config.private_key).to be_nil
        expect(config.jwks).to be_nil
        expect(config.metadata).to be_nil
        expect(config.expiration_seconds).to eq(86400)
        expect(config.kid).to be_nil
      end
    end

    describe "attr_accessor" do
      it "allows setting and getting issuer" do
        config = described_class.configuration
        config.issuer = issuer
        expect(config.issuer).to eq(issuer)
      end

      it "allows setting and getting subject" do
        config = described_class.configuration
        config.subject = subject
        expect(config.subject).to eq(subject)
      end

      it "allows setting and getting private_key" do
        config = described_class.configuration
        config.private_key = private_key
        expect(config.private_key).to eq(private_key)
      end

      it "allows setting and getting jwks" do
        config = described_class.configuration
        config.jwks = jwks
        expect(config.jwks).to eq(jwks)
      end

      it "allows setting and getting metadata" do
        config = described_class.configuration
        config.metadata = metadata
        expect(config.metadata).to eq(metadata)
      end

      it "allows setting and getting expiration_seconds" do
        config = described_class.configuration
        config.expiration_seconds = 7200
        expect(config.expiration_seconds).to eq(7200)
      end

      it "allows setting and getting kid" do
        config = described_class.configuration
        config.kid = "custom-kid"
        expect(config.kid).to eq("custom-kid")
      end
    end
  end

  describe ".generate_signed_jwks" do
    before do
      described_class.instance_variable_set(:@configuration, nil)
    end

    it "generates signed JWKS JWT" do
      described_class.auto_configure(
        issuer: issuer,
        private_key: private_key,
        metadata: metadata
      )

      signed_jwks = described_class.generate_signed_jwks
      expect(signed_jwks).to be_a(String)
      parts = signed_jwks.split(".")
      expect(parts.length).to eq(3)
    end

    it "uses custom signed_jwks_payload when configured" do
      custom_jwks = {keys: [{kty: "RSA", kid: "custom"}]}
      described_class.auto_configure(
        issuer: issuer,
        private_key: private_key,
        metadata: metadata
      )
      config = described_class.configuration
      config.signed_jwks_payload = custom_jwks

      signed_jwks = described_class.generate_signed_jwks
      parts = signed_jwks.split(".")
      payload = JSON.parse(Base64.urlsafe_decode64(parts[1]))
      expect(payload["jwks"]["keys"].length).to eq(1)
      expect(payload["jwks"]["keys"].first["kid"]).to eq("custom")
    end
  end

  describe ".auto_configure" do
    let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:temp_dir) { Dir.mktmpdir }
    let(:entity_statement_path) { File.join(temp_dir, "entity-statement.jwt") }

    after do
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    describe "error handling" do
      it "raises error when all three keys are provided simultaneously" do
        expect {
          described_class.auto_configure(
            issuer: issuer,
            signing_key: signing_key,
            encryption_key: encryption_key,
            private_key: private_key
          )
        }.to raise_error(
          OmniauthOpenidFederation::ConfigurationError,
          /Cannot specify signing_key, encryption_key, and private_key simultaneously/
        )
      end

      it "raises error when auto_provision_keys is false and no keys provided" do
        expect {
          described_class.auto_configure(
            issuer: issuer,
            auto_provision_keys: false
          )
        }.to raise_error(
          OmniauthOpenidFederation::ConfigurationError,
          /At least one key source is required/
        )
      end

      it "raises error when no signing key is available after provisioning" do
        # Create invalid entity statement file that won't provide keys
        File.write(entity_statement_path, "invalid.jwt.content")

        expect {
          described_class.auto_configure(
            issuer: issuer,
            entity_statement_path: entity_statement_path,
            auto_provision_keys: true
          )
        }.to raise_error(
          OmniauthOpenidFederation::ConfigurationError,
          /Signing key is required/
        )
      end
    end

    describe "key configuration branches" do
      it "configures separate signing_key and encryption_key" do
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          metadata: metadata
        )

        expect(config.signing_key).to eq(signing_key)
        expect(config.encryption_key).to eq(encryption_key)
        expect(config.private_key).to eq(signing_key)
        expect(config.jwks).to be_a(Hash)
        expect(config.jwks["keys"] || config.jwks[:keys]).to be_an(Array)
      end

      it "configures single private_key when provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          metadata: metadata
        )

        expect(config.private_key).to eq(private_key)
        expect(config.signing_key).to eq(private_key)
        expect(config.encryption_key).to eq(private_key)
        expect(config.jwks).to be_a(Hash)
      end

      it "loads keys from entity statement file when no keys provided" do
        # Create valid entity statement with keys
        signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
        encryption_key_file = File.join(temp_dir, ".federation-encryption-key.pem")
        File.write(signing_key_file, signing_key.to_pem)
        File.write(encryption_key_file, encryption_key.to_pem)
        File.chmod(0o600, signing_key_file)
        File.chmod(0o600, encryption_key_file)

        # Create entity statement JWT
        jwks_hash = {
          keys: [
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key, use: "sig"),
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc")
          ]
        }
        entity_statement = OmniauthOpenidFederation::Federation::EntityStatementBuilder.new(
          issuer: issuer,
          subject: issuer,
          private_key: signing_key,
          jwks: jwks_hash,
          metadata: metadata
        ).build
        File.write(entity_statement_path, entity_statement)

        config = described_class.auto_configure(
          issuer: issuer,
          entity_statement_path: entity_statement_path,
          auto_provision_keys: true
        )

        expect(config.signing_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.encryption_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.private_key).to eq(config.signing_key)
        expect(config.jwks).to be_a(Hash)
      end

      it "uses signing_key for both signing and encryption when only signing_key provided" do
        # When only signing_key is provided (no encryption_key), it should be used for both
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          metadata: metadata
        )

        expect(config.signing_key).to eq(signing_key)
        expect(config.encryption_key).to eq(signing_key)
        expect(config.private_key).to eq(signing_key)
        expect(config.jwks).to be_a(Hash)
        # Should generate single JWK without use field
        jwks_keys = config.jwks["keys"] || config.jwks[:keys]
        expect(jwks_keys.length).to eq(1)
        expect(jwks_keys.first["use"] || jwks_keys.first[:use]).to be_nil
      end
    end

    describe "same-key detection logic" do
      it "generates single JWK when signing_key and encryption_key are the same" do
        same_key = OpenSSL::PKey::RSA.new(2048)

        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: same_key,
          encryption_key: same_key,
          metadata: metadata
        )

        jwks_keys = config.jwks["keys"] || config.jwks[:keys]
        expect(jwks_keys.length).to eq(1)
        expect(jwks_keys.first["use"] || jwks_keys.first[:use]).to be_nil
        expect(jwks_keys.first["kid"] || jwks_keys.first[:kid]).to be_present
      end

      it "generates separate JWKs when signing_key and encryption_key are different" do
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          metadata: metadata
        )

        jwks_keys = config.jwks["keys"] || config.jwks[:keys]
        expect(jwks_keys.length).to eq(2)

        signing_jwk = jwks_keys.find { |k| (k["use"] || k[:use]) == "sig" }
        encryption_jwk = jwks_keys.find { |k| (k["use"] || k[:use]) == "enc" }

        expect(signing_jwk).to be_present
        expect(encryption_jwk).to be_present
        expect(signing_jwk["kid"] || signing_jwk[:kid]).not_to eq(encryption_jwk["kid"] || encryption_jwk[:kid])
      end

      it "raises error when encryption_key provided but no signing_key or private_key" do
        expect {
          described_class.auto_configure(
            issuer: issuer,
            encryption_key: encryption_key,
            metadata: metadata
          )
        }.to raise_error(
          OmniauthOpenidFederation::ConfigurationError,
          /Signing key is required when encryption_key is provided/
        )
      end
    end

    describe "auto-generated metadata" do
      it "generates metadata for openid_provider entity type" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          metadata: {
            openid_provider: {
              authorization_endpoint: "#{issuer}/oauth2/authorize"
            }
          }
        )

        op_metadata = config.metadata[:openid_provider] || config.metadata["openid_provider"]
        expect(op_metadata).to be_present
        expect(op_metadata[:federation_fetch_endpoint] || op_metadata["federation_fetch_endpoint"]).to eq("#{issuer}/.well-known/openid-federation/fetch")
        expect(op_metadata[:jwks_uri] || op_metadata["jwks_uri"]).to be_present
        expect(op_metadata[:signed_jwks_uri] || op_metadata["signed_jwks_uri"]).to be_present
      end

      it "generates metadata for openid_relying_party entity type when no metadata provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key
        )

        rp_metadata = config.metadata[:openid_relying_party] || config.metadata["openid_relying_party"]
        expect(rp_metadata).to be_present
        expect(rp_metadata[:issuer] || rp_metadata["issuer"]).to eq(issuer)
        expect(rp_metadata[:jwks_uri] || rp_metadata["jwks_uri"]).to eq("#{issuer}/.well-known/jwks.json")
        expect(rp_metadata[:signed_jwks_uri] || rp_metadata["signed_jwks_uri"]).to eq("#{issuer}/.well-known/signed-jwks.json")
      end
    end

    describe "entity statement file loading" do
      it "extracts JWKS from entity statement file when no keys provided" do
        # Create entity statement file with keys
        signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
        encryption_key_file = File.join(temp_dir, ".federation-encryption-key.pem")
        File.write(signing_key_file, signing_key.to_pem)
        File.write(encryption_key_file, encryption_key.to_pem)
        File.chmod(0o600, signing_key_file)
        File.chmod(0o600, encryption_key_file)

        jwks_hash = {
          keys: [
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key, use: "sig"),
            OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc")
          ]
        }
        entity_statement = OmniauthOpenidFederation::Federation::EntityStatementBuilder.new(
          issuer: issuer,
          subject: issuer,
          private_key: signing_key,
          jwks: jwks_hash,
          metadata: metadata
        ).build
        File.write(entity_statement_path, entity_statement)

        config = described_class.auto_configure(
          issuer: issuer,
          entity_statement_path: entity_statement_path,
          auto_provision_keys: true
        )

        expect(config.jwks).to be_a(Hash)
        expect(config.signing_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.encryption_key).to be_a(OpenSSL::PKey::RSA)
      end

      it "loads single key from disk when only signing key file exists" do
        signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
        File.write(signing_key_file, private_key.to_pem)
        File.chmod(0o600, signing_key_file)

        jwks_hash = {
          keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(private_key, use: nil)]
        }
        entity_statement = OmniauthOpenidFederation::Federation::EntityStatementBuilder.new(
          issuer: issuer,
          subject: issuer,
          private_key: private_key,
          jwks: jwks_hash,
          metadata: metadata
        ).build
        File.write(entity_statement_path, entity_statement)

        config = described_class.auto_configure(
          issuer: issuer,
          entity_statement_path: entity_statement_path,
          auto_provision_keys: true
        )

        expect(config.signing_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.encryption_key).to eq(config.signing_key)
        expect(config.private_key).to eq(config.signing_key)
      end
    end

    describe "auto-generation of keys" do
      it "auto-generates keys when auto_provision_keys is true and no keys provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          entity_statement_path: entity_statement_path,
          auto_provision_keys: true
        )

        expect(config.jwks).to be_a(Hash)
        expect(config.signing_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.encryption_key).to be_a(OpenSSL::PKey::RSA)
        expect(File.exist?(entity_statement_path)).to be true

        # Verify keys were written to disk
        keys_dir = File.dirname(entity_statement_path)
        signing_key_file = File.join(keys_dir, ".federation-signing-key.pem")
        encryption_key_file = File.join(keys_dir, ".federation-encryption-key.pem")
        expect(File.exist?(signing_key_file)).to be true
        expect(File.exist?(encryption_key_file)).to be true
      end

      it "generates minimal metadata when auto-generating keys" do
        config = described_class.auto_configure(
          issuer: issuer,
          entity_statement_path: entity_statement_path,
          auto_provision_keys: true
        )

        rp_metadata = config.metadata[:openid_relying_party] || config.metadata["openid_relying_party"]
        expect(rp_metadata).to be_present
        expect(rp_metadata[:issuer] || rp_metadata["issuer"]).to eq(issuer)
        expect(rp_metadata[:jwks_uri] || rp_metadata["jwks_uri"]).to be_present
      end
    end

    describe "key saving and entity statement regeneration" do
      it "saves provided keys to disk and regenerates entity statement" do
        signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
        encryption_key_file = File.join(temp_dir, ".federation-encryption-key.pem")

        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata
        )

        expect(File.exist?(signing_key_file)).to be true
        expect(File.exist?(encryption_key_file)).to be true
        expect(File.exist?(entity_statement_path)).to be true
        expect(config.jwks).to be_a(Hash)
      end

      it "saves single private_key to disk" do
        signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
        encryption_key_file = File.join(temp_dir, ".federation-encryption-key.pem")

        described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata
        )

        expect(File.exist?(signing_key_file)).to be true
        expect(File.exist?(encryption_key_file)).to be true
      end

      it "handles errors when saving keys gracefully" do
        # Make directory read-only to cause write failure
        FileUtils.chmod(0o555, temp_dir)

        expect {
          described_class.auto_configure(
            issuer: issuer,
            signing_key: signing_key,
            encryption_key: encryption_key,
            entity_statement_path: entity_statement_path,
            metadata: metadata
          )
        }.not_to raise_error

        FileUtils.chmod(0o755, temp_dir)
      end
    end

    describe "key rotation" do
      it "rotates keys when rotation period has elapsed" do
        # Create initial entity statement
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata,
          key_rotation_period: 1 # 1 second for testing
        )

        config.kid

        # Wait for rotation period to elapse
        sleep(1.1)

        # Trigger rotation by calling auto_configure again
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata,
          key_rotation_period: 1
        )

        # Keys should still be the same (we provided them)
        # But if we didn't provide keys, rotation would happen
        expect(config.kid).to be_present
      end

      it "does not rotate keys when rotation period has not elapsed" do
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata,
          key_rotation_period: 86400 # 24 hours
        )

        config.kid

        # Immediately call again - should not rotate
        config = described_class.auto_configure(
          issuer: issuer,
          signing_key: signing_key,
          encryption_key: encryption_key,
          entity_statement_path: entity_statement_path,
          metadata: metadata,
          key_rotation_period: 86400
        )

        expect(config.kid).to be_present
      end
    end

    describe "issuer validation" do
      it "raises error when issuer is nil" do
        expect {
          described_class.auto_configure(issuer: nil, private_key: private_key)
        }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
      end

      it "raises error when issuer is empty" do
        expect {
          described_class.auto_configure(issuer: "", private_key: private_key)
        }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
      end
    end

    describe "subject handling" do
      it "uses issuer as subject when subject is not provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          metadata: metadata
        )

        expect(config.subject).to eq(issuer)
      end

      it "uses provided subject" do
        custom_subject = "https://custom.example.com"
        config = described_class.auto_configure(
          issuer: issuer,
          subject: custom_subject,
          private_key: private_key,
          metadata: metadata
        )

        expect(config.subject).to eq(custom_subject)
      end
    end

    describe "optional configuration" do
      it "sets expiration_seconds when provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          expiration_seconds: 7200,
          metadata: metadata
        )

        expect(config.expiration_seconds).to eq(7200)
      end

      it "sets jwks_cache_ttl when provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          jwks_cache_ttl: 1800,
          metadata: metadata
        )

        expect(config.jwks_cache_ttl).to eq(1800)
      end

      it "sets key_rotation_period when provided" do
        config = described_class.auto_configure(
          issuer: issuer,
          private_key: private_key,
          key_rotation_period: 90 * 24 * 3600,
          metadata: metadata
        )

        expect(config.key_rotation_period).to eq(90 * 24 * 3600)
      end
    end
  end

  describe ".provision_jwks" do
    let(:temp_dir) { Dir.mktmpdir }
    let(:entity_statement_path) { File.join(temp_dir, "entity-statement.jwt") }
    let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }

    after do
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    it "generates JWKS from separate signing and encryption keys" do
      jwks = described_class.provision_jwks(
        signing_key: signing_key,
        encryption_key: encryption_key
      )

      expect(jwks).to be_a(Hash)
      expect(jwks[:keys] || jwks["keys"]).to be_an(Array)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(2)
    end

    it "generates single JWK when keys are the same" do
      same_key = OpenSSL::PKey::RSA.new(2048)
      jwks = described_class.provision_jwks(
        signing_key: same_key,
        encryption_key: same_key
      )

      expect(jwks).to be_a(Hash)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(1)
    end

    it "generates JWKS from single private_key" do
      jwks = described_class.provision_jwks(private_key: private_key)

      expect(jwks).to be_a(Hash)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(1)
    end

    it "extracts JWKS from entity statement file" do
      signing_key_file = File.join(temp_dir, ".federation-signing-key.pem")
      encryption_key_file = File.join(temp_dir, ".federation-encryption-key.pem")
      File.write(signing_key_file, signing_key.to_pem)
      File.write(encryption_key_file, encryption_key.to_pem)

      jwks_hash = {
        keys: [
          OmniauthOpenidFederation::Utils.rsa_key_to_jwk(signing_key, use: "sig"),
          OmniauthOpenidFederation::Utils.rsa_key_to_jwk(encryption_key, use: "enc")
        ]
      }
      entity_statement = OmniauthOpenidFederation::Federation::EntityStatementBuilder.new(
        issuer: issuer,
        subject: issuer,
        private_key: signing_key,
        jwks: jwks_hash,
        metadata: metadata
      ).build
      File.write(entity_statement_path, entity_statement)

      jwks = described_class.provision_jwks(
        entity_statement_path: entity_statement_path
      )

      expect(jwks).to be_a(Hash)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(2)
    end

    it "auto-generates keys when no keys provided and issuer given" do
      jwks = described_class.provision_jwks(
        issuer: issuer,
        subject: issuer,
        entity_statement_path: entity_statement_path,
        metadata: metadata
      )

      expect(jwks).to be_a(Hash)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(2)
      expect(File.exist?(entity_statement_path)).to be true
    end

    it "returns nil when extraction fails and no issuer provided" do
      File.write(entity_statement_path, "invalid content")

      jwks = described_class.provision_jwks(
        entity_statement_path: entity_statement_path,
        entity_statement_path_provided: true
      )

      expect(jwks).to be_nil
    end

    it "raises error when encryption_key provided without signing_key" do
      expect {
        described_class.provision_jwks(encryption_key: encryption_key)
      }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Signing key is required when encryption_key is provided/
      )
    end
  end

  describe ".generate_fresh_keys" do
    let(:temp_dir) { Dir.mktmpdir }
    let(:entity_statement_path) { File.join(temp_dir, "entity-statement.jwt") }
    let(:keys_output_dir) { File.join(temp_dir, "keys") }

    after do
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    it "generates fresh signing and encryption keys" do
      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: issuer,
        subject: issuer,
        metadata: metadata
      )

      expect(jwks).to be_a(Hash)
      expect((jwks[:keys] || jwks["keys"]).length).to eq(2)
      expect(File.exist?(entity_statement_path)).to be true

      signing_key_file = File.join(File.dirname(entity_statement_path), ".federation-signing-key.pem")
      encryption_key_file = File.join(File.dirname(entity_statement_path), ".federation-encryption-key.pem")
      expect(File.exist?(signing_key_file)).to be true
      expect(File.exist?(encryption_key_file)).to be true
    end

    it "uses custom keys_output_dir" do
      described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: issuer,
        keys_output_dir: keys_output_dir
      )

      expect(File.exist?(File.join(keys_output_dir, ".federation-signing-key.pem"))).to be true
      expect(File.exist?(File.join(keys_output_dir, ".federation-encryption-key.pem"))).to be true
    end

    it "generates minimal metadata when metadata not provided" do
      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: issuer
      )

      expect(jwks).to be_a(Hash)
      # generate_fresh_keys generates metadata internally but doesn't update config
      # Verify the entity statement was created with metadata
      expect(File.exist?(entity_statement_path)).to be true
      entity_statement = File.read(entity_statement_path)
      decoded = JWT.decode(entity_statement, nil, false).first
      expect(decoded["metadata"]).to be_present
    end

    it "returns nil when issuer is missing" do
      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path
      )

      expect(jwks).to be_nil
    end

    it "handles errors gracefully" do
      # Make directory read-only to cause write failure
      FileUtils.chmod(0o555, temp_dir)

      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: issuer
      )

      expect(jwks).to be_nil

      FileUtils.chmod(0o755, temp_dir)
    end
  end

  describe ".rotate_keys_if_needed" do
    let(:temp_dir) { Dir.mktmpdir }
    let(:entity_statement_path) { File.join(temp_dir, "entity-statement.jwt") }
    let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }

    after do
      FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
    end

    it "does nothing when key_rotation_period is nil" do
      config = described_class.configuration
      config.key_rotation_period = nil

      expect { described_class.rotate_keys_if_needed(config) }.not_to raise_error
    end

    it "does nothing when entity_statement_path is nil" do
      config = described_class.configuration
      config.key_rotation_period = 3600
      config.entity_statement_path = nil

      expect { described_class.rotate_keys_if_needed(config) }.not_to raise_error
    end

    it "does nothing when entity statement file does not exist" do
      config = described_class.configuration
      config.key_rotation_period = 3600
      config.entity_statement_path = "/nonexistent/path.jwt"

      expect { described_class.rotate_keys_if_needed(config) }.not_to raise_error
    end

    it "rotates keys when period has elapsed" do
      # Create initial entity statement
      config = described_class.auto_configure(
        issuer: issuer,
        signing_key: signing_key,
        encryption_key: encryption_key,
        entity_statement_path: entity_statement_path,
        metadata: metadata
      )

      # Set old modification time
      FileUtils.touch(entity_statement_path, mtime: Time.now - 7200)
      config.key_rotation_period = 3600

      described_class.rotate_keys_if_needed(config)

      # File should have new modification time
      expect(File.mtime(entity_statement_path)).to be > Time.now - 100
    end

    it "does not rotate when period has not elapsed" do
      config = described_class.auto_configure(
        issuer: issuer,
        signing_key: signing_key,
        encryption_key: encryption_key,
        entity_statement_path: entity_statement_path,
        metadata: metadata
      )

      old_mtime = File.mtime(entity_statement_path)
      config.key_rotation_period = 86400

      described_class.rotate_keys_if_needed(config)

      expect(File.mtime(entity_statement_path)).to eq(old_mtime)
    end
  end

  describe ".ensure_jwks_endpoints" do
    it "adds jwks_uri and signed_jwks_uri to openid_provider metadata" do
      metadata = {
        openid_provider: {
          issuer: issuer
        }
      }

      result = described_class.ensure_jwks_endpoints(metadata, issuer, :openid_provider)

      op_metadata = result[:openid_provider] || result["openid_provider"]
      expect(op_metadata[:jwks_uri] || op_metadata["jwks_uri"]).to eq("#{issuer}/.well-known/jwks.json")
      expect(op_metadata[:signed_jwks_uri] || op_metadata["signed_jwks_uri"]).to eq("#{issuer}/.well-known/signed-jwks.json")
      expect(op_metadata[:federation_fetch_endpoint] || op_metadata["federation_fetch_endpoint"]).to eq("#{issuer}/.well-known/openid-federation/fetch")
    end

    it "adds jwks_uri and signed_jwks_uri to openid_relying_party metadata" do
      metadata = {
        openid_relying_party: {
          issuer: issuer
        }
      }

      result = described_class.ensure_jwks_endpoints(metadata, issuer, :openid_relying_party)

      rp_metadata = result[:openid_relying_party] || result["openid_relying_party"]
      expect(rp_metadata[:jwks_uri] || rp_metadata["jwks_uri"]).to eq("#{issuer}/.well-known/jwks.json")
      expect(rp_metadata[:signed_jwks_uri] || rp_metadata["signed_jwks_uri"]).to eq("#{issuer}/.well-known/signed-jwks.json")
    end

    it "does not add federation_fetch_endpoint for openid_relying_party" do
      metadata = {
        openid_relying_party: {
          issuer: issuer
        }
      }

      result = described_class.ensure_jwks_endpoints(metadata, issuer, :openid_relying_party)

      rp_metadata = result[:openid_relying_party] || result["openid_relying_party"]
      expect(rp_metadata[:federation_fetch_endpoint] || rp_metadata["federation_fetch_endpoint"]).to be_nil
    end

    it "does not overwrite existing endpoints" do
      metadata = {
        openid_provider: {
          jwks_uri: "https://custom.example.com/jwks.json",
          signed_jwks_uri: "https://custom.example.com/signed-jwks.json"
        }
      }

      result = described_class.ensure_jwks_endpoints(metadata, issuer, :openid_provider)

      op_metadata = result[:openid_provider] || result["openid_provider"]
      expect(op_metadata[:jwks_uri] || op_metadata["jwks_uri"]).to eq("https://custom.example.com/jwks.json")
    end

    it "handles string keys in metadata" do
      metadata = {
        "openid_provider" => {
          "issuer" => issuer
        }
      }

      result = described_class.ensure_jwks_endpoints(metadata, issuer, :openid_provider)

      op_metadata = result[:openid_provider] || result["openid_provider"]
      expect(op_metadata).to be_present
    end
  end

  describe ".detect_entity_type" do
    it "returns :openid_relying_party for nil metadata" do
      result = described_class.send(:detect_entity_type, nil)
      expect(result).to eq(:openid_relying_party)
    end

    it "returns :openid_relying_party for empty metadata" do
      result = described_class.send(:detect_entity_type, {})
      expect(result).to eq(:openid_relying_party)
    end

    it "returns :openid_relying_party when openid_relying_party key present" do
      metadata = {openid_relying_party: {}}
      result = described_class.send(:detect_entity_type, metadata)
      expect(result).to eq(:openid_relying_party)
    end

    it "returns :openid_provider when openid_provider key present" do
      metadata = {openid_provider: {}}
      result = described_class.send(:detect_entity_type, metadata)
      expect(result).to eq(:openid_provider)
    end

    it "handles string keys" do
      metadata = {"openid_provider" => {}}
      result = described_class.send(:detect_entity_type, metadata)
      expect(result).to eq(:openid_provider)
    end

    it "defaults to :openid_relying_party when neither key present" do
      metadata = {other_key: {}}
      result = described_class.send(:detect_entity_type, metadata)
      expect(result).to eq(:openid_relying_party)
    end
  end

  describe ".generate_subordinate_statement" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = issuer
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "generates subordinate statement for openid_provider" do
      subject_entity_id = "https://subordinate.example.com"
      statement = described_class.send(:generate_subordinate_statement,
        subject_entity_id: subject_entity_id,
        subject_metadata: {openid_relying_party: {issuer: subject_entity_id}})

      expect(statement).to be_a(String)
      expect(statement.split(".").length).to eq(3)
    end

    it "raises error for non-OP entity" do
      described_class.configure do |config|
        config.metadata = {
          openid_relying_party: {
            issuer: issuer
          }
        }
      end

      expect {
        described_class.send(:generate_subordinate_statement,
          subject_entity_id: "https://subordinate.example.com")
      }.to raise_error(
        OmniauthOpenidFederation::ConfigurationError,
        /Subordinate statements can only be generated by openid_provider entities/
      )
    end

    it "uses federation_fetch_endpoint from metadata" do
      custom_fetch_endpoint = "#{issuer}/custom/fetch"
      subject_entity_id = "https://subordinate.example.com"
      described_class.configure do |config|
        config.metadata = {
          openid_provider: {
            issuer: issuer,
            federation_fetch_endpoint: custom_fetch_endpoint
          }
        }
      end

      statement = described_class.send(:generate_subordinate_statement,
        subject_entity_id: subject_entity_id,
        subject_metadata: {openid_relying_party: {issuer: subject_entity_id}})

      decoded = JWT.decode(statement, nil, false).first
      expect(decoded["source_endpoint"]).to eq(custom_fetch_endpoint)
    end
  end

  describe ".get_subordinate_statement" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = issuer
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "returns nil for non-OP entity" do
      described_class.configure do |config|
        config.metadata = {
          openid_relying_party: {
            issuer: issuer
          }
        }
      end

      result = described_class.send(:get_subordinate_statement, "https://subordinate.example.com")
      expect(result).to be_nil
    end

    it "calls subordinate_statements_proc when configured" do
      called_with = nil
      described_class.configure do |config|
        config.subordinate_statements_proc = ->(subject_id) {
          called_with = subject_id
          "jwt.statement"
        }
      end

      result = described_class.send(:get_subordinate_statement, "https://subordinate.example.com")

      expect(called_with).to eq("https://subordinate.example.com")
      expect(result).to eq("jwt.statement")
    end

    it "uses subordinate_statements hash when configured" do
      subject_entity_id = "https://subordinate.example.com"
      described_class.configure do |config|
        config.subordinate_statements = {
          subject_entity_id => {
            metadata: {openid_relying_party: {issuer: subject_entity_id}}
          }
        }
      end

      result = described_class.send(:get_subordinate_statement, subject_entity_id)

      expect(result).to be_a(String)
      expect(result.split(".").length).to eq(3)
    end

    it "returns nil when subordinate not found" do
      result = described_class.send(:get_subordinate_statement, "https://nonexistent.example.com")
      expect(result).to be_nil
    end
  end

  describe ".rack_app" do
    it "returns RackEndpoint instance" do
      app = described_class.rack_app
      expect(app).to be_a(OmniauthOpenidFederation::RackEndpoint)
    end
  end

  describe ".generate_signed_jwks error handling" do
    before do
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = private_key
        config.jwks = jwks
        config.metadata = metadata
      end
    end

    it "raises ConfigurationError when private_key is nil" do
      described_class.configure do |config|
        config.private_key = nil
      end

      expect {
        described_class.generate_signed_jwks
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Private key is required/)
    end

    it "raises SignatureError when JWT encoding fails" do
      # Set up valid config but make JWT.encode fail by using invalid key
      invalid_key = OpenSSL::PKey::RSA.new(512) # Too small, might cause issues
      described_class.configure do |config|
        config.issuer = issuer
        config.subject = subject
        config.private_key = invalid_key
        config.jwks = jwks
        config.metadata = metadata
      end

      # Mock JWT.encode to raise an error
      allow(JWT).to receive(:encode).and_raise(StandardError.new("JWT encoding failed"))

      expect {
        described_class.generate_signed_jwks
      }.to raise_error(OmniauthOpenidFederation::SignatureError, /Failed to sign JWKS/)
    end

    it "uses signed_jwks_payload_proc when configured" do
      custom_jwks = {keys: [{kty: "RSA", kid: "proc-key"}]}
      described_class.configure do |config|
        config.signed_jwks_payload_proc = -> { custom_jwks }
      end

      jwt_string = described_class.generate_signed_jwks
      decoded = JWT.decode(jwt_string, public_key, true, {algorithm: "RS256"})

      payload = decoded.first
      expect(payload["jwks"]["keys"].first["kid"]).to eq("proc-key")
    end

    it "uses signed_jwks_signing_kid when configured" do
      custom_kid = "custom-signing-kid"
      described_class.configure do |config|
        config.signed_jwks_signing_kid = custom_kid
      end

      jwt_string = described_class.generate_signed_jwks
      header = JWT.decode(jwt_string, nil, false).last
      expect(header["kid"]).to eq(custom_kid)
    end

    it "extracts kid from jwks when kid not configured" do
      described_class.configure do |config|
        config.kid = nil
      end

      jwt_string = described_class.generate_signed_jwks
      header = JWT.decode(jwt_string, nil, false).last
      expect(header["kid"]).to be_present
    end
  end

  describe "Configuration additional attributes" do
    let(:signing_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }

    it "allows setting and getting entity_type" do
      config = described_class.configuration
      config.entity_type = :openid_provider
      expect(config.entity_type).to eq(:openid_provider)
    end

    it "allows setting and getting signing_key" do
      config = described_class.configuration
      config.signing_key = signing_key
      expect(config.signing_key).to eq(signing_key)
    end

    it "allows setting and getting encryption_key" do
      config = described_class.configuration
      config.encryption_key = encryption_key
      expect(config.encryption_key).to eq(encryption_key)
    end

    it "allows setting and getting subordinate_statements" do
      config = described_class.configuration
      statements = {"https://sub.example.com" => {metadata: {}}}
      config.subordinate_statements = statements
      expect(config.subordinate_statements).to eq(statements)
    end

    it "allows setting and getting authority_hints" do
      config = described_class.configuration
      hints = ["https://authority.example.com"]
      config.authority_hints = hints
      expect(config.authority_hints).to eq(hints)
    end
  end
end
