require "spec_helper"

RSpec.describe OmniauthOpenidFederation::FederationEndpoint do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:encryption_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }
  let(:client_issuer) { "https://client.example.com" }

  def client_metadata
    {
      openid_relying_party: {
        redirect_uris: ["https://example.com/callback"],
        client_registration_types: ["automatic"]
      }
    }
  end

  def provider_metadata
    {
      openid_provider: {
        issuer: provider_issuer,
        authorization_endpoint: "#{provider_issuer}/oauth2/authorize",
        token_endpoint: "#{provider_issuer}/oauth2/token",
        jwks_uri: "#{provider_issuer}/.well-known/jwks.json",
        signed_jwks_uri: "#{provider_issuer}/.well-known/signed-jwks.json"
      }
    }
  end

  def jwks_from_key(key = private_key)
    {keys: [OmniauthOpenidFederation::Utils.rsa_key_to_jwk(key)]}
  end

  def reset_configuration!
    described_class.instance_variable_set(:@configuration, nil)
  end

  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
    reset_configuration!
  end

  after { reset_configuration! }

  describe "error paths" do
    it "handles configuration errors in generate_entity_statement" do
      expect {
        described_class.generate_entity_statement
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles configuration errors in generate_signed_jwks" do
      expect {
        described_class.generate_signed_jwks
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles configuration errors in current_jwks" do
      expect {
        described_class.current_jwks
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles auto_configure with missing parameters" do
      expect {
        described_class.auto_configure(
          entity_identifier: nil,
          private_key: private_key
        )
      }.to raise_error(ArgumentError, /missing keyword/)
    end

    it "handles configure with invalid parameters" do
      described_class.configure do |config|
        config.issuer = nil
        config.private_key = private_key
      end

      expect {
        described_class.generate_entity_statement
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "rejects signing_key, encryption_key, and private_key together" do
      expect {
        described_class.auto_configure(
          issuer: provider_issuer,
          signing_key: private_key,
          encryption_key: encryption_key,
          private_key: OpenSSL::PKey::RSA.new(2048),
          metadata: client_metadata
        )
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Cannot specify/)
    end

    it "requires a key source when auto_provision_keys is false" do
      expect {
        described_class.auto_configure(
          issuer: provider_issuer,
          auto_provision_keys: false,
          metadata: client_metadata
        )
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /At least one key source/)
    end
  end

  describe "auto_configure" do
    it "configures with private_key and generates entity statement JWT" do
      config = described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        metadata: client_metadata
      )

      jwt = described_class.generate_entity_statement
      aggregate_failures do
        expect(config.issuer).to eq(provider_issuer)
        expect(config.subject).to eq(provider_issuer)
        expect(jwt.split(".").length).to eq(3)
      end
    end

    it "configures with separate signing and encryption keys" do
      config = described_class.auto_configure(
        issuer: provider_issuer,
        signing_key: private_key,
        encryption_key: encryption_key,
        metadata: client_metadata
      )

      keys = config.jwks[:keys] || config.jwks["keys"]
      aggregate_failures do
        expect(keys.length).to eq(2)
        expect(keys.map { |k| k[:use] || k["use"] }).to contain_exactly("sig", "enc")
        expect(described_class.generate_entity_statement).to be_present
      end
    end

    it "auto-generates relying party metadata when metadata is omitted" do
      described_class.auto_configure(issuer: provider_issuer, private_key: private_key)

      metadata = described_class.configuration.metadata
      aggregate_failures do
        expect(metadata).to have_key(:openid_relying_party)
        expect(metadata[:openid_relying_party][:jwks_uri]).to include("/.well-known/jwks.json")
        expect(metadata[:openid_relying_party][:signed_jwks_uri]).to include("/.well-known/signed-jwks.json")
      end
    end

    it "ensures jwks endpoints on openid_provider metadata" do
      described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        metadata: {openid_provider: {issuer: provider_issuer}}
      )

      section = described_class.configuration.metadata[:openid_provider]
      aggregate_failures do
        expect(section[:jwks_uri]).to eq("#{provider_issuer}/.well-known/jwks.json")
        expect(section[:signed_jwks_uri]).to eq("#{provider_issuer}/.well-known/signed-jwks.json")
        expect(section[:federation_fetch_endpoint]).to eq("#{provider_issuer}/.well-known/openid-federation/fetch")
      end
    end

    it "writes entity statement and key files when entity_statement_path is provided" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        entity_statement_path: entity_statement_path,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(File.exist?(entity_statement_path)).to be(true)
        expect(File.exist?(File.join(output_dir, ".federation-signing-key.pem"))).to be(true)
        expect(File.exist?(File.join(output_dir, ".federation-encryption-key.pem"))).to be(true)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "configures with signing_key only when jwks are provided" do
      config = described_class.auto_configure(
        issuer: provider_issuer,
        signing_key: private_key,
        jwks: jwks_from_key,
        auto_provision_keys: false,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(config.signing_key).to eq(private_key)
        expect(config.encryption_key).to eq(private_key)
        expect(config.private_key).to eq(private_key)
      end
    end

    it "writes separate signing and encryption key files when both are provided" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      described_class.auto_configure(
        issuer: provider_issuer,
        signing_key: private_key,
        encryption_key: encryption_key,
        jwks: jwks_from_key,
        entity_statement_path: entity_statement_path,
        auto_provision_keys: false,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(File.exist?(File.join(output_dir, ".federation-signing-key.pem"))).to be(true)
        expect(File.exist?(File.join(output_dir, ".federation-encryption-key.pem"))).to be(true)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "defaults entity type to relying party for unrecognized metadata" do
      described_class.auto_configure(
        issuer: client_issuer,
        private_key: private_key,
        metadata: {organization: {name: "Example Org"}}
      )

      expect(described_class.configuration.entity_type).to eq(:openid_relying_party)
    end

    it "raises when auto_provision_keys cannot obtain signing material" do
      allow(described_class).to receive(:provision_jwks).and_return(nil)

      expect {
        described_class.auto_configure(
          issuer: provider_issuer,
          auto_provision_keys: true,
          metadata: client_metadata
        )
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Signing key is required/)
    end

    it "uses keys loaded onto configuration during provisioning" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")
      jwt = JWT.encode(
        {
          iss: client_issuer,
          sub: client_issuer,
          jwks: jwks_from_key,
          metadata: client_metadata
        },
        private_key,
        "RS256"
      )
      File.write(entity_statement_path, jwt)
      File.write(File.join(output_dir, ".federation-signing-key.pem"), private_key.to_pem)
      File.write(File.join(output_dir, ".federation-encryption-key.pem"), encryption_key.to_pem)

      config = described_class.auto_configure(
        issuer: client_issuer,
        auto_provision_keys: true,
        entity_statement_path: entity_statement_path,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(config.private_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.signing_key).to be_a(OpenSSL::PKey::RSA)
        expect(config.encryption_key).to be_a(OpenSSL::PKey::RSA)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "reuses signing key already stored on configuration" do
      described_class.configure do |config|
        config.signing_key = private_key
      end

      config = described_class.auto_configure(
        issuer: client_issuer,
        jwks: jwks_from_key,
        auto_provision_keys: false,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(config.private_key).to eq(private_key)
        expect(config.encryption_key).to eq(private_key)
      end
    end

    it "raises when JWKS is present but no signing material is available" do
      allow(described_class).to receive(:provision_jwks).and_return({keys: [{kty: "RSA", kid: "orphan"}]})

      expect {
        described_class.auto_configure(
          issuer: client_issuer,
          auto_provision_keys: true,
          metadata: client_metadata
        )
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Signing key is required/)
    end
  end

  describe "generate_entity_statement, generate_signed_jwks, and current_jwks" do
    before do
      described_class.configure do |config|
        config.issuer = provider_issuer
        config.subject = provider_issuer
        config.private_key = private_key
        config.jwks = jwks_from_key
        config.metadata = client_metadata
      end
    end

    it "generates entity statement JWT" do
      jwt = described_class.generate_entity_statement
      payload = JSON.parse(Base64.urlsafe_decode64(jwt.split(".")[1]))

      aggregate_failures do
        expect(jwt.split(".").length).to eq(3)
        expect(payload["iss"]).to eq(provider_issuer)
        expect(payload["sub"]).to eq(provider_issuer)
      end
    end

    it "generates signed JWKS JWT" do
      signed_jwks = described_class.generate_signed_jwks
      payload = JSON.parse(Base64.urlsafe_decode64(signed_jwks.split(".")[1]))

      aggregate_failures do
        expect(signed_jwks.split(".").length).to eq(3)
        expect(payload["jwks"]).to be_present
      end
    end

    it "raises SignatureError when signed JWKS signing fails" do
      allow(JWT).to receive(:encode).and_raise(StandardError.new("sign failed"))

      expect { described_class.generate_signed_jwks }
        .to raise_error(OmniauthOpenidFederation::SignatureError, /Failed to sign JWKS/)
    end

    it "returns current JWKS from configuration" do
      expect(described_class.current_jwks).to eq(jwks_from_key)
    end

    it "uses current_jwks_proc when set" do
      custom_jwks = {keys: [{kty: "RSA", kid: "custom"}]}
      described_class.configuration.current_jwks_proc = -> { custom_jwks }

      expect(described_class.current_jwks).to eq(custom_jwks)
    end
  end

  describe "provision_jwks" do
    it "builds JWKS from signing and encryption keys" do
      jwks = described_class.provision_jwks(
        signing_key: private_key,
        encryption_key: encryption_key
      )

      keys = jwks[:keys]
      aggregate_failures do
        expect(keys.length).to eq(2)
        expect(keys.map { |k| k[:use] }).to contain_exactly("sig", "enc")
      end
    end

    it "extracts JWKS from an existing entity statement file" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")
      jwt = JWT.encode(
        {
          iss: provider_issuer,
          sub: provider_issuer,
          jwks: jwks_from_key,
          metadata: client_metadata
        },
        private_key,
        "RS256"
      )
      File.write(entity_statement_path, jwt)
      File.write(File.join(output_dir, ".federation-signing-key.pem"), private_key.to_pem)
      File.write(File.join(output_dir, ".federation-encryption-key.pem"), private_key.to_pem)

      jwks = described_class.provision_jwks(entity_statement_path: entity_statement_path)

      aggregate_failures do
        expect(jwks[:keys]).to be_present
        expect(described_class.configuration.signing_key).to be_a(OpenSSL::PKey::RSA)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "loads a single signing key file from disk when encryption key file is absent" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")
      jwt = JWT.encode(
        {
          iss: provider_issuer,
          sub: provider_issuer,
          jwks: jwks_from_key,
          metadata: client_metadata
        },
        private_key,
        "RS256"
      )
      File.write(entity_statement_path, jwt)
      File.write(File.join(output_dir, ".federation-signing-key.pem"), private_key.to_pem)

      jwks = described_class.provision_jwks(entity_statement_path: entity_statement_path)

      aggregate_failures do
        expect(jwks[:keys]).to be_present
        expect(described_class.configuration.signing_key).to eq(described_class.configuration.encryption_key)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "returns a single JWK when signing and encryption keys are the same" do
      jwks = described_class.provision_jwks(signing_key: private_key, encryption_key: private_key)

      expect(jwks[:keys].length).to eq(1)
    end

    it "auto-generates keys when entity statement extraction fails" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")
      File.write(entity_statement_path, "invalid")

      jwks = described_class.provision_jwks(
        entity_statement_path: entity_statement_path,
        issuer: client_issuer,
        metadata: client_metadata
      )

      expect(jwks[:keys].length).to eq(2)
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "warns when on-disk private key files cannot be parsed" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")
      jwt = JWT.encode(
        {
          iss: provider_issuer,
          sub: provider_issuer,
          jwks: jwks_from_key,
          metadata: client_metadata
        },
        private_key,
        "RS256"
      )
      File.write(entity_statement_path, jwt)
      File.write(File.join(output_dir, ".federation-signing-key.pem"), "not-a-key")
      File.write(File.join(output_dir, ".federation-encryption-key.pem"), "not-a-key")

      jwks = described_class.provision_jwks(entity_statement_path: entity_statement_path)

      expect(jwks[:keys]).to be_present
    ensure
      FileUtils.rm_rf(output_dir)
    end
  end

  describe "generate_fresh_keys and rotate_keys_if_needed" do
    it "generates fresh keys and writes entity statement file" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: provider_issuer,
        metadata: client_metadata
      )

      aggregate_failures do
        expect(jwks[:keys].length).to eq(2)
        expect(File.exist?(entity_statement_path)).to be(true)
        expect(File.exist?(File.join(output_dir, ".federation-signing-key.pem"))).to be(true)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "rotates keys when rotation period has elapsed" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        entity_statement_path: entity_statement_path,
        metadata: client_metadata,
        key_rotation_period: 1
      )

      original_mtime = File.mtime(entity_statement_path)
      FileUtils.touch(entity_statement_path, mtime: Time.now - 10)

      described_class.rotate_keys_if_needed(described_class.configuration)

      aggregate_failures do
        expect(File.mtime(entity_statement_path)).to be > original_mtime
        expect(described_class.configuration.jwks[:keys].length).to eq(2)
      end
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "keeps existing keys when rotation generation fails" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        entity_statement_path: entity_statement_path,
        metadata: client_metadata,
        key_rotation_period: 1
      )
      original_jwks = described_class.configuration.jwks
      FileUtils.touch(entity_statement_path, mtime: Time.now - 10)
      allow(described_class).to receive(:generate_fresh_keys).and_return(nil)

      described_class.rotate_keys_if_needed(described_class.configuration)

      expect(described_class.configuration.jwks).to eq(original_jwks)
    ensure
      FileUtils.rm_rf(output_dir)
    end

    it "returns nil when generate_fresh_keys is called without issuer" do
      reset_configuration!

      expect(
        described_class.generate_fresh_keys(
          entity_statement_path: "entity.jwt",
          issuer: nil,
          metadata: client_metadata
        )
      ).to be_nil
    end

    it "returns nil when generate_fresh_keys raises an error" do
      allow(OmniauthOpenidFederation::Federation::EntityStatementBuilder).to receive(:new)
        .and_raise(StandardError.new("builder failed"))

      expect(
        described_class.generate_fresh_keys(
          entity_statement_path: "entity.jwt",
          issuer: provider_issuer,
          metadata: client_metadata
        )
      ).to be_nil
    end

    it "generates minimal metadata when metadata is omitted" do
      output_dir = Dir.mktmpdir
      entity_statement_path = File.join(output_dir, "entity.jwt")

      jwks = described_class.generate_fresh_keys(
        entity_statement_path: entity_statement_path,
        issuer: client_issuer,
        metadata: nil
      )

      expect(jwks[:keys].length).to eq(2)
    ensure
      FileUtils.rm_rf(output_dir)
    end
  end

  describe "get_subordinate_statement" do
    before do
      described_class.auto_configure(
        issuer: provider_issuer,
        private_key: private_key,
        metadata: provider_metadata
      )
    end

    it "returns nil for relying party entity type" do
      described_class.configuration.metadata = client_metadata
      described_class.configuration.entity_type = :openid_relying_party

      expect(described_class.get_subordinate_statement(client_issuer)).to be_nil
    end

    it "returns subordinate statement from configured hash" do
      described_class.configuration.subordinate_statements = {
        client_issuer => {
          metadata: client_metadata
        }
      }

      jwt = described_class.get_subordinate_statement(client_issuer)
      payload = JSON.parse(Base64.urlsafe_decode64(jwt.split(".")[1]))

      aggregate_failures do
        expect(jwt.split(".").length).to eq(3)
        expect(payload["sub"]).to eq(client_issuer)
        expect(payload["iss"]).to eq(provider_issuer)
      end
    end

    it "returns subordinate statement from proc" do
      described_class.configuration.subordinate_statements_proc = ->(_subject) { "header.payload.sig" }

      expect(described_class.get_subordinate_statement(client_issuer)).to eq("header.payload.sig")
    end

    it "rejects subordinate generation for relying party entity type" do
      described_class.configuration.metadata = client_metadata

      expect {
        described_class.send(:generate_subordinate_statement, subject_entity_id: client_issuer)
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /openid_provider/)
    end
  end

  describe "rack_app" do
    before do
      described_class.configure do |config|
        config.issuer = provider_issuer
        config.private_key = private_key
        config.jwks = jwks_from_key
        config.metadata = client_metadata
      end
    end

    it "returns a Rack endpoint handler" do
      expect(described_class.rack_app).to be_a(OmniauthOpenidFederation::RackEndpoint)
    end
  end
end

# NOTE: Tests for other modules have been moved to their respective spec files:
# - JWKS::Fetch tests -> spec/omniauth_openid_federation/jwks/fetch_spec.rb
# - JWKS::Decode tests -> spec/omniauth_openid_federation/jwks/decode_spec.rb
# - EntityStatementParser tests -> spec/omniauth_openid_federation/federation/entity_statement_parser_spec.rb
# - EndpointResolver tests -> spec/omniauth_openid_federation/endpoint_resolver_spec.rb
# - EntityStatementReader tests -> spec/omniauth_openid_federation/entity_statement_reader_spec.rb
# - SignedJWKS tests -> spec/omniauth_openid_federation/federation/signed_jwks_spec.rb
# - Jws tests -> spec/omniauth_openid_federation/jws_spec.rb
# - Utils tests -> spec/omniauth_openid_federation/utils_spec.rb
