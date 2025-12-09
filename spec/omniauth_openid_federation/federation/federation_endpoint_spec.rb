require "spec_helper"

RSpec.describe OmniauthOpenidFederation::FederationEndpoint do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:public_key) { private_key.public_key }
  let(:provider_issuer) { "https://provider.example.com" }

  # Stub all HTTP requests for tests that use relative paths
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end

  describe "error paths" do
    before do
      # Reset configuration
      described_class.instance_variable_set(:@configuration, nil)
    end

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
      # current_jwks raises ConfigurationError when not configured
      expect {
        described_class.current_jwks
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
    end

    it "handles auto_configure with missing parameters" do
      # auto_configure requires issuer as a keyword argument, so it raises ArgumentError if missing
      expect {
        described_class.auto_configure(
          entity_identifier: nil,
          private_key: private_key
        )
      }.to raise_error(ArgumentError, /missing keyword/)
    end

    it "handles configure with invalid parameters" do
      # configure doesn't validate immediately - validation happens when using the config
      described_class.configure do |config|
        config.issuer = nil
        config.private_key = private_key
      end

      # Validation happens when trying to generate entity statement
      expect {
        described_class.generate_entity_statement
      }.to raise_error(OmniauthOpenidFederation::ConfigurationError, /Issuer is required/)
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
