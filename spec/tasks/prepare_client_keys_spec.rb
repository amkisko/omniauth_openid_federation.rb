# frozen_string_literal: true

require "spec_helper"
require "rake"

# rubocop:disable RSpec/DescribeClass
RSpec.describe "openid_federation:prepare_client_keys" do
  include_context "with rake tasks helpers"

  def verify_single_key_files(temp_dir)
    private_key_path = File.join(temp_dir, "client-private-key.pem")
    jwks_path = File.join(temp_dir, "client-jwks.json")
    expect(File.exist?(private_key_path)).to be true
    expect(File.exist?(jwks_path)).to be true
    expect(File.stat(private_key_path).mode & 0o777).to eq(0o600)
    private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))
    expect(private_key).to be_private
    jwks = JSON.parse(File.read(jwks_path))
    expect(jwks["keys"].length).to eq(1)
    expect(jwks["keys"][0]["kty"]).to eq("RSA")
    expect(jwks["keys"][0]["use"]).to be_nil
  end

  def verify_separate_key_files(temp_dir)
    signing_key_path = File.join(temp_dir, "client-signing-private-key.pem")
    encryption_key_path = File.join(temp_dir, "client-encryption-private-key.pem")
    jwks_path = File.join(temp_dir, "client-jwks.json")
    expect(File.exist?(signing_key_path)).to be true
    expect(File.exist?(encryption_key_path)).to be true
    expect(File.exist?(jwks_path)).to be true
    expect(File.stat(signing_key_path).mode & 0o777).to eq(0o600)
    expect(File.stat(encryption_key_path).mode & 0o777).to eq(0o600)
    signing_key = OpenSSL::PKey::RSA.new(File.read(signing_key_path))
    encryption_key = OpenSSL::PKey::RSA.new(File.read(encryption_key_path))
    expect(signing_key.to_pem).not_to eq(encryption_key.to_pem)
    jwks = JSON.parse(File.read(jwks_path))
    expect(jwks["keys"].length).to eq(2)
    signing_key_jwk = jwks["keys"].find { |k| k["use"] == "sig" }
    encryption_key_jwk = jwks["keys"].find { |k| k["use"] == "enc" }
    expect(signing_key_jwk).to be_present
    expect(encryption_key_jwk).to be_present
  end

  context "when key_type is invalid" do
    it "exits with error" do
      result = run_rake_task("openid_federation:prepare_client_keys", "invalid", temp_dir)

      aggregate_failures do
        expect(result[:stdout]).to include("❌ Invalid key_type:")
        expect(result[:stdout]).to include("Valid options:")
      end
    end
  end

  context "when key_type is 'single'" do
    it "generates single key pair" do
      result = run_rake_task("openid_federation:prepare_client_keys", "single", temp_dir)

      aggregate_failures do
        verify_single_key_files(temp_dir)
        expect(result[:stdout]).to include("✅ Keys generated successfully:")
        expect(result[:stdout]).to include("Private key:")
        expect(result[:stdout]).to include("Public JWKS:")
      end
    end

    it "displays JWKS for provider registration" do
      result = run_rake_task("openid_federation:prepare_client_keys", "single", temp_dir)

      aggregate_failures do
        expect(result[:stdout]).to include("📋 Send this JWKS to your provider for client registration:")
        expect(result[:stdout]).to include("SECURITY WARNING:")
      end
    end
  end

  context "when key_type is 'separate'" do
    it "generates separate signing and encryption keys" do
      result = run_rake_task("openid_federation:prepare_client_keys", "separate", temp_dir)

      aggregate_failures do
        verify_separate_key_files(temp_dir)
        expect(result[:stdout]).to include("✅ Keys generated successfully:")
        expect(result[:stdout]).to include("Signing private key:")
        expect(result[:stdout]).to include("Encryption private key:")
      end
    end
  end

  context "when output directory does not exist" do
    let(:new_dir) { File.join(temp_dir, "new_dir") }

    it "creates output directory" do
      result = run_rake_task("openid_federation:prepare_client_keys", "single", new_dir)

      aggregate_failures do
        expect(Dir.exist?(new_dir)).to be true
        expect(result[:stdout]).to include("Created output directory:")
      end
    end
  end

  context "when using environment variables" do
    before do
      ENV["KEY_TYPE"] = "single"
      ENV["KEYS_OUTPUT_DIR"] = temp_dir
    end

    it "uses environment variables" do
      run_rake_task("openid_federation:prepare_client_keys")

      expect(File.exist?(File.join(temp_dir, "client-private-key.pem"))).to be true
    end
  end

  context "when key generation fails" do
    before do
      allow(OpenSSL::PKey::RSA).to receive(:new).and_raise(OpenSSL::PKey::RSAError.new("Key generation failed"))
    end

    it "exits with error" do
      result = run_rake_task("openid_federation:prepare_client_keys", "single", temp_dir)

      expect(result[:stdout]).to include("❌ Error generating keys:")
    end
  end
end
# rubocop:enable RSpec/DescribeClass
