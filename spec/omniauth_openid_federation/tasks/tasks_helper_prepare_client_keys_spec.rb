require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".prepare_client_keys" do
    let(:temp_dir) { Dir.mktmpdir }

    after do
      FileUtils.rm_rf(temp_dir)
    end

    context "with single key type" do
      it "writes a private key and public JWKS file" do
        result = described_class.prepare_client_keys(
          key_type: "single",
          output_dir: temp_dir
        )

        private_key_path = File.join(temp_dir, "client-private-key.pem")
        public_jwks_path = File.join(temp_dir, "client-jwks.json")

        aggregate_failures do
          expect(result[:success]).to be true
          expect(result[:output_path]).to eq(temp_dir)
          expect(result[:private_key_path]).to eq(private_key_path)
          expect(result[:public_jwks_path]).to eq(public_jwks_path)
          expect(File.exist?(private_key_path)).to be true
          expect(File.exist?(public_jwks_path)).to be true
          expect(File.stat(private_key_path).mode & 0o777).to eq(0o600)

          private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))
          expect(private_key).to be_private

          jwks = JSON.parse(File.read(public_jwks_path))
          expect(jwks["keys"].length).to eq(1)
          expect(jwks["keys"][0]["kty"]).to eq("RSA")
          expect(jwks["keys"][0]["use"]).to be_nil
          expect(result[:jwks][:keys].length).to eq(1)
          expect(result[:jwks][:keys].first[:kty]).to eq("RSA")
        end
      end
    end

    context "with separate key type" do
      it "writes signing and encryption keys with matching JWKS" do
        result = described_class.prepare_client_keys(
          key_type: "separate",
          output_dir: temp_dir
        )

        signing_key_path = File.join(temp_dir, "client-signing-private-key.pem")
        encryption_key_path = File.join(temp_dir, "client-encryption-private-key.pem")
        public_jwks_path = File.join(temp_dir, "client-jwks.json")

        aggregate_failures do
          expect(result[:success]).to be true
          expect(result[:output_path]).to eq(temp_dir)
          expect(result[:signing_key_path]).to eq(signing_key_path)
          expect(result[:encryption_key_path]).to eq(encryption_key_path)
          expect(result[:public_jwks_path]).to eq(public_jwks_path)
          expect(File.exist?(signing_key_path)).to be true
          expect(File.exist?(encryption_key_path)).to be true
          expect(File.stat(signing_key_path).mode & 0o777).to eq(0o600)
          expect(File.stat(encryption_key_path).mode & 0o777).to eq(0o600)

          signing_key = OpenSSL::PKey::RSA.new(File.read(signing_key_path))
          encryption_key = OpenSSL::PKey::RSA.new(File.read(encryption_key_path))
          expect(signing_key.to_pem).not_to eq(encryption_key.to_pem)

          jwks = JSON.parse(File.read(public_jwks_path))
          expect(jwks["keys"].length).to eq(2)
          expect(jwks["keys"].find { |key| key["use"] == "sig" }).to be_present
          expect(jwks["keys"].find { |key| key["use"] == "enc" }).to be_present
          expect(result[:jwks][:keys].length).to eq(2)
          expect(result[:jwks][:keys].map { |key| key[:use] || key["use"] }).to contain_exactly("sig", "enc")
        end
      end
    end

    context "with invalid key type" do
      it "raises ArgumentError" do
        expect {
          described_class.prepare_client_keys(
            key_type: "invalid",
            output_dir: temp_dir
          )
        }.to raise_error(ArgumentError, /Invalid key_type/)
      end
    end

    context "when output directory does not exist" do
      it "creates the directory before writing keys" do
        output_dir = File.join(temp_dir, "nested", "keys")

        result = described_class.prepare_client_keys(
          key_type: "single",
          output_dir: output_dir
        )

        aggregate_failures do
          expect(Dir.exist?(output_dir)).to be true
          expect(result[:success]).to be true
          expect(File.exist?(File.join(output_dir, "client-private-key.pem"))).to be true
        end
      end
    end
  end
end
