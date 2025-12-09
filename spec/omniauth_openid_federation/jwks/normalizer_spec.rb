require "spec_helper"

RSpec.describe OmniauthOpenidFederation::Jwks::Normalizer do
  describe ".to_jwks_hash" do
    context "with hash containing keys array" do
      it "normalizes hash with string keys" do
        jwks = {"keys" => [{kty: "RSA", kid: "1"}]}
        result = described_class.to_jwks_hash(jwks)

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_an(Array)
          expect(result["keys"].first).to be_a(Hash)
        end
      end

      it "normalizes hash with symbol keys" do
        jwks = {keys: [{kty: "RSA", kid: "1"}]}
        result = described_class.to_jwks_hash(jwks)

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_an(Array)
        end
      end
    end

    context "with array of keys" do
      it "converts array to hash with keys array" do
        jwks = [{kty: "RSA", kid: "1"}, {kty: "RSA", kid: "2"}]
        result = described_class.to_jwks_hash(jwks)

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_an(Array)
          expect(result["keys"].length).to eq(2)
        end
      end
    end

    context "with other formats" do
      it "handles empty hash" do
        result = described_class.to_jwks_hash({})
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to eq([])
        end
      end

      it "handles nil" do
        result = described_class.to_jwks_hash(nil)
        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to eq([])
        end
      end

      it "handles non-Hash JWK objects" do
        # Create a mock object that responds to to_json but is not a Hash
        jwk_object = double("JWKObject")
        allow(jwk_object).to receive(:to_json).and_return('{"kty":"RSA","kid":"1"}')
        allow(JSON).to receive(:parse).with('{"kty":"RSA","kid":"1"}').and_return({"kty" => "RSA", "kid" => "1"})

        jwks = [jwk_object]
        result = described_class.to_jwks_hash(jwks)

        aggregate_failures do
          expect(result).to be_a(Hash)
          expect(result["keys"]).to be_an(Array)
          expect(result["keys"].length).to eq(1)
        end
      end
    end
  end
end
