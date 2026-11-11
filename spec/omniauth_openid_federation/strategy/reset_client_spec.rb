# frozen_string_literal: true

require "spec_helper"

RSpec.describe OmniAuth::Strategies::OpenIDFederation, "#reset_client!", type: :strategy do
  let(:private_key) { OpenSSL::PKey::RSA.new(2048) }

  it "clears the memoized client so the next access rebuilds" do
    strategy = described_class.new(
      nil,
      client_options: {
        identifier: "rp",
        redirect_uri: "https://rp.example.com/cb",
        authorization_endpoint: "https://op.example.com/authorize",
        token_endpoint: "https://op.example.com/token",
        private_key: private_key
      }
    )

    first = strategy.client
    second = strategy.client
    expect(second).to equal(first)

    strategy.reset_client!
    third = strategy.client
    expect(third).not_to equal(first)
  end
end
