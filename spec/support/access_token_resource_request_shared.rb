# frozen_string_literal: true

RSpec.shared_context "access token resource_request" do
  before do
    stub_relative_path_endpoints(host: URI.parse(provider_issuer).host)
  end

  after do
    if defined?(Rails)
      RSpec::Mocks.space.proxy_for(Rails)&.reset
    end
    if defined?(OmniauthOpenidFederation::Logger)
      RSpec::Mocks.space.proxy_for(OmniauthOpenidFederation::Logger)&.reset
    end
  rescue
    nil
  end
end

RSpec.configure do |config|
  config.include_context "access token resource_request", type: :access_token
end
