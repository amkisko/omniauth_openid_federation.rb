require "simplecov"
require "simplecov-cobertura"

SimpleCov.start do
  track_files "{lib,app}/**/*.rb"
  add_filter "/lib/tasks/"
  formatter SimpleCov::Formatter::MultiFormatter.new([
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::CoberturaFormatter
  ])
end

require "rspec"
require "tempfile"
require "openssl"
require "base64"
require "json"
require "digest"
require_relative "../lib/omniauth_openid_federation"

# Load controller if Rails is available (for controller specs)
if defined?(Rails) && defined?(ActionController::Base)
  controller_path = File.expand_path("../app/controllers/omniauth_openid_federation/federation_controller.rb", __dir__)
  require controller_path if File.exist?(controller_path)
end

Dir[File.expand_path("support/**/*.rb", __dir__)].sort.each { |f| require_relative f }

# Include HTTP stubbing helpers in all specs
RSpec.configure do |config|
  config.include HttpStubbing
end

RSpec.configure do |config|
  # Clear cache adapter before each test to prevent test pollution
  config.before(:each) do
    OmniauthOpenidFederation::CacheAdapter.reset!
    # Only clear if adapter is available and not a test double
    begin
      if OmniauthOpenidFederation::CacheAdapter.available?
        adapter = OmniauthOpenidFederation::CacheAdapter.adapter
        # Skip clearing if it's a test double (they don't persist between tests)
        # or if it's a RailsCacheAdapter wrapping a double
        should_clear = true
        if adapter.is_a?(RSpec::Mocks::Double) || adapter.is_a?(RSpec::Mocks::InstanceVerifyingDouble)
          should_clear = false
        elsif adapter.is_a?(OmniauthOpenidFederation::CacheAdapter::RailsCacheAdapter)
          # Check if the wrapped cache store is a double
          cache_store = adapter.instance_variable_get(:@cache_store)
          if cache_store.is_a?(RSpec::Mocks::Double) || cache_store.is_a?(RSpec::Mocks::InstanceVerifyingDouble)
            should_clear = false
          end
        end

        OmniauthOpenidFederation::CacheAdapter.clear if should_clear
      end
    rescue
      # Ignore errors during cleanup (e.g., doubles that are no longer valid)
    end

    # Clear WebMock stubs between tests to prevent test pollution
    # This ensures each test starts with a clean slate
    WebMock.reset! if defined?(WebMock)
  end

  # Ensure WebMock blocks all HTTP requests by default
  # All requests must be explicitly stubbed
  config.before(:suite) do
    if defined?(WebMock)
      # Double-check that WebMock is blocking all requests including localhost
      # This prevents any real HTTP requests from being made during tests
      WebMock.disable_net_connect!(allow_localhost: false)
    end
  end

  # Remove old coverage.xml before suite if SHOW_ZERO_COVERAGE is set
  config.before(:suite) do
    if ENV["SHOW_ZERO_COVERAGE"] == "1"
      require "fileutils"
      FileUtils.rm_f("coverage/coverage.xml")
    end
  end
end

# Run coverage analyzer after SimpleCov finishes writing coverage.xml
# Use SimpleCov.at_exit to ensure our hook runs after the formatter writes files
# We need to call the formatter first, then run our analyzer
if ENV["SHOW_ZERO_COVERAGE"] == "1"
  SimpleCov.at_exit do
    # First, ensure the formatter runs (this writes coverage.xml)
    SimpleCov.result.format!
    # Then run our analyzer
    require_relative "support/coverage_analyzer"
    CoverageAnalyzer.run
  end
end
