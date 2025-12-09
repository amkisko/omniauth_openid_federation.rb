require "simplecov"
require "simplecov-cobertura"
require "simplecov_json_formatter"

SimpleCov.start do
  track_files "{lib,app}/**/*.rb"
  add_filter "/lib/tasks/"
  add_filter "/lib/omniauth_openid_federation/version.rb"
  add_filter "/spec/"
  formatter SimpleCov::Formatter::MultiFormatter.new([
    SimpleCov::Formatter::HTMLFormatter,
    SimpleCov::Formatter::CoberturaFormatter,
    SimpleCov::Formatter::JSONFormatter
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

  # Use defined order for reproducible test runs
  # This helps identify test isolation issues by ensuring consistent execution order
  # Rails-dependent tests (controllers, railtie) should run early to avoid state pollution
  config.order = :defined

  # Custom ordering: Run Rails-dependent tests first before any tests that stub Rails
  # This prevents test isolation issues where Rails stubs break subsequent Rails-dependent tests
  config.register_ordering :global do |items|
    # Separate Rails-dependent tests from others
    rails_dependent = []
    other_tests = []
    items.each do |item|
      if /(federation_controller|railtie)/.match?(item.metadata[:file_path])
        rails_dependent << item
      else
        other_tests << item
      end
    end
    # Run Rails-dependent tests first, then others
    [*rails_dependent, *other_tests]
  end

  # Ensure Rails-dependent tests run first to avoid state pollution from other tests
  # This helps with test isolation by running tests that require clean Rails state early
  config.before(:suite) do
    # Rails tests will run first due to alphabetical file ordering
    # (controllers/ and railtie_spec.rb come early alphabetically)
  end
end

RSpec.configure do |config|
  # Clear cache adapter before each test to prevent test pollution
  config.before do
    # Reset FederationEndpoint configuration to prevent test isolation issues
    # This ensures tests that modify configuration don't affect other tests
    if defined?(OmniauthOpenidFederation::FederationEndpoint)
      OmniauthOpenidFederation::FederationEndpoint.instance_variable_set(:@configuration, nil)
    end

    # Restore Rails if it was stubbed or hidden by previous tests
    # Tests that use stub_const("Rails", ...) or hide_const("Rails") can break subsequent Rails-dependent tests
    # RSpec should automatically restore stub_const/hide_const, but we ensure Rails is available
    if defined?(Rails)
      # Rails is defined - check if it was stubbed (doesn't respond to :application)
      # Real Rails module responds to :application, stubbed versions typically don't
      begin
        if Rails.is_a?(Module) && !Rails.respond_to?(:application, true)
          # Rails was likely stubbed and not restored by RSpec
          # Try to restore it by reloading rails_helper
          # Note: We can't use remove_const here as it's flagged by RuboCop
          # Instead, we rely on RSpec's stub_const to restore automatically
          # If Rails is still stubbed, the next test that requires rails_helper will restore it
          begin
            # Reload rails_helper to restore Rails (this will redefine Rails if it was stubbed)
            require_relative "rails_helper" if File.exist?(File.join(__dir__, "rails_helper.rb"))
          rescue LoadError, NameError
            # rails_helper might not be available or might fail to load
            # This is OK - some tests don't need Rails
          end
        end
      rescue
        # If we can't check Rails state, continue - some tests don't need it
      end
    else
      # Rails was hidden or not defined - try to restore it by loading rails_helper
      # This ensures Rails-dependent tests have Rails available
      begin
        require_relative "rails_helper" if File.exist?(File.join(__dir__, "rails_helper.rb"))
      rescue LoadError, NameError
        # rails_helper might not be available or might fail to load
        # This is OK - some tests don't need Rails
      end
    end

    # Ensure Rails application is properly initialized for Rails-dependent tests
    # This helps with test isolation by ensuring consistent Rails state
    if defined?(Rails) && Rails.respond_to?(:application) && Rails.application
      # Ensure routes are finalized if Rails is available
      # This prevents issues where routes aren't loaded when tests run in certain orders
      begin
        if Rails.application.respond_to?(:routes) && Rails.application.routes.respond_to?(:finalize!)
          Rails.application.routes.finalize! unless Rails.application.routes.finalized?
        end
      rescue
        # Routes might already be finalized or in an invalid state, ignore
      end
    end

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
