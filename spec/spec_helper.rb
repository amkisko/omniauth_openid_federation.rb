require "logger"

# Default: quiet SQL/schema/migration/Rails chatter, OmniAuth, and gem [OpenIDFederation] logs.
# Set SPEC_VERBOSE=1 to restore loggers and schema output.
module SpecTestLogging
  NULL = Logger.new(File::NULL)

  def self.enabled?
    !%w[1 true yes].include?(ENV["SPEC_VERBOSE"]&.to_s&.downcase)
  end

  # Per-example so specs that reset OmniauthOpenidFederation::Logger (e.g. logger_spec) cannot
  # leave the next example on OmniAuth/Rails loggers. Also silences OmniAuth's own strategy logs.
  def self.silence_loggers_for_example!
    return unless enabled?

    if defined?(OmniauthOpenidFederation::Logger)
      OmniauthOpenidFederation::Logger.logger = OmniauthOpenidFederation::Logger::NullLogger.new
    end
    if defined?(OmniAuth) && OmniAuth.config.respond_to?(:logger=)
      OmniAuth.config.logger = NULL
    end
  end

  def self.silence!
    return unless enabled?

    if defined?(ActiveRecord::Base)
      ActiveRecord::Base.logger = NULL
      ActiveRecord.verbose_query_logs = false if ActiveRecord.respond_to?(:verbose_query_logs=)
    end
    if defined?(ActiveRecord::Migration) && ActiveRecord::Migration.respond_to?(:verbose=)
      ActiveRecord::Migration.verbose = false
    end
    if defined?(ActiveRecord::Schema) && ActiveRecord::Schema.respond_to?(:verbose=)
      ActiveRecord::Schema.verbose = false
    end
    if defined?(ActiveRecord::LogSubscriber)
      ActiveRecord::LogSubscriber.logger = NULL
    end
    if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
      Rails.logger.level = Logger::WARN
    end
  end
end

unless %w[1 true yes].include?(ENV["POLYRUN_COVERAGE_DISABLE"]&.downcase)
  require "polyrun"
  root = File.expand_path("..", __dir__)
  Polyrun::Coverage::Collector.start!(
    root: root,
    track_files: "{lib,app}/**/*.rb",
    reject_patterns: [
      "/lib/tasks/",
      "/lib/omniauth_openid_federation/version.rb",
      "/spec/"
    ],
    formatter: Polyrun::Coverage::Formatter.multi(
      :json, :html, :cobertura, :console,
      output_dir: File.expand_path("../coverage", __dir__),
      basename: "coverage"
    ),
    meta: {"title" => "omniauth_openid_federation coverage"}
  )
end

require "rspec"
require "active_support"
require "active_support/core_ext/hash/keys"
require "active_support/core_ext/object/blank"
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
  config.before(:suite) { SpecTestLogging.silence! }
  config.before(:each) { SpecTestLogging.silence_loggers_for_example! }

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
require "polyrun/rspec"
Polyrun::RSpec.install_failure_fragments!

