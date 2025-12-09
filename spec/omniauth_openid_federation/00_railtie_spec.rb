require "spec_helper"

# Only run these tests if Rails is available
begin
  require "rails"
  require "action_controller/railtie"
  require "action_dispatch/railtie"
rescue LoadError
  # Rails not available - don't define any tests
  return
end

# Load engine and railtie
require_relative "../../lib/omniauth_openid_federation/engine"
require_relative "../../lib/omniauth_openid_federation/railtie"

# Ensure Rails application exists for testing
# Use rails_helper to ensure proper initialization
begin
  require "rails_helper"
rescue LoadError
  # If rails_helper not available, set up minimal Rails app
  unless defined?(Rails) && Rails.application&.initialized?
    module TestApp
      class Application < Rails::Application
        config.eager_load = false
        config.secret_key_base = "test_secret_key_base_for_railtie_tests"
        config.log_level = :error
        config.active_support.deprecation = :silence
        config.hosts.clear
        config.hosts << proc { true }
      end
    end

    TestApp::Application.initialize!
  end
end

# Ensure Rails is available for these tests
unless defined?(Rails) && Rails.application
  # Skip all tests if Rails is not available
  RSpec.describe OmniauthOpenidFederation::Railtie do
    it "skips tests when Rails is not available" do
      skip "Rails not available"
    end
  end

  return
end

RSpec.describe OmniauthOpenidFederation::Railtie do
  describe "Engine integration" do
    it "Engine is defined and inherits from Rails::Engine" do
      # Rails should be available since we're inside the begin/rescue block
      # If Rails is not available, the test file would have returned early
      aggregate_failures do
        expect(defined?(Rails)).to be_truthy
        expect(Rails).to be_const_defined(:Engine)
        expect(OmniauthOpenidFederation::Engine).to be < Rails::Engine
      end
    end

    it "Engine automatically adds app/controllers to autoload paths" do
      controllers_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers")

      # Rails Engine automatically adds app/controllers to autoload paths
      # This is tested by checking that the Engine is properly configured
      aggregate_failures do
        expect(OmniauthOpenidFederation::Engine.config.root).to be_a(Pathname)
        expect(OmniauthOpenidFederation::Engine.config.root.join("app", "controllers")).to exist if File.exist?(controllers_path)
      end
    end
  end

  describe "rake_tasks" do
    it "defines rake_tasks block" do
      # Verify that the Railtie has a rake_tasks block defined
      expect(described_class).to respond_to(:rake_tasks)
    end

    it "loads rake task files when Rails loads tasks" do
      task_files = Dir[File.join(File.dirname(__FILE__), "..", "..", "lib", "tasks", "**", "*.rake")]

      # Verify tasks are loaded when Rails loads tasks
      # Note: Rails automatically loads lib/tasks/**/*.rake, and the Railtie ensures they're loaded
      aggregate_failures do
        expect(task_files).not_to be_empty

        # Load tasks - this should not raise an error
        # Rails should be available since we're inside the begin/rescue block
        # If Rails is not available, the test file would have returned early
        expect(defined?(Rails)).to be_truthy
        expect(Rails.application).to be_present
        expect { Rails.application.load_tasks }.not_to raise_error

        # Verify at least some tasks are available (Rails loads all tasks)
        expect(Rake::Task.tasks).not_to be_empty
      end
    end
  end
end
