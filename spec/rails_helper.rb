# frozen_string_literal: true

# This file sets up a minimal Rails application for controller testing
# Based on recommendations from tmp/integration_testing.md
# Key principles:
# 1. Don't stub routes file - let Engine load routes normally
# 2. Force Rails initialization - ensure consistent Rails.application
# 3. Mount engine routes once, after initialization
# 4. Ensure proper autoloading and middleware

require "spec_helper"

begin
  require "rails"
  require "action_controller/railtie"
  require "action_dispatch/railtie"

  ENV["RAILS_ENV"] ||= "test"

  # Define ApplicationController before loading controllers that inherit from it
  unless defined?(ApplicationController)
    class ApplicationController < ActionController::Base
    end
  end

  # Load Engine and controller
  require_relative "../lib/omniauth_openid_federation/engine"
  controller_path = File.expand_path("../app/controllers/omniauth_openid_federation/federation_controller.rb", __dir__)
  require controller_path if File.exist?(controller_path)

  # Always ensure TestApp is defined for Engine tests
  # This ensures routes and controllers are available
  unless defined?(TestApp)
    module TestApp
      class Application < Rails::Application
        config.eager_load = false
        config.secret_key_base = SecureRandom.hex(32) # Required for session middleware
        config.log_level = :error
        config.active_support.deprecation = :silence

        # Allow all hosts for testing
        config.hosts.clear
        config.hosts << proc { true }

        # Disable CSRF protection for testing
        config.action_controller.allow_forgery_protection = false

        # Enable detailed error pages in test (unmasks 500 errors)
        config.consider_all_requests_local = true
        config.action_dispatch.show_exceptions = false

        # Add gem's app/controllers to autoload paths so controllers can be found
        gem_root = File.expand_path("../", __dir__)
        controllers_path = File.join(gem_root, "app", "controllers")
        if File.directory?(controllers_path)
          config.autoload_paths << controllers_path
          config.eager_load_paths << controllers_path
        end

        # Ensure session middleware is available (required for federation)
        config.session_store :cookie_store, key: "_test_session"
      end
    end
  end

  # Initialize Rails app if not already initialized
  unless defined?(Rails) && Rails.application&.initialized?
    TestApp::Application.initialize!
    # Ensure routes are finalized after initialization
    Rails.application.routes.finalize! if Rails.application.routes.respond_to?(:finalize!)
  end
rescue LoadError => e
  # Rails or ActionController not available - skip Rails tests
  # This allows the file to be required even when Rails isn't available
  # Individual spec files will handle this gracefully
end
