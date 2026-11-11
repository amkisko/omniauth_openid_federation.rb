# frozen_string_literal: true

# Explicit Rails entrypoint for Gemfile `require: false` consumers.
#
#   # Gemfile
#   gem "omniauth_openid_federation", require: false
#
#   # config/application.rb or an early initializer
#   require "omniauth_openid_federation/rails"
#   OmniauthOpenidFederation.base_controller = "ActionController::API" # optional
#
# Prefer mounting OmniauthOpenidFederation::Engine, or use RackEndpoint alone for
# hosts that must stay outside Action Controller filters.
require "omniauth_openid_federation"

unless defined?(Rails)
  raise LoadError, "omniauth_openid_federation/rails requires Rails"
end

require_relative "controller"
require_relative "engine"
require_relative "railtie"

controller_path = File.expand_path("../../app/controllers/omniauth_openid_federation/federation_controller.rb", __dir__)
require controller_path if File.file?(controller_path)
