# frozen_string_literal: true

module OmniauthOpenidFederation
  class << self
    attr_writer :base_controller

    # Host controller class or name for FederationController.
    # Set before the controller loads (for example in an initializer before routes).
    #
    # @return [Class, String]
    def base_controller
      @base_controller || default_base_controller
    end

    # @return [Class]
    def base_controller_class
      value = base_controller
      return value if value.is_a?(Class)

      value.to_s.constantize
    end

    def default_base_controller
      return "ApplicationController" if defined?(::ApplicationController)
      return "ActionController::API" if defined?(::ActionController::API)

      "ActionController::Base"
    end

    def reset_base_controller!
      @base_controller = nil
    end
  end
end
