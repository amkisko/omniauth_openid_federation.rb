# String helper utilities for compatibility with ActiveSupport
# Provides present? and blank? methods without monkey patching core classes
module OmniauthOpenidFederation
  module StringHelpers
    # Check if a value is present (not nil, not empty string, not blank)
    #
    # @param value [Object] The value to check
    # @return [Boolean] true if value is present, false otherwise
    def self.present?(value)
      case value
      when String
        !value.empty? && !value.strip.empty?
      when NilClass
        false
      when Array, Hash
        !value.empty?
      else
        !value.nil?
      end
    end

    # Check if a value is blank (nil, empty string, or whitespace-only string)
    #
    # @param value [Object] The value to check
    # @return [Boolean] true if value is blank, false otherwise
    def self.blank?(value)
      !present?(value)
    end
  end
end
