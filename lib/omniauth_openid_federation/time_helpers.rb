# Time helper utilities for compatibility with ActiveSupport
# Provides time methods that work with or without Time.zone
module OmniauthOpenidFederation
  module TimeHelpers
    # Get current time, using Time.zone if available, otherwise Time
    #
    # @return [Time] Current time
    def self.now
      if time_zone_available?
        Time.zone.now
      else
        # rubocop:disable Rails/TimeZone
        Time.now
        # rubocop:enable Rails/TimeZone
      end
    end

    # Convert a timestamp to Time, using Time.zone if available, otherwise Time
    #
    # @param timestamp [Integer, Float] Unix timestamp
    # @return [Time] Time object representing the timestamp
    def self.at(timestamp)
      if time_zone_available?
        Time.zone.at(timestamp)
      else
        # rubocop:disable Rails/TimeZone
        Time.at(timestamp)
        # rubocop:enable Rails/TimeZone
      end
    end

    # Parse a time string, using Time.zone if available, otherwise Time
    #
    # @param time_string [String] Time string to parse
    # @return [Time] Parsed time object
    def self.parse(time_string)
      if time_zone_available?
        Time.zone.parse(time_string)
      else
        # rubocop:disable Rails/TimeZone
        Time.parse(time_string)
        # rubocop:enable Rails/TimeZone
      end
    end

    # Check if Time.zone is available and configured
    #
    # @return [Boolean] true if Time.zone is available and not nil
    def self.time_zone_available?
      return false unless defined?(ActiveSupport)
      return false unless Time.respond_to?(:zone)

      begin
        !Time.zone.nil?
      rescue
        false
      end
    end
  end
end
