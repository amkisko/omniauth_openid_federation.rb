# Logger abstraction for omniauth_openid_federation
# Provides a configurable logging interface that works with or without Rails
#
# Logger Priority (automatic detection):
# 1. OmniAuth.config.logger (if configured)
# 2. Rails.logger (if Rails is available)
# 3. Standard Logger (if available)
# 4. NullLogger (silent fallback)
#
# Developers can configure logging once via OmniAuth.config.logger and this library
# will automatically use it, eliminating the need for separate configuration.
#
# Logging Level Guidelines:
# - debug: Detailed flow information, verbose debugging (development only)
# - info: Important state changes, successful operations, key rotations
# - warn: Recoverable errors, fallbacks, deprecation warnings, rate limiting
# - error: Unrecoverable errors, security issues, validation failures
module OmniauthOpenidFederation
  class Logger
    class << self
      attr_writer :logger

      # Get the configured logger instance
      #
      # @return [Logger, #debug, #info, #warn, #error] The logger instance
      def logger
        @logger ||= default_logger
      end

      # Log a debug message
      # Use for: Detailed flow information, verbose debugging (development only)
      #
      # @param message [String] The message to log
      def debug(message)
        logger.debug("[OpenIDFederation] #{message}")
      end

      # Log an info message
      # Use for: Important state changes, successful operations, key rotations
      #
      # @param message [String] The message to log
      def info(message)
        logger.info("[OpenIDFederation] #{message}")
      end

      # Log a warning message
      # Use for: Recoverable errors, fallbacks, deprecation warnings, rate limiting
      #
      # @param message [String] The message to log
      def warn(message)
        logger.warn("[OpenIDFederation] #{message}")
      end

      # Log an error message
      # Use for: Unrecoverable errors, security issues, validation failures
      #
      # @param message [String] The message to log
      def error(message)
        logger.error("[OpenIDFederation] #{message}")
      end

      private

      # Get the default logger based on available libraries
      # Priority: OmniAuth logger > Rails logger > standard Logger > NullLogger
      #
      # @return [Logger, NullLogger] The default logger instance
      def default_logger
        # Respect OmniAuth's configured logger if available
        # This allows developers to configure logging once via OmniAuth.config.logger
        if defined?(OmniAuth) && OmniAuth.config.respond_to?(:logger) && OmniAuth.config.logger
          OmniAuth.config.logger
        elsif defined?(Rails) && Rails.logger
          Rails.logger
        elsif defined?(::Logger)
          ::Logger.new($stdout)
        else
          NullLogger.new
        end
      end
    end

    # Null logger that discards all log messages
    # Used when no logger is available
    class NullLogger
      def debug(*)
      end

      def info(*)
      end

      def warn(*)
      end

      def error(*)
      end
    end
  end
end
