# Configuration for omniauth_openid_federation
# Provides centralized configuration management
module OmniauthOpenidFederation
  class Configuration
    # SSL verification setting
    # @return [Boolean] true to verify SSL certificates, false to skip verification
    attr_accessor :verify_ssl

    # Cache TTL for JWKS in seconds
    # @return [Integer, nil] Cache TTL in seconds, or nil for manual rotation (never expires)
    #   - nil: Cache forever, manual rotation only (default)
    #   - positive integer: Cache expires after this many seconds
    attr_accessor :cache_ttl

    # Rotate JWKS cache on key-related errors
    # @return [Boolean] true to automatically rotate cache on key-related errors, false to require manual rotation
    #   - false: Manual rotation only (default)
    #   - true: Automatically rotate cache when key-related errors occur (401, 403, 404, signature failures)
    attr_accessor :rotate_on_errors

    # HTTP request timeout in seconds
    # @return [Integer] Timeout in seconds
    attr_accessor :http_timeout

    # Maximum number of retries for HTTP requests
    # @return [Integer] Maximum retry count
    attr_accessor :max_retries

    # Retry delay in seconds (will be multiplied by retry attempt)
    # @return [Integer] Base retry delay in seconds
    attr_accessor :retry_delay

    # HTTP options for HTTP::Options.new
    # Can be a Hash or a Proc that returns a Hash
    # @return [Hash, Proc, nil] HTTP options hash or proc that returns hash
    # @example
    #   config.http_options = { ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE } }
    #   # Or with a proc for dynamic configuration:
    #   config.http_options = -> { { ssl: { verify_mode: OpenSSL::SSL::VERIFY_NONE } } }
    attr_accessor :http_options

    # Custom cache adapter (optional)
    # If not set, automatically detects Rails.cache or ActiveSupport::Cache
    # @return [Object, nil] Cache adapter instance or nil
    # @example
    #   class MyCacheAdapter
    #     def fetch(key, expires_in: nil, &block)
    #       # Your implementation
    #     end
    #   end
    #   config.cache_adapter = MyCacheAdapter.new
    attr_accessor :cache_adapter

    # Root path for file operations (optional)
    # Used for resolving relative file paths when Rails.root is not available
    # @return [String, nil] Root path or nil
    # @example
    #   config.root_path = "/path/to/app"
    attr_accessor :root_path

    # Clock skew tolerance in seconds for entity statement time validation
    # Per OpenID Federation 1.0 Section 3.2.1, time validation MUST allow for clock skew
    # @return [Integer] Clock skew tolerance in seconds (default: 60)
    # @example
    #   config.clock_skew_tolerance = 120  # Allow 2 minutes of clock skew
    attr_accessor :clock_skew_tolerance

    # Custom instrumentation callback for security events
    # Can be a Proc, object with #call or #notify method, or logger-like object
    # @return [Proc, Object, nil] Instrumentation callback or nil to disable
    # @example Configure with Sentry
    #   config.instrumentation = ->(event, data) do
    #     Sentry.capture_message("OpenID Federation: #{event}", level: :warning, extra: data)
    #   end
    # @example Configure with Honeybadger
    #   config.instrumentation = ->(event, data) do
    #     Honeybadger.notify("OpenID Federation: #{event}", context: data)
    #   end
    # @example Configure with custom logger
    #   config.instrumentation = ->(event, data) do
    #     Rails.logger.warn("[Security] #{event}: #{data.inspect}")
    #   end
    # @example Disable instrumentation
    #   config.instrumentation = nil
    attr_accessor :instrumentation

    def initialize
      @verify_ssl = true # Default to secure
      @cache_ttl = nil # Default: manual rotation (never expires)
      @rotate_on_errors = false # Default: manual rotation only
      @http_timeout = 10
      @max_retries = 3
      @retry_delay = 1
      @http_options = nil
      @cache_adapter = nil
      @root_path = nil
      @clock_skew_tolerance = 60 # Default: 60 seconds clock skew tolerance
      @instrumentation = nil # Default: no instrumentation
    end

    # Configure the gem
    #
    # @yield [config] Yields the configuration object
    # @example
    #   OmniauthOpenidFederation.configure do |config|
    #     config.verify_ssl = false # Only for development
    #     config.cache_ttl = 3600  # Cache expires after 1 hour
    #     config.rotate_on_errors = true  # Rotate on key-related errors
    #   end
    def self.configure
      yield(config) if block_given?
      config
    end

    # Get the global configuration instance (thread-safe)
    #
    # @return [Configuration] The configuration instance
    def self.config
      @config_mutex ||= Mutex.new
      @config_mutex.synchronize do
        @config ||= new
      end
    end

    # Reset configuration (useful for testing)
    #
    # @return [void]
    def self.reset!
      @config_mutex ||= Mutex.new
      @config_mutex.synchronize do
        @config = nil
      end
    end
  end
end
