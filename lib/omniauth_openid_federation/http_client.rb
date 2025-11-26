require_relative "constants"

# HTTP client with retry logic and SSL configuration
module OmniauthOpenidFederation
  class HttpClient
    # Execute an HTTP GET request with retry logic
    #
    # @param uri [String, URI] The URI to fetch
    # @param options [Hash] Request options
    # @option options [Integer] :max_retries Maximum number of retries (default: from config)
    # @option options [Integer] :retry_delay Base retry delay in seconds (default: from config)
    # @option options [Integer] :timeout Request timeout in seconds (default: from config)
    # @return [HTTP::Response] The HTTP response
    # @raise [NetworkError] If the request fails after all retries
    def self.get(uri, options = {})
      max_retries = options[:max_retries] || Configuration.config.max_retries
      retry_delay = options[:retry_delay] || Configuration.config.retry_delay
      timeout = options[:timeout] || Configuration.config.http_timeout

      http_client = build_http_client(timeout)

      retries = 0
      begin
        http_client.get(uri)
      rescue HTTP::Error, Timeout::Error, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
        retries += 1
        if retries > max_retries
          error_msg = "Failed to fetch #{uri} after #{max_retries} retries: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[HttpClient] #{error_msg}")
          raise OmniauthOpenidFederation::NetworkError, error_msg, e.backtrace
        end

        delay = [retry_delay * retries, Constants::MAX_RETRY_DELAY_SECONDS].min
        OmniauthOpenidFederation::Logger.warn("[HttpClient] Request failed (attempt #{retries}/#{max_retries}), retrying in #{delay}s: #{e.message}")
        sleep(delay)
        retry
      end
    end

    # Build HTTP client with SSL configuration
    #
    # @param timeout [Integer] Request timeout in seconds
    # @return [HTTP::Client] Configured HTTP client
    def self.build_http_client(timeout)
      http_options_hash = build_http_options_hash || {}
      http_options = HTTP::Options.new(http_options_hash)
      HTTP::Client.new(http_options).timeout(timeout)
    end

    # Build HTTP options hash from configuration
    #
    # @return [Hash, nil] HTTP options hash or nil
    def self.build_http_options_hash
      config = Configuration.config

      # If http_options is configured, use it (can be Hash or Proc)
      if config.http_options
        if config.http_options.is_a?(Proc)
          config.http_options.call
        else
          config.http_options
        end
      end
    end

    private_class_method :build_http_options_hash

    private_class_method :build_http_client
  end
end
