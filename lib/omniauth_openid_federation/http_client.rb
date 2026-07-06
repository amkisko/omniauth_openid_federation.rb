require "http"
require "openssl"
require_relative "constants"

# HTTP client with retry logic and SSL configuration
module OmniauthOpenidFederation
  class HttpClient
    RETRYABLE_ERRORS = [
      HTTP::Error,
      Timeout::Error,
      Errno::ECONNREFUSED,
      Errno::ETIMEDOUT
    ].freeze

    # Execute an HTTP GET request with retry logic
    #
    # @param uri [String, URI] The URI to fetch
    # @param options [Hash] Request options
    # @option options [Integer] :max_retries Maximum number of retries (default: from config)
    # @option options [Integer] :retry_delay Base retry delay in seconds (default: from config)
    # @option options [Integer] :timeout Request timeout in seconds (default: from config)
    # @option options [Integer] :connect_timeout Connect timeout in seconds
    # @option options [Integer] :read_timeout Read timeout in seconds
    # @option options [Hash] :headers Request headers
    # @return [HTTP::Response] The HTTP response
    # @raise [NetworkError] If the request fails after all retries
    def self.get(uri, options = {})
      request(:get, uri, options)
    end

    # Execute an HTTP POST request with retry logic
    #
    # @param uri [String, URI] The URI to post to
    # @param options [Hash] Request options (same as get, plus :form)
    # @option options [Hash] :form Form parameters
    # @return [HTTP::Response] The HTTP response
    # @raise [NetworkError] If the request fails after all retries
    def self.post(uri, options = {})
      request(:post, uri, options)
    end

    def self.request(method, uri, options = {})
      max_retries = max_retries_for(options)
      retry_delay = options[:retry_delay] || Configuration.config.retry_delay
      http_client = build_http_client(resolve_timeout(options))
      headers = options[:headers] || {}
      form = options[:form]

      retries = 0
      begin
        client = http_client
        client = client.headers(headers) unless headers.empty?

        case method
        when :get
          client.get(uri)
        when :post
          client.post(uri, form: form || {})
        else
          raise ArgumentError, "Unsupported HTTP method: #{method}"
        end
      rescue *RETRYABLE_ERRORS => error
        retries += 1
        if retries > max_retries
          error_message = "Failed to #{method.to_s.upcase} #{uri} after #{max_retries} retries: #{error.class} - #{error.message}"
          OmniauthOpenidFederation::Logger.error("[HttpClient] #{error_message}")
          raise OmniauthOpenidFederation::NetworkError, error_message, error.backtrace
        end

        delay = [retry_delay * retries, Constants::MAX_RETRY_DELAY_SECONDS].min
        OmniauthOpenidFederation::Logger.warn(
          "[HttpClient] Request failed (attempt #{retries}/#{max_retries}), retrying in #{delay}s: #{error.message}"
        )
        sleep(delay)
        retry
      end
    end

    def self.build_http_client(timeout_config)
      http_options = HTTP::Options.new(build_http_options_hash)
      HTTP::Client.new(http_options).timeout(timeout_config)
    end

    def self.build_http_options_hash
      config = Configuration.config
      user_options = if config.http_options
        if config.http_options.is_a?(Proc)
          config.http_options.call
        else
          config.http_options
        end
      end

      options = (user_options || {}).dup
      options[:ssl] = (options[:ssl] || {}).dup
      options[:ssl][:verify_mode] ||= ssl_verify_mode(config.verify_ssl)
      options
    end

    def self.ssl_verify_mode(verify_ssl)
      verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    end

    def self.max_retries_for(options)
      return options[:max_retries] if options.key?(:max_retries)

      Configuration.config.max_retries
    end

    def self.resolve_timeout(options)
      default_timeout = Configuration.config.http_timeout

      if options[:connect_timeout] || options[:read_timeout]
        {
          connect: options[:connect_timeout] || default_timeout,
          read: options[:read_timeout] || default_timeout
        }
      else
        options[:timeout] || default_timeout
      end
    end

    private_class_method :request, :build_http_client, :build_http_options_hash, :ssl_verify_mode,
      :max_retries_for, :resolve_timeout
  end
end
