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

    RETRYABLE_HTTP_STATUS_CODES = [429, 502, 503].freeze

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
    # POST defaults to max_retries: 0 because retries are not safe for non-idempotent requests.
    # Pass max_retries explicitly when duplicate POST attempts are acceptable.
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
      max_retries = max_retries_for(options, method)
      retry_delay = options[:retry_delay] || Configuration.config.retry_delay
      http_client = build_http_client(resolve_timeout(options))
      headers = options[:headers] || {}
      form = options[:form]
      max_attempts = max_retries + 1

      retries = 0

      loop do
        response = perform_request(http_client, headers, method, uri, form)

        if should_retry_for_status?(method, response, retries, max_retries)
          retries = retry_after_status(response, retries, max_attempts, retry_delay)
          next
        end

        return response
      rescue *RETRYABLE_ERRORS => error
        retries = handle_network_error(method, uri, error, retries, max_retries, max_attempts, retry_delay)
      end
    end

    def self.perform_request(http_client, headers, method, uri, form)
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
    end

    def self.should_retry_for_status?(method, response, retries, max_retries)
      method == :get && retryable_http_status?(response.status.code) && retries < max_retries
    end

    def self.retry_after_status(response, retries, max_attempts, retry_delay)
      retries += 1
      delay = retry_delay_for(retries, retry_delay)
      OmniauthOpenidFederation::Logger.warn(
        "[HttpClient] HTTP #{response.status.code} on attempt #{retries}/#{max_attempts}, retrying in #{delay}s"
      )
      sleep(delay)
      retries
    end

    def self.handle_network_error(method, uri, error, retries, max_retries, max_attempts, retry_delay)
      retries += 1
      if retries > max_retries
        error_message = "Failed to #{method.to_s.upcase} #{uri} after #{max_attempts} attempts: #{error.class} - #{error.message}"
        OmniauthOpenidFederation::Logger.error("[HttpClient] #{error_message}")
        raise OmniauthOpenidFederation::NetworkError, error_message, error.backtrace
      end

      delay = retry_delay_for(retries, retry_delay)
      OmniauthOpenidFederation::Logger.warn(
        "[HttpClient] Request failed on attempt #{retries}/#{max_attempts}, retrying in #{delay}s: #{error.message}"
      )
      sleep(delay)
      retries
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
      if options[:ssl][:verify_mode] == OpenSSL::SSL::VERIFY_PEER && !options[:ssl][:ca_file]
        ca_file = ssl_ca_file
        options[:ssl][:ca_file] = ca_file if ca_file
      end
      options
    end

    def self.ssl_verify_mode(verify_ssl)
      verify_ssl ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    end

    def self.ssl_ca_file
      if ENV["SSL_CERT_FILE"] && File.file?(ENV["SSL_CERT_FILE"])
        ENV["SSL_CERT_FILE"]
      elsif File.exist?(OpenSSL::X509::DEFAULT_CERT_FILE)
        OpenSSL::X509::DEFAULT_CERT_FILE
      end
    end

    def self.max_retries_for(options, method)
      return options[:max_retries] if options.key?(:max_retries)

      (method == :post) ? 0 : Configuration.config.max_retries
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

    def self.retryable_http_status?(status_code)
      RETRYABLE_HTTP_STATUS_CODES.include?(status_code)
    end

    def self.retry_delay_for(retry_count, base_delay)
      [base_delay * retry_count, Constants::MAX_RETRY_DELAY_SECONDS].min
    end

    private_class_method :request, :perform_request, :should_retry_for_status?, :retry_after_status,
      :handle_network_error, :build_http_client, :build_http_options_hash, :ssl_verify_mode, :ssl_ca_file,
      :max_retries_for, :resolve_timeout, :retryable_http_status?, :retry_delay_for
  end
end
