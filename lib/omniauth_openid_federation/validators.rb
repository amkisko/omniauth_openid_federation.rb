# Input validation utilities for omniauth_openid_federation
module OmniauthOpenidFederation
  module Validators
    # Validate that a private key is present and valid
    #
    # @param private_key [OpenSSL::PKey::RSA, String, nil] The private key to validate
    # @raise [ConfigurationError] If private key is missing or invalid
    def self.validate_private_key!(private_key)
      if private_key.nil?
        raise ConfigurationError, "Private key is required for signed request objects"
      end

      # Try to parse if it's a string
      if private_key.is_a?(String)
        begin
          OpenSSL::PKey::RSA.new(private_key)
        rescue => e
          raise ConfigurationError, "Invalid private key format: #{e.message}"
        end
      elsif !private_key.is_a?(OpenSSL::PKey::RSA)
        raise ConfigurationError, "Private key must be an OpenSSL::PKey::RSA instance or PEM string"
      end

      true
    end

    # Validate that a URI is valid
    #
    # @param uri [String, URI, nil] The URI to validate
    # @param required [Boolean] Whether the URI is required
    # @raise [ConfigurationError] If URI is invalid or missing when required
    def self.validate_uri!(uri, required: false)
      if StringHelpers.blank?(uri)
        if required
          raise ConfigurationError, "URI is required"
        end
        return false
      end

      begin
        parsed = URI.parse(uri.to_s)
        unless parsed.is_a?(URI::HTTP) || parsed.is_a?(URI::HTTPS)
          raise ConfigurationError, "URI must be HTTP or HTTPS: #{uri}"
        end
        true
      rescue URI::InvalidURIError => e
        raise ConfigurationError, "Invalid URI format: #{e.message}"
      end
    end

    # Validate that a file path exists
    #
    # @param path [String, nil] The file path to validate
    # @param required [Boolean] Whether the file is required
    # @raise [ConfigurationError] If file is missing when required
    def self.validate_file_path!(path, required: false)
      if StringHelpers.blank?(path)
        if required
          raise ConfigurationError, "File path is required"
        end
        return false
      end

      unless File.exist?(path)
        if required
          raise ConfigurationError, "File not found: #{path}"
        end
        return false
      end

      true
    end

    # Validate client options hash
    #
    # @param client_options [Hash] The client options to validate
    # @raise [ConfigurationError] If required options are missing
    def self.validate_client_options!(client_options)
      client_options ||= {}

      # Normalize hash keys to symbols
      normalized = normalize_hash(client_options)

      # Validate required fields
      if StringHelpers.blank?(normalized[:identifier])
        raise ConfigurationError, "Client identifier is required"
      end

      if StringHelpers.blank?(normalized[:redirect_uri])
        raise ConfigurationError, "Redirect URI is required"
      end

      # Validate redirect URI format
      validate_uri!(normalized[:redirect_uri], required: true)

      # Validate private key
      validate_private_key!(normalized[:private_key])

      # Validate endpoints if provided
      %i[authorization_endpoint token_endpoint jwks_uri].each do |endpoint|
        if normalized.key?(endpoint) && !StringHelpers.blank?(normalized[endpoint])
          # Endpoints can be paths or full URLs
          endpoint_value = normalized[endpoint]
          unless endpoint_value.to_s.start_with?("/", "http://", "https://")
            raise ConfigurationError, "Invalid endpoint format for #{endpoint}: #{endpoint_value}"
          end
        end
      end

      normalized
    end

    # Normalize hash keys to symbols
    #
    # @param hash [Hash] The hash to normalize
    # @return [Hash] Hash with symbol keys
    def self.normalize_hash(hash)
      return {} if hash.nil?

      hash.each_with_object({}) do |(k, v), result|
        key = k.is_a?(String) ? k.to_sym : k
        result[key] = v
      end
    end
  end
end
