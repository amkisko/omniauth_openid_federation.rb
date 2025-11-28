# Input validation utilities for omniauth_openid_federation
require_relative "constants"
require_relative "configuration"

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

    # Validate client options hash (for configuration validation only)
    # Note: This validates configuration structure, not security (config is trusted)
    #
    # @param client_options [Hash] The client options to validate
    # @raise [ConfigurationError] If required options are missing
    def self.validate_client_options!(client_options)
      client_options ||= {}

      # Normalize hash keys to symbols
      normalized = normalize_hash(client_options)

      # Validate required fields (structure validation, not security)
      if StringHelpers.blank?(normalized[:identifier])
        raise ConfigurationError, "Client identifier is required"
      end

      if StringHelpers.blank?(normalized[:redirect_uri])
        raise ConfigurationError, "Redirect URI is required"
      end

      # Basic format check for redirect URI (config validation, not security)
      # Note: Config values are trusted, we only check format to catch config errors
      begin
        parsed = URI.parse(normalized[:redirect_uri].to_s)
        unless parsed.is_a?(URI::HTTP) || parsed.is_a?(URI::HTTPS)
          raise ConfigurationError, "Redirect URI must be HTTP or HTTPS: #{normalized[:redirect_uri]}"
        end
      rescue URI::InvalidURIError => e
        raise ConfigurationError, "Invalid redirect URI format: #{e.message}"
      end

      # Validate private key (required for security)
      validate_private_key!(normalized[:private_key])

      # Basic format check for endpoints (config validation, not security)
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

    # Validate and sanitize user input from HTTP requests only (not config values)
    # Prevents URI exploitation, ReDoS, string overflow, and control character attacks
    # Default max_length uses Configuration.config.max_string_length (8KB default) - large enough for legitimate use, prevents DoS attacks
    def self.sanitize_request_param(value, max_length: nil, allow_control_chars: false)
      max_length ||= ::OmniauthOpenidFederation::Configuration.config.max_string_length
      return nil if value.nil?

      str = value.to_s.strip
      return nil if str.length > max_length

      # Only allow printable ASCII (whitelist approach)
      unless allow_control_chars
        str = str.gsub(/[^\x20-\x7E]/, "")
      end

      str.empty? ? nil : str
    end

    # Validate URI for user input only (not config values)
    # Prevents URI gem exploitation and validates scheme/length
    def self.validate_uri_safe!(uri_str, max_length: nil, allowed_schemes: ["http", "https"])
      max_length ||= ::OmniauthOpenidFederation::Configuration.config.max_string_length
      raise SecurityError, "URI cannot be nil" if uri_str.nil?

      str = uri_str.to_s.strip
      raise SecurityError, "URI cannot be empty" if str.empty?
      raise SecurityError, "URI exceeds maximum length of #{max_length} characters" if str.length > max_length

      sanitized = str.gsub(/[^\x20-\x7E]/, "")
      raise SecurityError, "URI contains invalid characters (only printable ASCII allowed)" if sanitized != str

      begin
        parsed = URI.parse(sanitized)
      rescue URI::InvalidURIError => e
        raise SecurityError, "Invalid URI format: #{e.message}"
      end

      unless parsed.scheme && allowed_schemes.include?(parsed.scheme.downcase)
        raise SecurityError, "URI scheme must be one of: #{allowed_schemes.join(", ")}"
      end

      unless parsed.is_a?(URI::HTTP) || parsed.is_a?(URI::HTTPS)
        raise SecurityError, "URI must be HTTP or HTTPS"
      end

      raise SecurityError, "URI host cannot be empty" if parsed.host.nil? || parsed.host.empty?

      parsed
    end

    # Validate and normalize acr_values parameter per OIDC Core 1.0 spec
    # acr_values is a space-separated string of ACR values
    # Security: Uses allowed characters approach - only allows printable ASCII characters
    #
    # @param acr_values [String, Array, nil] ACR values in any format
    # @param max_length [Integer] Maximum total length (default: Configuration.config.max_string_length)
    # @param skip_sanitization [Boolean] Skip sanitization if values are already sanitized (default: false)
    # @return [String, nil] Normalized space-separated string or nil
    def self.normalize_acr_values(acr_values, max_length: nil, skip_sanitization: false)
      max_length ||= ::OmniauthOpenidFederation::Configuration.config.max_string_length
      return nil if StringHelpers.blank?(acr_values)

      case acr_values
      when Array
        # Filter out blanks (arrays may already be sanitized)
        values = acr_values.map(&:to_s).map(&:strip).reject { |v| StringHelpers.blank?(v) }
      when String
        # Trim and split by whitespace and validate each value using allowed characters
        # Security: Use simple space split (no regexp to avoid ReDoS)
        trimmed = acr_values.strip
        values = trimmed.split(" ").map(&:strip).reject { |v| StringHelpers.blank?(v) }
      else
        # Convert to string, trim and split
        str = acr_values.to_s.strip
        return nil if str.length > max_length
        # Security: Use simple space split (no regexp to avoid ReDoS)
        values = str.split(" ").map(&:strip).reject { |v| StringHelpers.blank?(v) }
      end

      # Sanitize each value unless already sanitized
      unless skip_sanitization
        values = values.map { |v| sanitize_request_param(v) }.compact
      end

      return nil if values.empty?

      result = values.join(" ")
      return nil if result.length > max_length

      result
    end

    # Validate and sanitize client_id per OIDC Core 1.0 spec
    # client_id is REQUIRED and must be a valid string
    #
    # @param client_id [String, nil] Client identifier
    # @return [String] Sanitized client_id
    # @raise [ConfigurationError] If client_id is invalid
    def self.validate_client_id!(client_id)
      if StringHelpers.blank?(client_id)
        raise ConfigurationError, "client_id is REQUIRED per OIDC Core 1.0 spec"
      end

      str = client_id.to_s.strip
      if str.empty?
        raise ConfigurationError, "client_id cannot be empty after trimming"
      end

      # Sanitize using allowed characters (printable ASCII only)
      sanitized = sanitize_request_param(str)
      if sanitized.nil? || sanitized.empty?
        raise ConfigurationError, "client_id contains invalid characters"
      end

      sanitized
    end

    # Validate and sanitize redirect_uri per OIDC Core 1.0 spec
    # redirect_uri is REQUIRED and must be a valid absolute URI
    #
    # @param redirect_uri [String, nil] Redirect URI
    # @return [String] Validated redirect_uri
    # @raise [ConfigurationError] If redirect_uri is invalid
    def self.validate_redirect_uri!(redirect_uri)
      if StringHelpers.blank?(redirect_uri)
        raise ConfigurationError, "redirect_uri is REQUIRED per OIDC Core 1.0 spec"
      end

      str = redirect_uri.to_s.strip
      if str.empty?
        raise ConfigurationError, "redirect_uri cannot be empty after trimming"
      end

      # Validate as URI (includes allowed characters validation)
      validated = validate_uri_safe!(str, allowed_schemes: ["http", "https"])
      validated.to_s
    end

    # Validate and sanitize scope per OIDC Core 1.0 spec
    # scope is space-delimited, case-sensitive list of ASCII string values
    # MUST include "openid" scope value
    #
    # @param scope [String, Array, nil] Scope value(s)
    # @param require_openid [Boolean] Whether to require "openid" scope (default: true)
    # @return [String] Normalized space-separated scope string
    # @raise [ConfigurationError] If scope is invalid
    def self.validate_scope!(scope, require_openid: true)
      if StringHelpers.blank?(scope)
        if require_openid
          raise ConfigurationError, "scope is REQUIRED and MUST include 'openid' per OIDC Core 1.0 spec"
        end
        return nil
      end

      # Normalize to array
      scopes = case scope
      when Array
        scope.map(&:to_s).map(&:strip).reject { |s| StringHelpers.blank?(s) }
      when String
        scope.strip.split(" ").map(&:strip).reject { |s| StringHelpers.blank?(s) }
      else
        scope.to_s.strip.split(" ").map(&:strip).reject { |s| StringHelpers.blank?(s) }
      end

      # Validate each scope value (allowed: printable ASCII)
      scopes = scopes.map { |s| sanitize_request_param(s) }.compact

      if scopes.empty?
        raise ConfigurationError, "scope cannot be empty after validation"
      end

      # Check for "openid" scope if required
      if require_openid && !scopes.include?("openid")
        raise ConfigurationError, "scope MUST include 'openid' per OIDC Core 1.0 spec"
      end

      result = scopes.join(" ")
      max_length = ::OmniauthOpenidFederation::Configuration.config.max_string_length
      if result.length > max_length
        raise ConfigurationError, "scope exceeds maximum length of #{max_length} characters"
      end

      result
    end

    # Validate and sanitize state parameter
    # state is REQUIRED for CSRF protection
    #
    # @param state [String, nil] State value
    # @return [String] Sanitized state value
    # @raise [ConfigurationError] If state is invalid
    def self.validate_state!(state)
      if StringHelpers.blank?(state)
        raise ConfigurationError, "state is REQUIRED for CSRF protection"
      end

      str = state.to_s.strip
      if str.empty?
        raise ConfigurationError, "state cannot be empty after trimming"
      end

      # Sanitize using allowed characters (printable ASCII only)
      sanitized = sanitize_request_param(str)
      if sanitized.nil? || sanitized.empty?
        raise ConfigurationError, "state contains invalid characters"
      end

      sanitized
    end

    # Validate and sanitize nonce parameter
    # nonce is REQUIRED for Implicit and Hybrid flows, RECOMMENDED for Authorization Code flow
    #
    # @param nonce [String, nil] Nonce value
    # @param required [Boolean] Whether nonce is required (default: false)
    # @return [String, nil] Sanitized nonce value or nil
    # @raise [ConfigurationError] If nonce is required but invalid
    def self.validate_nonce(nonce, required: false)
      return nil unless nonce

      str = nonce.to_s.strip
      if str.empty?
        if required
          raise ConfigurationError, "nonce is REQUIRED but is empty after trimming"
        end
        return nil
      end

      # Sanitize using allowed characters (printable ASCII only)
      # OIDC Core 1.0: nonce value is a case-sensitive string
      sanitized = sanitize_request_param(str)
      if sanitized.nil? || sanitized.empty?
        if required
          raise ConfigurationError, "nonce contains invalid characters"
        end
        return nil
      end

      sanitized
    end

    # Validate and sanitize response_type per OIDC Core 1.0 spec
    # response_type is REQUIRED and must be a valid value
    #
    # @param response_type [String, nil] Response type
    # @return [String] Validated response_type
    # @raise [ConfigurationError] If response_type is invalid
    def self.validate_response_type!(response_type)
      if StringHelpers.blank?(response_type)
        raise ConfigurationError, "response_type is REQUIRED per OIDC Core 1.0 spec"
      end

      str = response_type.to_s.strip
      if str.empty?
        raise ConfigurationError, "response_type cannot be empty after trimming"
      end

      # Sanitize using allowed characters (printable ASCII only)
      sanitized = sanitize_request_param(str)
      if sanitized.nil? || sanitized.empty?
        raise ConfigurationError, "response_type contains invalid characters"
      end

      # Validate it's a known response type (space-separated list)
      valid_types = ["code", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"]
      types = sanitized.split(" ").map(&:strip)
      unless types.all? { |t| valid_types.include?(t) || t.match?(/^[a-z_]+$/) }
        raise ConfigurationError, "response_type contains invalid value: #{sanitized}"
      end

      sanitized
    end

    # Validate entity identifier per OpenID Federation 1.0 spec
    # Entity identifiers are URIs that identify entities in the federation
    #
    # @param entity_id [String, nil] Entity identifier
    # @param max_length [Integer] Maximum length (default: Configuration.config.max_string_length)
    # @return [String] Validated and trimmed entity identifier
    # @raise [SecurityError] If entity identifier is invalid
    def self.validate_entity_identifier!(entity_id, max_length: nil)
      max_length ||= ::OmniauthOpenidFederation::Configuration.config.max_string_length
      if StringHelpers.blank?(entity_id)
        raise SecurityError, "Entity identifier cannot be nil or empty"
      end

      str = entity_id.to_s.strip
      if str.empty?
        raise SecurityError, "Entity identifier cannot be empty after trimming"
      end

      # Validate as URI (includes allowed characters and length validation)
      validate_uri_safe!(str, max_length: max_length, allowed_schemes: ["http", "https"])

      # Return trimmed and validated value
      str
    end
  end
end
