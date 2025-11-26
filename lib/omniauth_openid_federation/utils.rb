# Utility functions for omniauth_openid_federation
module OmniauthOpenidFederation
  module Utils
    # Convert hash to HashWithIndifferentAccess if available
    #
    # @param hash [Hash, Object] The hash to convert
    # @return [Hash, HashWithIndifferentAccess] Converted hash
    def self.to_indifferent_hash(hash)
      if defined?(ActiveSupport::HashWithIndifferentAccess)
        ActiveSupport::HashWithIndifferentAccess.new(hash)
      else
        hash.is_a?(Hash) ? hash : hash.to_h
      end
    end

    # Sanitize file path for error messages (only show filename, not full path)
    #
    # @param path [String, nil] The file path
    # @return [String] Sanitized path (filename only)
    def self.sanitize_path(path)
      return "[REDACTED]" if path.nil? || path.empty?
      File.basename(path)
    end

    # Sanitize URI for error messages (only show scheme and host)
    #
    # @param uri [String, nil] The URI
    # @return [String] Sanitized URI
    def self.sanitize_uri(uri)
      return "[REDACTED]" if uri.nil? || uri.empty?
      begin
        parsed = URI.parse(uri)
        "#{parsed.scheme}://#{parsed.host}/[REDACTED]"
      rescue URI::InvalidURIError
        "[REDACTED]"
      end
    end

    # Build full endpoint URL from issuer and endpoint path
    #
    # @param issuer_uri [String, URI] Issuer URI (e.g., "https://provider.example.com")
    # @param endpoint_path [String] Endpoint path (e.g., "/oauth2/authorize")
    # @return [String] Full endpoint URL
    def self.build_endpoint_url(issuer_uri, endpoint_path)
      return endpoint_path if endpoint_path.to_s.start_with?("http://", "https://")

      issuer_str = issuer_uri.to_s
      issuer_str = issuer_str.chomp("/")
      path = endpoint_path.to_s
      path = "/#{path}" unless path.start_with?("/")
      "#{issuer_str}#{path}"
    end

    # Build full entity statement URL from issuer and endpoint path
    #
    # @param issuer_uri [String, URI] Issuer URI (e.g., "https://provider.example.com")
    # @param entity_statement_endpoint [String, nil] Entity statement endpoint path (e.g., "/.well-known/openid-federation")
    # @return [String] Full entity statement URL
    def self.build_entity_statement_url(issuer_uri, entity_statement_endpoint: nil)
      endpoint = entity_statement_endpoint || "/.well-known/openid-federation"
      build_endpoint_url(issuer_uri, endpoint)
    end

    # Validate file path to prevent path traversal attacks
    #
    # @param path [String, Pathname] The file path to validate
    # @param allowed_dirs [Array<String>, nil] Allowed base directories (optional)
    # @return [String] Resolved absolute path
    # @raise [SecurityError] If path traversal is detected or path is outside allowed directories
    def self.validate_file_path!(path, allowed_dirs: nil)
      raise SecurityError, "File path cannot be nil" if path.nil?

      # Convert Pathname to string if needed
      path_str = path.to_s
      raise SecurityError, "File path cannot be empty" if path_str.empty?

      # Check for path traversal attempts
      if path_str.include?("..") || path_str.include?("~")
        raise SecurityError, "Path traversal detected in: #{sanitize_path(path_str)}"
      end

      # Resolve to absolute path
      resolved = File.expand_path(path_str)

      # Validate it's within allowed directories if specified
      # When allowed_dirs is nil, we trust the developer to pass appropriate paths
      # Path traversal protection (.. and ~) is still enforced above
      if allowed_dirs && !allowed_dirs.empty?
        allowed = allowed_dirs.any? do |dir|
          expanded_dir = File.expand_path(dir)
          resolved.start_with?(expanded_dir)
        end
        unless allowed
          raise SecurityError, "File path outside allowed directories: #{sanitize_path(path)}"
        end
      end

      resolved
    end

    # Validate JWT format (must have exactly 3 parts separated by dots)
    #
    # @param str [String] The string to validate
    # @return [Boolean] true if valid JWT format, false otherwise
    def self.valid_jwt_format?(str)
      return false unless str.is_a?(String)
      parts = str.split(".")
      parts.length == 3 && parts.all? { |p| p.length > 0 }
    end

    # Convert RSA key to JWK format
    #
    # @param key [OpenSSL::PKey::RSA] RSA private or public key
    # @param use [String, nil] Key use ("sig" for signing, "enc" for encryption, nil for both)
    # @return [Hash] JWK hash with kty, kid, n, e, and optionally use
    def self.rsa_key_to_jwk(key, use: "sig")
      require "digest"
      require "base64"

      n = Base64.urlsafe_encode64(key.n.to_s(2), padding: false)
      e = Base64.urlsafe_encode64(key.e.to_s(2), padding: false)

      # Generate kid (key ID) from public key
      public_key_pem = key.public_key.to_pem
      kid = Digest::SHA256.hexdigest(public_key_pem)[0, 16]

      jwk = {
        kty: "RSA",
        kid: kid,
        n: n,
        e: e
      }

      # Add use field if specified
      jwk[:use] = use if use

      jwk
    end

    # Extract JWKS from entity statement JWT
    #
    # @param entity_statement_content [String] Entity statement JWT string
    # @return [Hash, nil] JWKS hash with "keys" array, or nil if extraction fails
    def self.extract_jwks_from_entity_statement(entity_statement_content)
      require "json"
      require "base64"

      return nil unless valid_jwt_format?(entity_statement_content)

      jwt_parts = entity_statement_content.split(".")
      return nil unless jwt_parts.length == 3

      begin
        payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
        entity_jwks = payload["jwks"] || payload[:jwks] || {}
        return nil if entity_jwks.empty?

        keys = entity_jwks["keys"] || entity_jwks[:keys] || []
        return nil if keys.empty?

        {keys: Array(keys)}
      rescue => e
        OmniauthOpenidFederation::Logger.warn("[Utils] Failed to extract JWKS from entity statement: #{e.message}")
        nil
      end
    end
  end
end
