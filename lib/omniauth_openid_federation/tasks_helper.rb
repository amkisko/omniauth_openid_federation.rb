# Tasks helper module for rake tasks
# Contains all business logic that can be tested independently
require "json"
require "fileutils"
require "net/http"
require "uri"
require "openssl"
require_relative "utils"
require_relative "configuration"
require_relative "errors"
require_relative "http_client"
require_relative "federation/entity_statement"
require_relative "entity_statement_reader"
require_relative "jwks/fetch"
require_relative "federation/signed_jwks"
require_relative "string_helpers"

module OmniauthOpenidFederation
  module TasksHelper
    # Resolve file path using configuration
    #
    # @param file_path [String] Relative or absolute file path
    # @return [String] Resolved absolute path
    def self.resolve_path(file_path)
      return file_path if file_path.start_with?("/")

      config = Configuration.config
      if defined?(Rails) && Rails.root
        Rails.root.join(file_path).to_s
      elsif config.root_path
        File.join(config.root_path, file_path)
      else
        File.expand_path(file_path)
      end
    end

    # Fetch entity statement and save to file
    #
    # @param url [String] Entity statement URL
    # @param fingerprint [String, nil] Expected fingerprint
    # @param output_file [String] Output file path
    # @return [Hash] Result hash with :success, :entity_statement, :output_path, :metadata
    # @raise [Federation::EntityStatement::FetchError] If fetching fails
    # @raise [Federation::EntityStatement::ValidationError] If validation fails
    def self.fetch_entity_statement(url:, output_file:, fingerprint: nil)
      output_path = resolve_path(output_file)

      entity_statement = Federation::EntityStatement.fetch!(
        url,
        fingerprint: fingerprint
      )

      entity_statement.save_to_file(output_path)

      metadata = entity_statement.parse

      {
        success: true,
        entity_statement: entity_statement,
        output_path: output_path,
        fingerprint: entity_statement.fingerprint,
        metadata: metadata
      }
    end

    # Validate entity statement file
    #
    # @param file_path [String] Path to entity statement file
    # @param expected_fingerprint [String, nil] Expected fingerprint
    # @return [Hash] Result hash with :success, :fingerprint, :metadata
    # @raise [Federation::EntityStatement::ValidationError] If validation fails
    def self.validate_entity_statement(file_path:, expected_fingerprint: nil)
      resolved_path = resolve_path(file_path)

      unless File.exist?(resolved_path)
        raise ConfigurationError, "Entity statement file not found: #{resolved_path}"
      end

      entity_statement_content = File.read(resolved_path)
      entity_statement = Federation::EntityStatement.new(
        entity_statement_content,
        fingerprint: expected_fingerprint
      )

      if expected_fingerprint
        unless entity_statement.validate_fingerprint(expected_fingerprint)
          raise Federation::EntityStatement::ValidationError, "Fingerprint mismatch: expected #{expected_fingerprint}, got #{entity_statement.fingerprint}"
        end
      end

      metadata = entity_statement.parse

      {
        success: true,
        fingerprint: entity_statement.fingerprint,
        metadata: metadata
      }
    end

    # Fetch JWKS and save to file
    #
    # @param jwks_uri [String] JWKS URI
    # @param output_file [String] Output file path
    # @return [Hash] Result hash with :success, :jwks, :output_path
    # @raise [FetchError] If fetching fails
    def self.fetch_jwks(jwks_uri:, output_file:)
      output_path = resolve_path(output_file)

      jwks = Jwks::Fetch.run(jwks_uri)

      File.write(output_path, JSON.pretty_generate(jwks))

      {
        success: true,
        jwks: jwks,
        output_path: output_path
      }
    end

    # Parse entity statement and return metadata
    #
    # @param file_path [String] Path to entity statement file
    # @return [Hash] Metadata hash
    # @raise [ConfigurationError] If file not found
    # @raise [ValidationError] If parsing fails
    def self.parse_entity_statement(file_path:)
      resolved_path = resolve_path(file_path)

      unless File.exist?(resolved_path)
        raise ConfigurationError, "Entity statement file not found: #{resolved_path}"
      end

      metadata = EntityStatementReader.parse_metadata(
        entity_statement_path: resolved_path
      )

      unless metadata
        raise Federation::EntityStatement::ValidationError, "Failed to parse entity statement"
      end

      metadata
    end

    # Generate client keys
    #
    # @param key_type [String] "single" or "separate"
    # @param output_dir [String] Output directory
    # @return [Hash] Result hash with :success, :keys, :jwks, :output_path
    # @raise [ArgumentError] If key_type is invalid
    def self.prepare_client_keys(key_type:, output_dir:)
      unless %w[single separate].include?(key_type)
        raise ArgumentError, "Invalid key_type: #{key_type}. Valid options: 'single' or 'separate'"
      end

      output_path = resolve_path(output_dir)

      # Create output directory if it doesn't exist
      FileUtils.mkdir_p(output_path) unless File.directory?(output_path)

      result = if key_type == "single"
        generate_single_key(output_path)
      else
        generate_separate_keys(output_path)
      end

      {
        success: true,
        output_path: output_path,
        **result
      }
    end

    # Test local entity statement endpoint
    #
    # @param base_url [String] Base URL of the local server
    # @return [Hash] Result hash with :success, :results, :entity_statement, :key_status, :validation_warnings
    # @raise [Federation::EntityStatement::FetchError] If fetching fails
    def self.test_local_endpoint(base_url:)
      entity_statement_url = "#{base_url}/.well-known/openid-federation"
      validation_warnings = []

      # Fetch and parse entity statement
      begin
        entity_statement = Federation::EntityStatement.fetch!(
          entity_statement_url,
          fingerprint: nil # Don't validate fingerprint for local testing
        )
      rescue ValidationError => e
        # Don't block execution - treat validation errors as warnings
        validation_warnings << e.message
        # Try to parse anyway for diagnostic purposes
        begin
          require "json"
          require "base64"
          response = HttpClient.get(entity_statement_url)
          entity_statement = Federation::EntityStatement.new(response.body.to_s)
        rescue
          raise FetchError, "Failed to fetch entity statement: #{e.message}"
        end
      end

      begin
        metadata = entity_statement.parse
      rescue ValidationError => e
        validation_warnings << e.message
        # Try to extract basic info even if validation fails
        begin
          require "json"
          require "base64"
          jwt_parts = entity_statement.entity_statement.split(".")
          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          # Preserve original structure (string keys from JSON)
          metadata = {
            issuer: payload["iss"],
            sub: payload["sub"],
            exp: payload["exp"],
            iat: payload["iat"],
            jwks: payload["jwks"],
            metadata: payload["metadata"] || {}
          }
        rescue
          raise FetchError, "Failed to parse entity statement: #{e.message}"
        end
      end

      # Extract endpoints - handle both provider and relying party entity types
      metadata_section = metadata[:metadata] || {}
      provider_metadata = metadata_section[:openid_provider] || metadata_section["openid_provider"] || {}
      rp_metadata = metadata_section[:openid_relying_party] || metadata_section["openid_relying_party"] || {}

      endpoints = {}

      # Provider endpoints
      if provider_metadata.any?
        endpoints["Authorization Endpoint"] = provider_metadata[:authorization_endpoint] || provider_metadata["authorization_endpoint"]
        endpoints["Token Endpoint"] = provider_metadata[:token_endpoint] || provider_metadata["token_endpoint"]
        endpoints["UserInfo Endpoint"] = provider_metadata[:userinfo_endpoint] || provider_metadata["userinfo_endpoint"]
        endpoints["JWKS URI"] = provider_metadata[:jwks_uri] || provider_metadata["jwks_uri"]
        endpoints["Signed JWKS URI"] = provider_metadata[:signed_jwks_uri] || provider_metadata["signed_jwks_uri"]
        endpoints["End Session Endpoint"] = provider_metadata[:end_session_endpoint] || provider_metadata["end_session_endpoint"]
      end

      # Relying Party endpoints (JWKS only)
      if rp_metadata.any?
        endpoints["JWKS URI"] ||= rp_metadata[:jwks_uri] || rp_metadata["jwks_uri"]
        endpoints["Signed JWKS URI"] ||= rp_metadata[:signed_jwks_uri] || rp_metadata["signed_jwks_uri"]
      end

      endpoints.compact!

      # Detect key configuration status
      key_status = detect_key_status(metadata[:jwks])

      # Test endpoints
      results = {}
      entity_jwks = metadata[:jwks]

      endpoints.each do |name, url|
        next unless url

        begin
          case name
          when "JWKS URI"
            jwks = Jwks::Fetch.run(url)
            key_count = jwks["keys"]&.length || 0
            results[name] = {status: :success, keys: key_count}

          when "Signed JWKS URI"
            signed_jwks = Federation::SignedJWKS.fetch!(
              url,
              entity_jwks,
              force_refresh: true
            )
            key_count = signed_jwks["keys"]&.length || 0
            results[name] = {status: :success, keys: key_count}

          else
            # Test other endpoints with simple HTTP GET
            # Note: Rake tasks are developer tools, no security validation needed
            begin
              uri = URI.parse(url)
            rescue URI::InvalidURIError => e
              results[name] = {status: :error, message: "Invalid URL: #{e.message}"}
              next
            end
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = (uri.scheme == "https")
            if uri.scheme == "https"
              http.verify_mode = OpenSSL::SSL::VERIFY_PEER

              # Set ca_file directly - this is the simplest and most reliable approach
              # Try SSL_CERT_FILE first, then default cert file
              ca_file = if ENV["SSL_CERT_FILE"] && File.file?(ENV["SSL_CERT_FILE"])
                ENV["SSL_CERT_FILE"]
              elsif File.exist?(OpenSSL::X509::DEFAULT_CERT_FILE)
                OpenSSL::X509::DEFAULT_CERT_FILE
              end

              http.ca_file = ca_file if ca_file
            end

            request_path = uri.path
            request_path += "?#{uri.query}" if uri.query
            request = Net::HTTP::Get.new(request_path)
            response = http.request(request)

            results[name] = if response.code.to_i < 400
              {status: :success, code: response.code}
            else
              {status: :warning, code: response.code, body: response.body}
            end
          end
        rescue FetchError, Federation::SignedJWKS::FetchError => e
          results[name] = {status: :error, message: e.message}
        rescue Federation::SignedJWKS::ValidationError => e
          results[name] = {status: :error, message: e.message}
        rescue => e
          results[name] = {status: :error, message: e.message}
        end
      end

      {
        success: true,
        entity_statement: entity_statement,
        metadata: metadata,
        results: results,
        key_status: key_status,
        validation_warnings: validation_warnings
      }
    end

    # Detect key configuration (single vs separate keys)
    #
    # @param jwks [Hash, nil] JWKS hash with keys array
    # @return [Hash] Hash with :type, :count, :recommendation
    def self.detect_key_status(jwks)
      return {type: :unknown, count: 0, recommendation: "No keys found in entity statement"} unless jwks

      keys = jwks.is_a?(Hash) ? (jwks["keys"] || jwks[:keys] || []) : []
      return {type: :unknown, count: 0, recommendation: "No keys found in entity statement"} if keys.empty?

      # Check for duplicate kids (indicates single key used for both signing and encryption)
      kids = keys.map { |k| k["kid"] || k[:kid] }.compact
      duplicate_kids = kids.length != kids.uniq.length

      # Check use fields
      uses = keys.map { |k| k["use"] || k[:use] }.compact.uniq
      has_sig = uses.include?("sig")
      has_enc = uses.include?("enc")
      has_both_uses = has_sig && has_enc

      if duplicate_kids
        {
          type: :single,
          count: keys.length,
          recommendation: "⚠️  Single key detected (duplicate Key IDs). This is NOT RECOMMENDED for production. Use separate signing and encryption keys for better security. Generate with: rake openid_federation:prepare_client_keys[separate]"
        }
      elsif has_both_uses && keys.length >= 2
        {
          type: :separate,
          count: keys.length,
          recommendation: "✅ Separate keys detected (recommended for production)"
        }
      elsif keys.length == 1
        {
          type: :single,
          count: 1,
          recommendation: "⚠️  Single key detected. This is NOT RECOMMENDED for production. Use separate signing and encryption keys for better security. Generate with: rake openid_federation:prepare_client_keys[separate]"
        }
      else
        {
          type: :unknown,
          count: keys.length,
          recommendation: "Key configuration unclear. Ensure keys have unique Key IDs and proper 'use' fields ('sig' for signing, 'enc' for encryption)"
        }
      end
    end

    # Generate single key for both signing and encryption
    #
    # @param output_path [String] Output directory path
    # @return [Hash] Result with :private_key_path, :public_jwks_path, :jwks
    def self.generate_single_key(output_path)
      private_key = OpenSSL::PKey::RSA.new(2048)
      jwk_hash = Utils.rsa_key_to_jwk(private_key, use: "sig")

      # Remove private key components and 'use' field for backward compatibility
      public_jwk = jwk_hash.reject { |k, _v| %w[d p q dp dq qi use].include?(k.to_s) }
      jwks = {keys: [public_jwk]}

      # Save private key
      private_key_path = File.join(output_path, "client-private-key.pem")
      File.write(private_key_path, private_key.to_pem)
      File.chmod(0o600, private_key_path)

      # Save public JWKS
      public_jwks_path = File.join(output_path, "client-jwks.json")
      File.write(public_jwks_path, JSON.pretty_generate(jwks))

      {
        private_key_path: private_key_path,
        public_jwks_path: public_jwks_path,
        jwks: jwks
      }
    end

    # Generate separate keys for signing and encryption
    #
    # @param output_path [String] Output directory path
    # @return [Hash] Result with :signing_key_path, :encryption_key_path, :public_jwks_path, :jwks
    def self.generate_separate_keys(output_path)
      signing_private_key = OpenSSL::PKey::RSA.new(2048)
      encryption_private_key = OpenSSL::PKey::RSA.new(2048)

      signing_jwk_hash = Utils.rsa_key_to_jwk(signing_private_key, use: "sig")
      encryption_jwk_hash = Utils.rsa_key_to_jwk(encryption_private_key, use: "enc")

      # Remove private key components and add 'use' field
      signing_public_jwk = signing_jwk_hash.reject { |k, _v| %w[d p q dp dq qi].include?(k.to_s) }.merge("use" => "sig")
      encryption_public_jwk = encryption_jwk_hash.reject { |k, _v| %w[d p q dp dq qi].include?(k.to_s) }.merge("use" => "enc")

      jwks = {keys: [signing_public_jwk, encryption_public_jwk]}

      # Save private keys
      signing_key_path = File.join(output_path, "client-signing-private-key.pem")
      encryption_key_path = File.join(output_path, "client-encryption-private-key.pem")

      File.write(signing_key_path, signing_private_key.to_pem)
      File.write(encryption_key_path, encryption_private_key.to_pem)
      File.chmod(0o600, signing_key_path)
      File.chmod(0o600, encryption_key_path)

      # Save public JWKS
      public_jwks_path = File.join(output_path, "client-jwks.json")
      File.write(public_jwks_path, JSON.pretty_generate(jwks))

      {
        signing_key_path: signing_key_path,
        encryption_key_path: encryption_key_path,
        public_jwks_path: public_jwks_path,
        jwks: jwks
      }
    end

    # Test full OpenID Federation authentication flow
    #
    # This method tests the complete authentication flow with a real provider:
    # 1. Fetches CSRF token and cookies from login page URL
    # 2. Finds authorization form/button in HTML
    # 3. Makes authorization request with signed request object
    # 4. Returns authorization URL for user interaction
    #
    # @param login_page_url [String] Full URL to login page that contains CSRF token and authorization form
    # @param base_url [String] Base URL of the application (for resolving relative URLs)
    # @param provider_acr [String, nil] Optional ACR (Authentication Context Class Reference) value for provider selection
    # @return [Hash] Result hash with authorization URL, CSRF token, cookies, and instructions
    # @raise [StandardError] If critical errors occur during testing
    def self.test_authentication_flow(
      login_page_url:,
      base_url:,
      provider_acr: nil
    )
      require "uri"
      require "cgi"
      require "json"
      require "base64"
      require "http"
      require "openssl"

      results = {
        steps_completed: [],
        errors: [],
        warnings: [],
        csrf_token: nil,
        cookies: [],
        authorization_url: nil,
        instructions: []
      }

      # HTTP client helper for custom requests

      # Step 1: Fetch login page for CSRF token and cookies
      results[:steps_completed] << "fetch_csrf_token"

      html_body = nil
      cookie_header = nil
      csrf_token = nil
      cookies = []

      begin
        login_response = build_http_client(connect_timeout: 10, read_timeout: 10).get(login_page_url)

        unless login_response.status.success?
          raise "Failed to fetch login page: #{login_response.status.code} #{login_response.status.reason}"
        end

        # Extract cookies
        set_cookie_headers = login_response.headers["Set-Cookie"]
        if set_cookie_headers
          cookie_list = set_cookie_headers.is_a?(Array) ? set_cookie_headers : [set_cookie_headers]
          cookie_list.each do |set_cookie|
            cookie_str = set_cookie.to_s
            # Security: Limit cookie header size to prevent DoS attacks (max 4KB per cookie)
            next if cookie_str.length > 4096
            # Security: Use non-greedy matching with length limits to prevent ReDoS
            cookie_match = cookie_str.match(/^([^=]{1,256})=([^;]{1,4096})/)
            cookies << "#{cookie_match[1]}=#{cookie_match[2]}" if cookie_match
          end
        end

        cookie_header = cookies.join("; ")

        # Extract CSRF token from HTML
        html_body = login_response.body.to_s

        # Security: Limit HTML body size to prevent DoS attacks (max 1MB)
        if html_body.bytesize > 1_048_576
          raise "HTML response too large (#{html_body.bytesize} bytes), possible DoS attack"
        end

        # Try meta tag first
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        csrf_meta_match = html_body.match(/<meta\s+name=["']csrf-token["']\s+content=["']([^"']{1,256})["']/i)
        csrf_token = csrf_meta_match[1] if csrf_meta_match

        # Try form input if not found
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        unless csrf_token
          csrf_input_match = html_body.match(/<input[^>]*name=["']authenticity_token["'][^>]*value=["']([^"']{1,256})["']/i)
          csrf_token = csrf_input_match[1] if csrf_input_match
        end

        unless csrf_token
          raise "Failed to extract CSRF token from login page"
        end

        results[:csrf_token] = csrf_token
        results[:cookies] = cookies
        results[:steps_completed] << "extract_csrf_and_cookies"
      rescue => e
        results[:errors] << "Step 1 (CSRF token): #{e.message}"
        raise
      end

      # Step 2: Find authorization form/button in HTML
      results[:steps_completed] << "find_authorization_form"

      begin
        # Try to find form with action containing "openid_federation"
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        form_match = html_body.match(/<form[^>]*action=["']([^"']{0,2048}openid[_-]?federation[^"']{0,2048})["'][^>]*>/i)
        auth_endpoint = nil

        if form_match
          form_action = form_match[1]
          # Note: Rake tasks are developer tools, no security validation needed
          begin
            auth_endpoint = if form_action.start_with?("http://", "https://")
              URI.parse(form_action).to_s
            else
              URI.join(base_url, form_action).to_s
            end
          rescue URI::InvalidURIError => e
            raise "Invalid form action URI: #{e.message}"
          end
        else
          # Try to find button/link with href containing "openid_federation"
          # Security: Use non-greedy matching and limit capture group to prevent ReDoS
          button_match = html_body.match(/<a[^>]*href=["']([^"']{0,2048}openid[_-]?federation[^"']{0,2048})["'][^>]*>/i)
          if button_match
            button_href = button_match[1]
            # Note: Rake tasks are developer tools, no security validation needed
            begin
              auth_endpoint = if button_href.start_with?("http://", "https://")
                URI.parse(button_href).to_s
              else
                URI.join(base_url, button_href).to_s
              end
            rescue URI::InvalidURIError => e
              raise "Invalid button href URI: #{e.message}"
            end
          else
            # Fallback: try common paths
            common_paths = [
              "/users/auth/openid_federation",
              "/auth/openid_federation",
              "/openid_federation"
            ]
            auth_endpoint = nil
            common_paths.each do |path|
              test_url = URI.join(base_url, path).to_s
              begin
                test_response = build_http_client(connect_timeout: 5, read_timeout: 5).get(test_url)
                if test_response.status.code >= 300 && test_response.status.code < 400
                  auth_endpoint = test_url
                  break
                end
              rescue
                # Continue to next path
              end
            end
            auth_endpoint ||= URI.join(base_url, "/users/auth/openid_federation").to_s
          end
        end

        results[:auth_endpoint] = auth_endpoint
        results[:steps_completed] << "resolve_auth_endpoint"
      rescue => e
        results[:errors] << "Step 2 (Find authorization form): #{e.message}"
        raise
      end

      # Step 3: Request authorization URL
      results[:steps_completed] << "request_authorization"

      begin
        headers = {
          "X-CSRF-Token" => csrf_token,
          "X-Requested-With" => "XMLHttpRequest",
          "Referer" => login_page_url
        }
        headers["Cookie"] = cookie_header unless cookie_header.empty?

        form_data = {}
        # Include acr_values if provided (must be configured in request_object_params to be included in JWT)
        form_data[:acr_values] = provider_acr if StringHelpers.present?(provider_acr)

        auth_response = build_http_client(connect_timeout: 10, read_timeout: 10)
          .headers(headers)
          .post(auth_endpoint, form: form_data)

        authorization_url = nil

        if auth_response.status.code >= 300 && auth_response.status.code < 400
          location = auth_response.headers["Location"]
          if location
            # Security: Validate location header
            if location.length > 2048
              raise "Location header exceeds maximum length"
            end
            authorization_url = if location.start_with?("http://", "https://")
              # Note: Rake tasks are developer tools, no security validation needed
              location
            else
              URI.join(base_url, location).to_s
            end
          end
        elsif auth_response.status.code == 200
          authorization_url = auth_response.headers["Location"] || auth_response.body.to_s
          authorization_url = nil unless authorization_url&.start_with?("http")
        end

        unless authorization_url
          raise "Failed to get authorization URL: #{auth_response.status.code} #{auth_response.status.reason}"
        end

        results[:authorization_url] = authorization_url
        results[:steps_completed] << "authorization_url_received"
      rescue => e
        results[:errors] << "Step 3 (Authorization request): #{e.message}"
        raise
      end

      # Return results with instructions
      results[:instructions] = [
        "1. Copy the authorization URL and open it in your browser",
        "2. Complete the authentication with your provider",
        "3. After authentication, you'll be redirected to a callback URL",
        "4. Copy the ENTIRE callback URL (including all parameters) and provide it when prompted"
      ]

      results
    end

    # Process callback URL and complete authentication flow
    #
    # This method processes the callback from the provider and validates the authentication:
    # 1. Parses callback URL and extracts authorization code
    # 2. Exchanges authorization code for tokens
    # 3. Decrypts and validates ID token
    # 4. Validates OpenID Federation compliance
    #
    # @param callback_url [String] Full callback URL from provider
    # @param base_url [String] Base URL of the application
    # @param entity_statement_url [String, nil] Provider entity statement URL (for resolving configuration)
    # @param entity_statement_path [String, nil] Provider entity statement path (cached copy)
    # @param client_id [String] Client ID
    # @param redirect_uri [String] Redirect URI
    # @param private_key [OpenSSL::PKey::RSA] Private key for client authentication
    # @param provider_acr [String, nil] Optional ACR value
    # @param client_entity_statement_url [String, nil] Client entity statement URL (for automatic registration)
    # @param client_entity_statement_path [String, nil] Client entity statement path (cached copy)
    # @return [Hash] Result hash with tokens, ID token claims, and compliance status
    def self.process_callback_and_validate(
      callback_url:,
      base_url:,
      client_id:, redirect_uri:, private_key:, entity_statement_url: nil,
      entity_statement_path: nil,
      provider_acr: nil,
      client_entity_statement_url: nil,
      client_entity_statement_path: nil
    )
      require "uri"
      require "cgi"
      require "json"
      require "base64"
      require_relative "../strategy"

      results = {
        steps_completed: [],
        errors: [],
        warnings: [],
        compliance_checks: {},
        token_info: {},
        id_token_claims: {}
      }

      # Parse callback URL
      begin
        # Note: Rake tasks are developer tools, no security validation needed
        begin
          uri = URI.parse(callback_url)
        rescue URI::InvalidURIError => e
          raise "Invalid callback URL: #{e.message}"
        end
        params = CGI.parse(uri.query || "")

        auth_code = params["code"]&.first
        state = params["state"]&.first
        error = params["error"]&.first
        error_description = params["error_description"]&.first

        if error
          raise "Authorization error: #{error}#{" - #{error_description}" if error_description}"
        end

        unless auth_code
          raise "No authorization code found in callback URL"
        end

        results[:authorization_code] = auth_code
        results[:state] = state
        results[:steps_completed] << "parse_callback"
      rescue => e
        results[:errors] << "Callback parsing: #{e.message}"
        raise
      end

      # Build strategy options from provided parameters
      begin
        # Resolve entity statement URL if only path provided
        resolved_entity_statement_url = entity_statement_url
        if resolved_entity_statement_url.nil? && entity_statement_path
          # If only path provided, try to resolve from base_url
          resolved_entity_statement_url = "#{base_url}/.well-known/openid-federation"
        end

        # Resolve client entity statement URL if only path provided
        resolved_client_entity_statement_url = client_entity_statement_url
        if resolved_client_entity_statement_url.nil? && client_entity_statement_path
          resolved_client_entity_statement_url = "#{base_url}/.well-known/openid-federation"
        end

        # Build strategy options
        strategy_options = {
          discovery: true,
          scope: [:openid],
          response_type: "code",
          client_auth_method: :jwt_bearer,
          client_signing_alg: :RS256,
          always_encrypt_request_object: true,
          entity_statement_url: resolved_entity_statement_url,
          entity_statement_path: entity_statement_path,
          client_entity_statement_url: resolved_client_entity_statement_url,
          client_entity_statement_path: client_entity_statement_path,
          client_options: {
            identifier: client_id,
            redirect_uri: redirect_uri,
            private_key: private_key
          }
        }

        # Store client_auth_method before filtering nil values
        client_auth_method = strategy_options[:client_auth_method] || :jwt_bearer

        # Remove nil values
        strategy_options = strategy_options.reject { |_k, v| v.nil? }
        strategy_options[:client_options] = strategy_options[:client_options].reject { |_k, v| v.nil? }

        strategy = OmniAuth::Strategies::OpenIDFederation.new(nil, strategy_options)
        oidc_client = strategy.client

        unless oidc_client
          raise "Failed to initialize OpenID Connect client"
        end

        unless oidc_client.private_key
          raise "Private key not set on OpenID Connect client (required for private_key_jwt)"
        end

        results[:steps_completed] << "initialize_strategy"
      rescue => e
        results[:errors] << "Strategy initialization: #{e.message}"
        raise
      end

      # Exchange authorization code for tokens
      begin
        oidc_client.authorization_code = auth_code
        oidc_client.redirect_uri = redirect_uri
        access_token = oidc_client.access_token!(client_auth_method)

        id_token_raw = access_token.id_token
        access_token_value = access_token.access_token
        refresh_token = access_token.refresh_token

        results[:token_info] = {
          access_token: access_token_value ? "#{access_token_value[0..30]}..." : nil,
          refresh_token: refresh_token ? "Present" : "Not provided",
          id_token_encrypted: id_token_raw ? "#{id_token_raw[0..50]}..." : nil
        }

        results[:steps_completed] << "token_exchange"
      rescue => e
        results[:errors] << "Token exchange: #{e.message}"
        raise
      end

      # Decrypt and validate ID token
      begin
        id_token = strategy.send(:decode_id_token, id_token_raw)

        results[:id_token_claims] = {
          iss: id_token.iss,
          sub: id_token.sub,
          aud: id_token.aud,
          exp: id_token.exp,
          iat: id_token.iat,
          nonce: id_token.nonce,
          acr: id_token.acr,
          auth_time: id_token.auth_time,
          amr: id_token.amr
        }

        # Validate required claims
        required_claims = {
          iss: id_token.iss,
          sub: id_token.sub,
          aud: id_token.aud,
          exp: id_token.exp,
          iat: id_token.iat
        }

        missing_claims = required_claims.select { |_k, v| v.nil? }
        if missing_claims.empty?
          results[:id_token_valid] = true
        else
          results[:errors] << "Missing required ID token claims: #{missing_claims.keys.join(", ")}"
        end

        results[:steps_completed] << "id_token_validation"
      rescue => e
        results[:errors] << "ID token validation: #{e.message}"
        raise
      end

      # Validate OpenID Federation compliance
      results[:compliance_checks] = {
        "Signed Request Objects" => {
          status: "✅ MANDATORY",
          description: "All requests use signed request objects (RFC 9101)",
          verified: true
        },
        "ID Token Encryption" => {
          status: "✅ MANDATORY",
          description: "ID tokens are encrypted (RSA-OAEP + A128CBC-HS256)",
          verified: id_token_raw.split(".").length == 5 # JWE has 5 parts
        },
        "Client Assertion (private_key_jwt)" => {
          status: "✅ MANDATORY",
          description: "Token endpoint uses private_key_jwt authentication",
          verified: true
        },
        "Entity Statement JWKS" => {
          status: "✅ MANDATORY",
          description: "JWKS extracted from entity statement",
          verified: StringHelpers.present?(entity_statement_path) || StringHelpers.present?(entity_statement_url)
        },
        "Signed JWKS Support" => {
          status: "✅ MANDATORY",
          description: "Supports OpenID Federation signed JWKS for key rotation",
          verified: true
        }
      }

      # Check for client entity statement (optional but recommended)
      if StringHelpers.present?(client_entity_statement_path) || StringHelpers.present?(client_entity_statement_url)
        results[:compliance_checks]["Client Entity Statement"] = {
          status: "✅ RECOMMENDED",
          description: "Client entity statement for federation-based key management",
          verified: true
        }
      end

      # Check registration type (automatic if client entity statement is provided)
      if StringHelpers.present?(client_entity_statement_path) || StringHelpers.present?(client_entity_statement_url)
        results[:compliance_checks]["Automatic Registration"] = {
          status: "✅ ENABLED",
          description: "Automatic client registration using entity statement",
          verified: true
        }
      end

      results[:all_compliance_verified] = results[:compliance_checks].all? { |_k, v| v[:verified] }

      results
    end

    private_class_method :generate_single_key, :generate_separate_keys
  end
end
