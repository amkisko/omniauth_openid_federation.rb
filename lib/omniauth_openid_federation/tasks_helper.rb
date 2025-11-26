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
            uri = URI(url)
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = (uri.scheme == "https")
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE if defined?(Rails) && Rails.respond_to?(:env) && Rails.env.development?

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

    private_class_method :generate_single_key, :generate_separate_keys
  end
end
