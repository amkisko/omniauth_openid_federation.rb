# Rake tasks for OmniAuth OpenID Federation
# Thin wrappers around TasksHelper for CLI interface
require_relative "../omniauth_openid_federation/time_helpers"

namespace :openid_federation do
  desc "Fetch entity statement from OpenID Federation provider"
  task :fetch_entity_statement, [:url, :fingerprint, :output_file] => :environment do |_t, args|
    require "omniauth_openid_federation"

    url = args[:url] || ENV["ENTITY_STATEMENT_URL"]
    fingerprint = args[:fingerprint] || ENV["ENTITY_STATEMENT_FINGERPRINT"]
    output_file = args[:output_file] || ENV["ENTITY_STATEMENT_OUTPUT"] || "config/provider-entity-statement.jwt"

    unless url
      puts "❌ Entity statement URL is required"
      puts "   Usage: rake openid_federation:fetch_entity_statement[URL,FINGERPRINT,OUTPUT_FILE]"
      puts "   Or set: ENTITY_STATEMENT_URL, ENTITY_STATEMENT_FINGERPRINT, ENTITY_STATEMENT_OUTPUT"
      exit 1
    end

    puts "Fetching entity statement from #{url}..."
    puts "Output file: #{OmniauthOpenidFederation::TasksHelper.resolve_path(output_file)}"

    if fingerprint
      puts "Expected fingerprint: #{fingerprint}"
    end

    begin
      result = OmniauthOpenidFederation::TasksHelper.fetch_entity_statement(
        url: url,
        fingerprint: fingerprint,
        output_file: output_file
      )

      puts "✅ Entity statement saved to: #{result[:output_path]}"
      puts "✅ Fingerprint: #{result[:fingerprint]}"

      metadata = result[:metadata]
      puts "\n📋 Entity Statement Metadata:"
      puts "   Issuer: #{metadata[:issuer]}"
      puts "   Authorization Endpoint: #{metadata[:metadata][:openid_provider][:authorization_endpoint]}"
      puts "   Token Endpoint: #{metadata[:metadata][:openid_provider][:token_endpoint]}"
      puts "   UserInfo Endpoint: #{metadata[:metadata][:openid_provider][:userinfo_endpoint]}"
      puts "   JWKS URI: #{metadata[:metadata][:openid_provider][:jwks_uri]}"
      if metadata[:metadata][:openid_provider][:signed_jwks_uri]
        puts "   Signed JWKS URI: #{metadata[:metadata][:openid_provider][:signed_jwks_uri]}"
      end
    rescue OmniauthOpenidFederation::Federation::EntityStatement::FetchError => e
      puts "❌ Error fetching entity statement: #{e.message}"
      exit 1
    rescue OmniauthOpenidFederation::Federation::EntityStatement::ValidationError => e
      puts "❌ Validation error: #{e.message}"
      puts "   ⚠️  Entity statement fingerprint mismatch. Check provider documentation."
      exit 1
    rescue => e
      puts "❌ Unexpected error: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first}"
      exit 1
    end
  end

  desc "Validate existing entity statement file"
  task :validate_entity_statement, [:file_path, :fingerprint] => :environment do |_t, args|
    require "omniauth_openid_federation"

    file_path = args[:file_path] || ENV["ENTITY_STATEMENT_PATH"] || "config/provider-entity-statement.jwt"
    expected_fingerprint = args[:fingerprint] || ENV["ENTITY_STATEMENT_FINGERPRINT"]

    begin
      result = OmniauthOpenidFederation::TasksHelper.validate_entity_statement(
        file_path: file_path,
        expected_fingerprint: expected_fingerprint
      )

      if expected_fingerprint
        puts "✅ Fingerprint matches: #{result[:fingerprint]}"
      else
        puts "📋 Entity statement fingerprint: #{result[:fingerprint]}"
      end

      metadata = result[:metadata]
      puts "\n📋 Entity Statement Metadata:"
      puts "   Issuer: #{metadata[:issuer]}"
      puts "   Authorization Endpoint: #{metadata[:metadata][:openid_provider][:authorization_endpoint]}"
      puts "   Token Endpoint: #{metadata[:metadata][:openid_provider][:token_endpoint]}"
      puts "   UserInfo Endpoint: #{metadata[:metadata][:openid_provider][:userinfo_endpoint]}"
      puts "   JWKS URI: #{metadata[:metadata][:openid_provider][:jwks_uri]}"
      if metadata[:metadata][:openid_provider][:signed_jwks_uri]
        puts "   Signed JWKS URI: #{metadata[:metadata][:openid_provider][:signed_jwks_uri]}"
      end
    rescue OmniauthOpenidFederation::ConfigurationError => e
      puts "❌ #{e.message}"
      exit 1
    rescue OmniauthOpenidFederation::ValidationError => e
      puts "❌ Validation error: #{e.message}"
      exit 1
    rescue => e
      puts "❌ Error: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first}"
      exit 1
    end
  end

  desc "Fetch JWKS from provider"
  task :fetch_jwks, [:jwks_uri, :output_file] => :environment do |_t, args|
    require "omniauth_openid_federation"

    jwks_uri = args[:jwks_uri] || ENV["JWKS_URI"]
    output_file = args[:output_file] || ENV["JWKS_OUTPUT"] || "config/provider-jwks.json"

    unless jwks_uri
      puts "❌ JWKS URI is required"
      puts "   Usage: rake openid_federation:fetch_jwks[JWKS_URI,OUTPUT_FILE]"
      puts "   Or set: JWKS_URI, JWKS_OUTPUT"
      exit 1
    end

    puts "Fetching JWKS from #{jwks_uri}..."
    puts "Output file: #{OmniauthOpenidFederation::TasksHelper.resolve_path(output_file)}"

    begin
      result = OmniauthOpenidFederation::TasksHelper.fetch_jwks(
        jwks_uri: jwks_uri,
        output_file: output_file
      )

      jwks = result[:jwks]
      puts "✅ JWKS saved to: #{result[:output_path]}"
      puts "✅ Keys found: #{jwks&.[]("keys")&.length || 0}"

      jwks&.[]("keys")&.each_with_index do |key, index|
        puts "   Key #{index + 1}:"
        puts "     - kid: #{key["kid"]}"
        puts "     - kty: #{key["kty"]}"
        puts "     - use: #{key["use"] || "not specified"}"
      end
    rescue => e
      puts "❌ Error fetching JWKS: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first}"
      exit 1
    end
  end

  desc "Parse entity statement and display endpoints"
  task :parse_entity_statement, [:file_path] => :environment do |_t, args|
    require "omniauth_openid_federation"
    require "json"

    file_path = args[:file_path] || ENV["ENTITY_STATEMENT_PATH"] || "config/provider-entity-statement.jwt"

    begin
      metadata = OmniauthOpenidFederation::TasksHelper.parse_entity_statement(file_path: file_path)

      puts "📋 Entity Statement Metadata:"
      puts JSON.pretty_generate(metadata)
    rescue OmniauthOpenidFederation::ConfigurationError, OmniauthOpenidFederation::ValidationError => e
      puts "❌ Error: #{e.message}"
      exit 1
    rescue => e
      puts "❌ Error parsing entity statement: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first}"
      exit 1
    end
  end

  desc "Generate client keys and prepare public JWKS for provider registration"
  task :prepare_client_keys, [:key_type, :output_dir] => :environment do |_t, args|
    require "omniauth_openid_federation"
    require "json"
    require "fileutils"

    key_type = (args[:key_type] || ENV["KEY_TYPE"] || "single").to_s.downcase
    output_dir = args[:output_dir] || ENV["KEYS_OUTPUT_DIR"] || "config"

    output_path = OmniauthOpenidFederation::TasksHelper.resolve_path(output_dir)

    unless File.directory?(output_path)
      FileUtils.mkdir_p(output_path)
      puts "Created output directory: #{output_path}"
    end

    puts "Generating client keys..."
    puts "Key type: #{key_type}"
    puts "Output directory: #{output_path}"

    begin
      result = OmniauthOpenidFederation::TasksHelper.prepare_client_keys(
        key_type: key_type,
        output_dir: output_dir
      )

      puts "\n✅ Keys generated successfully:"
      if key_type == "single"
        puts "   Private key: #{result[:private_key_path]}"
      else
        puts "   Signing private key: #{result[:signing_key_path]}"
        puts "   Encryption private key: #{result[:encryption_key_path]}"
      end

      puts "   Public JWKS: #{result[:public_jwks_path]}"
      puts "\n📋 Send this JWKS to your provider for client registration:"
      separator = "=" * 70
      puts separator
      puts JSON.pretty_generate(result[:jwks])
      puts separator

      puts "\n⚠️  SECURITY WARNING:"
      puts "   - Keep private keys secure! Never commit them to version control."
      puts "   - Add to .gitignore: config/*-private-key.pem"
      puts "   - Prefer storing secrets in secret vaults (1Password, HashiCorp Vault, etc.)"
      puts "   - Only send the public JWKS (client-jwks.json) to your provider"
    rescue ArgumentError => e
      puts "❌ #{e.message}"
      puts "   Valid options: 'single' (one key for both signing/encryption) or 'separate' (two keys)"
      exit 1
    rescue => e
      puts "❌ Error generating keys: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first}"
      exit 1
    end
  end

  desc "Test local entity statement endpoint and all linked endpoints"
  task :test_local_endpoint, [:base_url] => :environment do |_t, args|
    require "omniauth_openid_federation"

    base_url = args[:base_url] || ENV["BASE_URL"] || "http://localhost:3000"

    puts "=" * 80
    puts "Testing Local Entity Statement Endpoint"
    puts "=" * 80
    puts
    puts "Base URL: #{base_url}"
    puts "Entity Statement URL: #{base_url}/.well-known/openid-federation"
    puts

    begin
      result = OmniauthOpenidFederation::TasksHelper.test_local_endpoint(base_url: base_url)

      entity_statement = result[:entity_statement]
      metadata = result[:metadata]
      results = result[:results]
      key_status = result[:key_status]
      validation_warnings = result[:validation_warnings] || []

      puts "📥 Step 1: Fetching entity statement..."
      if validation_warnings.any? { |w| w.include?("fetch") || w.include?("Fetch") }
        puts "⚠️  Entity statement fetched with warnings"
      else
        puts "✅ Entity statement fetched successfully"
      end
      puts "   Fingerprint: #{entity_statement.fingerprint}"
      puts

      puts "📋 Step 2: Parsing entity statement..."
      if validation_warnings.any?
        puts "⚠️  Entity statement parsed with validation warnings:"
        validation_warnings.each do |warning|
          puts "   ⚠️  #{warning}"
        end
      else
        puts "✅ Entity statement parsed successfully"
      end
      puts "   Issuer: #{metadata[:issuer]}"
      puts "   Subject: #{metadata[:sub]}"
      puts "   Expires: #{OmniauthOpenidFederation::TimeHelpers.at(metadata[:exp])}" if metadata[:exp]
      puts "   Issued At: #{OmniauthOpenidFederation::TimeHelpers.at(metadata[:iat])}" if metadata[:iat]
      puts

      # Key status information
      if key_status
        puts "🔑 Key Configuration:"
        case key_status[:type]
        when :single
          puts "   Status: Single key detected (#{key_status[:count]} key(s))"
        when :separate
          puts "   Status: Separate keys detected (#{key_status[:count]} key(s))"
        else
          puts "   Status: #{key_status[:type]} (#{key_status[:count]} key(s))"
        end
        puts "   #{key_status[:recommendation]}"
        puts
      end

      puts "🔗 Step 3: Testing endpoints from entity statement..."
      puts "   Found #{results.length} endpoint(s) to test"
      puts

      results.each do |name, result_data|
        puts "   Testing: #{name}"
        case result_data[:status]
        when :success
          if result_data[:keys]
            puts "   ✅ JWKS fetched successfully (#{result_data[:keys]} key(s))"
          else
            puts "   ✅ Endpoint accessible (HTTP #{result_data[:code]})"
          end
        when :warning
          warning_msg = "HTTP #{result_data[:code]}"
          if result_data[:code] == "404" && result_data[:body]
            body_text = result_data[:body].strip
            warning_msg += " - #{body_text}" if body_text.length > 0
          end
          puts "   ⚠️  Endpoint returned #{warning_msg}"
        when :error
          puts "   ❌ Error: #{result_data[:message]}"
        end
        puts
      end

      # Summary
      puts "=" * 80
      puts "Test Summary"
      puts "=" * 80
      puts

      success_count = results.values.count { |r| r[:status] == :success }
      warning_count = results.values.count { |r| r[:status] == :warning }
      error_count = results.values.count { |r| r[:status] == :error }

      results.each do |name, result_data|
        case result_data[:status]
        when :success
          puts "✅ #{name}: #{result_data[:keys] ? "#{result_data[:keys]} key(s)" : "OK"}"
        when :warning
          warning_msg = "HTTP #{result_data[:code]}"
          if result_data[:code] == "404" && result_data[:body]
            body_text = result_data[:body].strip
            warning_msg += " - #{body_text}" if body_text.length > 0
          end
          puts "⚠️  #{name}: #{warning_msg}"
        when :error
          puts "❌ #{name}: #{result_data[:message]}"
        end
      end

      puts
      if results.empty?
        puts "No endpoints found to test in entity statement."
        if validation_warnings.any?
          puts "Validation warnings: #{validation_warnings.length}"
        end
        puts
        if validation_warnings.any?
          puts "⚠️  Entity statement has validation warnings (see above)."
          puts "   Review the warnings and fix any issues before deploying to production."
        else
          puts "ℹ️  Entity statement parsed successfully, but no testable endpoints found."
        end
      else
        puts "Total: #{success_count} successful, #{warning_count} warning(s), #{error_count} error(s)"
        if validation_warnings.any?
          puts "Validation warnings: #{validation_warnings.length}"
        end
        puts

        if error_count > 0
          puts "⚠️  Some endpoints failed. Check the errors above."
          exit 1
        elsif validation_warnings.any?
          puts "⚠️  Entity statement has validation warnings (see above), but endpoints were tested."
          puts "   Review the warnings and fix any issues before deploying to production."
        else
          puts "✅ All endpoints tested successfully!"
        end
      end
    rescue OmniauthOpenidFederation::Federation::EntityStatement::FetchError => e
      puts "❌ Error fetching entity statement: #{e.message}"
      puts "   Make sure the server is running and the endpoint is accessible"
      exit 1
    rescue => e
      puts "❌ Unexpected error: #{e.message}"
      puts "   #{e.class}: #{e.backtrace.first(3).join("\n   ")}"
      exit 1
    end
  end

  desc "Test full OpenID Federation authentication flow with a real provider"
  task :test_authentication_flow, [:login_page_url, :base_url, :provider_acr] => :environment do |_t, args|
    require "omniauth_openid_federation"
    require "cgi"
    require "base64"
    require "openssl"
    require "uri"
    require "time"

    login_page_url = args[:login_page_url] || ENV["LOGIN_PAGE_URL"]
    base_url = args[:base_url] || ENV["BASE_URL"] || (login_page_url ? URI.parse(login_page_url).tap { |u|
      u.path = ""
      u.query = nil
      u.fragment = nil
    }.to_s : "http://localhost:3000")
    provider_acr = args[:provider_acr] || ENV["PROVIDER_ACR"]

    # Required configuration from environment
    client_id = ENV["CLIENT_ID"]
    redirect_uri = ENV["REDIRECT_URI"] || "#{base_url}/users/auth/openid_federation/callback"
    private_key_pem = ENV["PRIVATE_KEY"] || (ENV["PRIVATE_KEY_BASE64"] ? Base64.decode64(ENV["PRIVATE_KEY_BASE64"]) : nil)
    private_key_path = ENV["PRIVATE_KEY_PATH"]

    # Entity statement configuration
    entity_statement_url = ENV["ENTITY_STATEMENT_URL"]
    entity_statement_path = ENV["ENTITY_STATEMENT_PATH"]
    client_entity_statement_url = ENV["CLIENT_ENTITY_STATEMENT_URL"]
    client_entity_statement_path = ENV["CLIENT_ENTITY_STATEMENT_PATH"]

    puts "=" * 80
    puts "OpenID Federation Authentication Flow Test"
    puts "=" * 80
    puts
    puts "Login Page URL: #{login_page_url || "Not provided"}"
    puts "Base URL: #{base_url}"
    puts "Provider ACR: #{provider_acr || "Not specified (will use default)"}"
    puts

    # Validate required parameters
    unless login_page_url
      puts "❌ LOGIN_PAGE_URL is required"
      puts "   Set it as an environment variable or pass as first argument:"
      puts "   rake openid_federation:test_authentication_flow[https://example.com/login]"
      exit 1
    end

    # Load private key
    private_key = nil
    if private_key_pem
      begin
        private_key = OpenSSL::PKey::RSA.new(private_key_pem)
      rescue => e
        puts "❌ Failed to parse private key from PRIVATE_KEY or PRIVATE_KEY_BASE64: #{e.message}"
        exit 1
      end
    elsif private_key_path
      begin
        private_key = OpenSSL::PKey::RSA.new(File.read(private_key_path))
      rescue => e
        puts "❌ Failed to load private key from #{private_key_path}: #{e.message}"
        exit 1
      end
    end

    unless private_key
      puts "❌ Private key is required"
      puts "   Set one of: PRIVATE_KEY, PRIVATE_KEY_BASE64, or PRIVATE_KEY_PATH"
      exit 1
    end

    unless client_id
      puts "❌ CLIENT_ID is required"
      puts "   Set it as an environment variable: CLIENT_ID=your_client_id"
      exit 1
    end

    # Try to resolve entity statement if not provided
    unless entity_statement_url || entity_statement_path
      # Try to fetch from well-known endpoint
      begin
        well_known_url = "#{base_url}/.well-known/openid-federation"
        puts "📥 Attempting to fetch entity statement from: #{well_known_url}"
        require "http"
        response = HTTP.timeout(connect: 5, read: 5).get(well_known_url)
        if response.status.success?
          entity_statement_path = "/tmp/entity_statement_#{Time.now.to_i}.json"
          File.write(entity_statement_path, response.body.to_s)
          puts "   ✅ Entity statement cached to: #{entity_statement_path}"
        end
      rescue => e
        puts "   ⚠️  Could not fetch entity statement: #{e.message}"
        puts "   Set ENTITY_STATEMENT_URL or ENTITY_STATEMENT_PATH manually"
      end
    end

    # Display configuration status
    puts "📋 Configuration Status:"
    puts "   ✅ Client ID: #{client_id}"
    puts "   ✅ Redirect URI: #{redirect_uri}"
    puts "   ✅ Private Key: Loaded"
    if entity_statement_url
      puts "   ✅ Provider Entity Statement URL: #{entity_statement_url}"
    elsif entity_statement_path
      puts "   ✅ Provider Entity Statement Path: #{entity_statement_path}"
    else
      puts "   ⚠️  Provider Entity Statement: Not configured"
    end
    if client_entity_statement_url
      puts "   ✅ Client Entity Statement URL: #{client_entity_statement_url}"
    elsif client_entity_statement_path
      puts "   ✅ Client Entity Statement Path: #{client_entity_statement_path}"
    end
    puts

    begin
      # Step 1: Request authorization URL
      puts "=" * 80
      puts "📋 Step 1: Requesting Authorization URL"
      puts "-" * 80
      puts

      result = OmniauthOpenidFederation::TasksHelper.test_authentication_flow(
        login_page_url: login_page_url,
        base_url: base_url,
        provider_acr: provider_acr
      )

      if result[:errors].any?
        puts "❌ Errors occurred:"
        result[:errors].each { |error| puts "   - #{error}" }
        exit 1
      end

      puts "✅ CSRF token extracted: #{result[:csrf_token][0..20]}..." if result[:csrf_token]
      puts "✅ Cookies received: #{result[:cookies].length} cookie(s)"
      puts
      puts "✅ Authorization URL received"
      puts
      puts "🔗 Authorization URL:"
      puts result[:authorization_url]
      puts
      puts "📋 Instructions:"
      result[:instructions].each { |instruction| puts "   #{instruction}" }
      puts

      # Step 2: Get callback URL from user
      puts "=" * 80
      puts "📥 Step 2: Waiting for Callback URL"
      puts "-" * 80
      puts
      print "Paste the callback URL here (or press Enter to skip to manual code entry): "
      callback_url = $stdin.gets.chomp

      if callback_url.empty?
        puts
        print "Enter authorization code manually: "
        auth_code = $stdin.gets.chomp

        if auth_code.empty?
          puts "❌ No authorization code provided"
          exit 1
        end

        # Build callback URL with code
        callback_url = "#{base_url}/users/auth/openid_federation/callback?code=#{CGI.escape(auth_code)}"
      end

      # Step 3: Process callback and validate
      puts
      puts "=" * 80
      puts "🔄 Step 3: Processing Callback and Validating"
      puts "-" * 80
      puts

      callback_result = OmniauthOpenidFederation::TasksHelper.process_callback_and_validate(
        callback_url: callback_url,
        base_url: base_url,
        entity_statement_url: entity_statement_url,
        entity_statement_path: entity_statement_path,
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key,
        provider_acr: provider_acr,
        client_entity_statement_url: client_entity_statement_url,
        client_entity_statement_path: client_entity_statement_path
      )

      if callback_result[:errors].any?
        puts "❌ Errors occurred:"
        callback_result[:errors].each { |error| puts "   - #{error}" }
        exit 1
      end

      puts "✅ Authorization code extracted"
      puts "✅ Strategy initialized"
      puts "✅ Tokens received"
      puts
      puts "📋 Token Information:"
      callback_result[:token_info].each do |key, value|
        if value
          label = key.to_s.split("_").map(&:capitalize).join(" ")
          puts "   #{label}: #{value}"
        end
      end
      puts

      # Step 4: ID Token validation
      puts "=" * 80
      puts "🔐 Step 4: ID Token Validation"
      puts "-" * 80
      puts

      if callback_result[:id_token_valid]
        puts "✅ ID token decrypted and validated"
        puts
        puts "📋 ID Token Claims:"
        callback_result[:id_token_claims].each do |key, value|
          if value
            if [:exp, :iat, :auth_time].include?(key)
              time_value = begin
                OmniauthOpenidFederation::TimeHelpers.at(value)
              rescue
                value
              end
              puts "   #{key}: #{value} (#{time_value})"
            else
              puts "   #{key}: #{value}"
            end
          end
        end
        puts
        puts "✅ All required claims present"
      else
        puts "❌ ID token validation failed"
      end
      puts

      # Step 5: OpenID Federation Compliance
      puts "=" * 80
      puts "✅ Step 5: OpenID Federation Compliance Check"
      puts "-" * 80
      puts

      callback_result[:compliance_checks].each do |check_name, check_data|
        status_icon = check_data[:verified] ? "✅" : "❌"
        puts "#{status_icon} #{check_name}"
        puts "   Status: #{check_data[:status]}"
        puts "   Description: #{check_data[:description]}"
        puts
      end

      all_verified = callback_result[:all_compliance_verified]

      if all_verified
        puts "✅ All OpenID Federation requirements verified"
      else
        puts "⚠️  Some requirements not verified"
      end
      puts

      # Step 6: Summary
      puts "=" * 80
      puts "📊 Test Summary"
      puts "=" * 80
      puts
      puts "Provider ACR: #{provider_acr || "Default"}"
      if callback_result[:id_token_claims][:sub]
        puts "Subject (sub): #{callback_result[:id_token_claims][:sub]}"
      end
      if callback_result[:id_token_claims][:iss]
        puts "Issuer (iss): #{callback_result[:id_token_claims][:iss]}"
      end
      if callback_result[:id_token_claims][:aud]
        puts "Audience (aud): #{callback_result[:id_token_claims][:aud]}"
      end
      if callback_result[:id_token_claims][:acr]
        puts "Authentication Context (acr): #{callback_result[:id_token_claims][:acr]}"
      end
      puts
      puts "OpenID Federation Compliance: #{all_verified ? "✅ PASS" : "❌ FAIL"}"
      puts
      puts "=" * 80

      if all_verified
        puts "✅ All tests passed! Implementation is compliant."
        exit 0
      else
        puts "⚠️  Some checks failed. Review the output above."
        exit 1
      end
    rescue => e
      puts "❌ Test failed: #{e.message}"
      puts "   #{e.class}"
      puts "   #{e.backtrace.first(10).join("\n   ")}"
      exit 1
    end
  end
end
