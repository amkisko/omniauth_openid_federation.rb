# Rake tasks for OmniAuth OpenID Federation
# Thin wrappers around TasksHelper for CLI interface

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
      puts "   Expires: #{Time.at(metadata[:exp])}" if metadata[:exp]
      puts "   Issued At: #{Time.at(metadata[:iat])}" if metadata[:iat]
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
end
