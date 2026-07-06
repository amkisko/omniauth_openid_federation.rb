# Tasks helper module for rake tasks
# Contains business logic that can be tested independently
require "json"
require "fileutils"
require_relative "utils"
require_relative "configuration"
require_relative "errors"
require_relative "federation/entity_statement"
require_relative "entity_statement_reader"
require_relative "jwks/fetch"
require_relative "tasks/path_resolver"
require_relative "tasks/local_endpoint_tester"
require_relative "tasks/client_keys_preparer"
require_relative "tasks/authentication_flow_tester"
require_relative "tasks/callback_processor"

module OmniauthOpenidFederation
  module TasksHelper
    def self.resolve_path(file_path)
      Tasks::PathResolver.resolve(file_path)
    end

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

    def self.prepare_client_keys(key_type:, output_dir:)
      Tasks::ClientKeysPreparer.prepare(key_type: key_type, output_dir: output_dir)
    end

    def self.test_local_endpoint(base_url:)
      Tasks::LocalEndpointTester.run(base_url: base_url)
    end

    def self.detect_key_status(jwks)
      Tasks::LocalEndpointTester.detect_key_status(jwks)
    end

    def self.test_authentication_flow(login_page_url:, base_url:, provider_acr: nil)
      Tasks::AuthenticationFlowTester.run(
        login_page_url: login_page_url,
        base_url: base_url,
        provider_acr: provider_acr
      )
    end

    def self.process_callback_and_validate(
      callback_url:,
      base_url:,
      client_id:, redirect_uri:, private_key:, entity_statement_url: nil,
      entity_statement_path: nil,
      provider_acr: nil,
      client_entity_statement_url: nil,
      client_entity_statement_path: nil
    )
      Tasks::CallbackProcessor.process(
        callback_url: callback_url,
        base_url: base_url,
        client_id: client_id,
        redirect_uri: redirect_uri,
        private_key: private_key,
        entity_statement_url: entity_statement_url,
        entity_statement_path: entity_statement_path,
        provider_acr: provider_acr,
        client_entity_statement_url: client_entity_statement_url,
        client_entity_statement_path: client_entity_statement_path
      )
    end
  end
end
