require "base64"
require "jwt"

require_relative "../secure_compare"

module OmniauthOpenidFederation
  module Strategy
    module IdTokenDecoding
      private

      def decode_id_token(id_token)
        client_options_hash = options.client_options || {}
        normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)

        if encrypted_token?(id_token)
          decryption_key_source = options.decryption_key_source || options.key_source || :local
          private_key = normalized_options[:private_key]
          jwks = normalized_options[:jwks] || normalized_options["jwks"]
          metadata = load_metadata_for_key_extraction

          encryption_key = case decryption_key_source
          when :federation
            OmniauthOpenidFederation::KeyExtractor.extract_encryption_key(
              jwks: jwks,
              metadata: metadata,
              private_key: private_key
            )
          when :local
            private_key
          else
            raise OmniauthOpenidFederation::ConfigurationError, "Unknown decryption key source: #{decryption_key_source}"
          end

          OmniauthOpenidFederation::Validators.validate_private_key!(encryption_key)

          begin
            decrypted_token = OmniauthOpenidFederation::Jwe.decrypt(id_token, encryption_key)
            OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decrypted ID token using encryption key")

            parts = decrypted_token.to_s.split(".")
            if parts.length != 3
              error_msg = "Decrypted token is not a valid JWT (expected 3 parts, got #{parts.length})"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              OmniauthOpenidFederation::Instrumentation.notify_decryption_failed(
                token_type: "id_token",
                error_message: error_msg,
                error_class: "DecryptionError"
              )
              raise OmniauthOpenidFederation::DecryptionError, error_msg
            end

            id_token = decrypted_token
          rescue => e
            error_msg = "Failed to decrypt ID token: #{e.class} - #{e.message}"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            OmniauthOpenidFederation::Instrumentation.notify_decryption_failed(
              token_type: "id_token",
              error_message: e.message,
              error_class: e.class.name
            )
            raise OmniauthOpenidFederation::DecryptionError, error_msg, e.backtrace
          end
        end

        header_part = id_token.split(".").first
        header = JSON.parse(Base64.urlsafe_decode64(header_part))
        kid = header["kid"] || header[:kid]

        OmniauthOpenidFederation::Logger.debug("[Strategy] ID token kid: #{kid}")

        jwks = resolve_jwks_for_validation_with_kid(normalized_options, kid)

        unless jwks
          error_msg = "JWKS not available for ID token validation. Provide entity statement with provider JWKS or configure jwks_uri"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        begin
          OmniauthOpenidFederation::Logger.debug("[Strategy] Decoding ID token with JWKS (keys: #{(jwks.is_a?(Hash) && jwks["keys"]) ? jwks["keys"].length : "N/A"})")

          unless jwks.is_a?(Hash) && jwks["keys"]
            error_msg = "JWKS format invalid: expected hash with 'keys' array"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          if kid.nil?
            error_msg = "No key id (kid) found in JWT header. JWT must include kid in header to identify the signing key."
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            raise OmniauthOpenidFederation::SignatureError, error_msg
          end

          key_data = jwks["keys"].find { |key| (key["kid"] || key[:kid]) == kid }

          unless key_data
            available_kids = jwks["keys"].map { |k| k["kid"] || k[:kid] }.compact
            error_msg = "Key with kid '#{kid}' not found in JWKS after trying all sources (entity statement, signed JWKS, standard JWKS URI). Available kids: #{available_kids.join(", ")}"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            OmniauthOpenidFederation::Instrumentation.notify_kid_not_found(
              kid: kid,
              jwks_uri: resolve_jwks_uri(normalized_options),
              available_kids: available_kids,
              token_type: "id_token"
            )
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(key_data)

          decoded_payload, _ = JWT.decode(
            id_token,
            public_key,
            true,
            {algorithm: "RS256"}
          )

          normalized_payload = decoded_payload.each_with_object({}) do |(k, v), h|
            h[k.to_s] = v
          end

          OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decoded ID token. Claims: #{normalized_payload.keys.join(", ")}")

          required_claims = ["iss", "sub", "aud", "exp", "iat"]
          payload_keys = normalized_payload.keys.map(&:to_s)
          missing_claims = required_claims - payload_keys

          if missing_claims.any?
            error_msg = "ID token missing required claims: #{missing_claims.join(", ")}. Available claims: #{payload_keys.join(", ")}"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            OmniauthOpenidFederation::Instrumentation.notify_missing_required_claims(
              missing_claims: missing_claims,
              available_claims: payload_keys,
              token_type: "id_token"
            )
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          validate_id_token_claims!(normalized_payload, normalized_options)
          omniauth_rack_session&.delete("omniauth.nonce") if options.send_nonce

          payload_with_symbols = normalized_payload.each_with_object({}) do |(k, v), h|
            h[k.to_sym] = v
          end

          OmniauthOpenidFederation::IdToken.new(payload_with_symbols)
        rescue JWT::DecodeError, JWT::VerificationError => e
          error_msg = "Failed to decode or verify ID token signature: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")

          available_kids = []
          if jwks.is_a?(Hash) && jwks["keys"]
            available_kids = jwks["keys"].map { |k| k["kid"] || k[:kid] }.compact
            OmniauthOpenidFederation::Logger.debug("[Strategy] Available keys in JWKS (kids): #{available_kids.join(", ")}")
          end

          OmniauthOpenidFederation::Instrumentation.notify_signature_verification_failed(
            token_type: "id_token",
            kid: kid,
            jwks_uri: resolve_jwks_uri(normalized_options),
            error_message: e.message,
            error_class: e.class.name,
            available_kids: available_kids
          )

          raise OmniauthOpenidFederation::SignatureError, error_msg, e.backtrace
        rescue OmniauthOpenidFederation::ValidationError,
          OmniauthOpenidFederation::SecurityError,
          OmniauthOpenidFederation::ConfigurationError,
          OmniauthOpenidFederation::DecryptionError => error
          raise error
        rescue => e
          error_msg = "Failed to decode or validate ID token: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::SignatureError, error_msg, e.backtrace
        end
      end

      def encrypted_token?(token)
        OmniauthOpenidFederation::Jwe.encrypted?(token)
      end

      def validate_id_token_claims!(payload, normalized_options)
        expected_issuer = expected_id_token_issuer(normalized_options)
        token_issuer = payload["iss"]

        if OmniauthOpenidFederation::StringHelpers.present?(expected_issuer) &&
            token_issuer != expected_issuer
          OmniauthOpenidFederation::Instrumentation.notify_issuer_mismatch(
            expected_issuer: expected_issuer,
            actual_issuer: token_issuer
          )
          raise OmniauthOpenidFederation::ValidationError,
            "ID token issuer mismatch: expected '#{expected_issuer}', got '#{token_issuer}'"
        end

        expected_client_id = expected_id_token_client_id(normalized_options)
        token_audiences = Array(payload["aud"]).map(&:to_s)

        if OmniauthOpenidFederation::StringHelpers.present?(expected_client_id) &&
            !token_audiences.include?(expected_client_id.to_s)
          OmniauthOpenidFederation::Instrumentation.notify_audience_mismatch(
            expected_audience: expected_client_id,
            actual_audience: payload["aud"]
          )
          raise OmniauthOpenidFederation::ValidationError,
            "ID token audience mismatch: expected '#{expected_client_id}' in aud, got '#{payload["aud"]}'"
        end

        if options.send_nonce
          rack_session = omniauth_rack_session
          unless rack_session
            raise OmniauthOpenidFederation::ValidationError,
              "ID token nonce validation failed: no nonce in session"
          end

          session_nonce = rack_session["omniauth.nonce"]
          token_nonce = payload["nonce"]

          if OmniauthOpenidFederation::StringHelpers.blank?(session_nonce)
            raise OmniauthOpenidFederation::ValidationError,
              "ID token nonce validation failed: no nonce in session"
          end

          if OmniauthOpenidFederation::StringHelpers.blank?(token_nonce) ||
              !OmniauthOpenidFederation::SecureCompare.secure_compare(token_nonce.to_s, session_nonce.to_s)
            OmniauthOpenidFederation::Instrumentation.notify_invalid_nonce(
              expected_nonce: "[PRESENT]",
              actual_nonce: token_nonce ? "[PRESENT]" : "[MISSING]"
            )
            raise OmniauthOpenidFederation::SecurityError, "ID token nonce mismatch"
          end
        end

        OmniauthOpenidFederation::Validators.validate_allowed_acr_value!(
          payload["acr"],
          options.allowed_acr_values
        )
      end

      def expected_id_token_issuer(normalized_options)
        options.issuer ||
          normalized_options[:issuer] ||
          resolve_issuer_from_metadata
      end

      def expected_id_token_client_id(normalized_options)
        if (options.client_registration_type || :explicit) == :automatic
          client_entity_statement = load_client_entity_statement(
            options.client_entity_statement_path,
            options.client_entity_statement_url
          )
          entity_identifier = extract_entity_identifier_from_statement(
            client_entity_statement,
            options.client_entity_identifier
          )
          return entity_identifier if OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)
        end

        if client.respond_to?(:identifier) && OmniauthOpenidFederation::StringHelpers.present?(client.identifier)
          client.identifier
        else
          normalized_options[:identifier]
        end
      end
    end
  end
end
