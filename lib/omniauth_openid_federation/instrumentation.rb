# Instrumentation for omniauth_openid_federation
# Provides configurable notifications for security events, MITM attacks, and authentication mismatches
#
# @example Configure with Sentry
#   OmniauthOpenidFederation.configure do |config|
#     config.instrumentation = ->(event, data) do
#       Sentry.capture_message("OpenID Federation: #{event}", level: :warning, extra: data)
#     end
#   end
#
# @example Configure with Honeybadger
#   OmniauthOpenidFederation.configure do |config|
#     config.instrumentation = ->(event, data) do
#       Honeybadger.notify("OpenID Federation: #{event}", context: data)
#     end
#   end
#
# @example Configure with custom logger
#   OmniauthOpenidFederation.configure do |config|
#     config.instrumentation = ->(event, data) do
#       Rails.logger.warn("[Security] #{event}: #{data.inspect}")
#     end
#   end
#
# @example Disable instrumentation
#   OmniauthOpenidFederation.configure do |config|
#     config.instrumentation = nil
#   end
module OmniauthOpenidFederation
  module Instrumentation
    # Security event types
    EVENT_CSRF_DETECTED = "csrf_detected"
    EVENT_SIGNATURE_VERIFICATION_FAILED = "signature_verification_failed"
    EVENT_DECRYPTION_FAILED = "decryption_failed"
    EVENT_TOKEN_VALIDATION_FAILED = "token_validation_failed"
    EVENT_KEY_ROTATION_DETECTED = "key_rotation_detected"
    EVENT_KID_NOT_FOUND = "kid_not_found"
    EVENT_ENTITY_STATEMENT_VALIDATION_FAILED = "entity_statement_validation_failed"
    EVENT_FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    EVENT_TRUST_CHAIN_VALIDATION_FAILED = "trust_chain_validation_failed"
    EVENT_ENDPOINT_MISMATCH = "endpoint_mismatch"
    EVENT_UNEXPECTED_AUTHENTICATION_BREAK = "unexpected_authentication_break"
    EVENT_STATE_MISMATCH = "state_mismatch"
    EVENT_MISSING_REQUIRED_CLAIMS = "missing_required_claims"
    EVENT_AUDIENCE_MISMATCH = "audience_mismatch"
    EVENT_ISSUER_MISMATCH = "issuer_mismatch"
    EVENT_EXPIRED_TOKEN = "expired_token"
    EVENT_INVALID_NONCE = "invalid_nonce"
    EVENT_AUTHENTICITY_ERROR = "authenticity_error"

    class << self
      # Notify about a security event
      #
      # @param event [String] Event type (use constants from this module)
      # @param data [Hash] Event data (will be sanitized to remove sensitive information)
      # @param severity [Symbol] Event severity (:info, :warning, :error)
      # @return [void]
      def notify(event, data: {}, severity: :warning)
        config = Configuration.config
        return unless config.instrumentation

        # Sanitize data to remove sensitive information
        sanitized_data = sanitize_data(data)

        # Build notification payload
        payload = {
          event: event,
          severity: severity,
          timestamp: Time.now.utc.iso8601,
          data: sanitized_data
        }

        # Call the configured instrumentation callback
        begin
          if config.instrumentation.respond_to?(:call)
            config.instrumentation.call(event, payload)
          elsif config.instrumentation.respond_to?(:notify)
            config.instrumentation.notify(event, payload)
          else
            # Assume it's a logger-like object
            log_message = "[OpenID Federation Security] #{event}: #{sanitized_data.inspect}"
            case severity
            when :error
              config.instrumentation.error(log_message)
            when :warning
              config.instrumentation.warn(log_message)
            else
              config.instrumentation.info(log_message)
            end
          end
        rescue => e
          # Don't let instrumentation failures break the authentication flow
          Logger.warn("[Instrumentation] Failed to notify about #{event}: #{e.message}")
        end
      end

      # Notify about CSRF detection
      #
      # @param data [Hash] Additional context (state_param, state_session, request_info)
      # @return [void]
      def notify_csrf_detected(data = {})
        notify(
          EVENT_CSRF_DETECTED,
          data: {
            reason: "State parameter mismatch - possible CSRF attack",
            **data
          },
          severity: :error
        )
      end

      # Notify about signature verification failure
      #
      # @param data [Hash] Additional context (token_type, kid, jwks_uri, error_message)
      # @return [void]
      def notify_signature_verification_failed(data = {})
        notify(
          EVENT_SIGNATURE_VERIFICATION_FAILED,
          data: {
            reason: "JWT signature verification failed - possible MITM attack or key rotation",
            **data
          },
          severity: :error
        )
      end

      # Notify about decryption failure
      #
      # @param data [Hash] Additional context (token_type, error_message)
      # @return [void]
      def notify_decryption_failed(data = {})
        notify(
          EVENT_DECRYPTION_FAILED,
          data: {
            reason: "Token decryption failed - possible MITM attack or key mismatch",
            **data
          },
          severity: :error
        )
      end

      # Notify about token validation failure
      #
      # @param data [Hash] Additional context (validation_type, missing_claims, error_message)
      # @return [void]
      def notify_token_validation_failed(data = {})
        notify(
          EVENT_TOKEN_VALIDATION_FAILED,
          data: {
            reason: "Token validation failed - possible tampering or configuration mismatch",
            **data
          },
          severity: :error
        )
      end

      # Notify about key rotation detection
      #
      # @param data [Hash] Additional context (jwks_uri, kid, available_kids)
      # @return [void]
      def notify_key_rotation_detected(data = {})
        notify(
          EVENT_KEY_ROTATION_DETECTED,
          data: {
            reason: "Key rotation detected - kid not found in current JWKS",
            **data
          },
          severity: :warning
        )
      end

      # Notify about kid not found
      #
      # @param data [Hash] Additional context (kid, jwks_uri, available_kids)
      # @return [void]
      def notify_kid_not_found(data = {})
        notify(
          EVENT_KID_NOT_FOUND,
          data: {
            reason: "Key ID not found in JWKS - possible key rotation or MITM attack",
            **data
          },
          severity: :error
        )
      end

      # Notify about entity statement validation failure
      #
      # @param data [Hash] Additional context (entity_id, validation_step, error_message)
      # @return [void]
      def notify_entity_statement_validation_failed(data = {})
        notify(
          EVENT_ENTITY_STATEMENT_VALIDATION_FAILED,
          data: {
            reason: "Entity statement validation failed - possible tampering or MITM attack",
            **data
          },
          severity: :error
        )
      end

      # Notify about fingerprint mismatch
      #
      # @param data [Hash] Additional context (expected_fingerprint, calculated_fingerprint, entity_statement_url)
      # @return [void]
      def notify_fingerprint_mismatch(data = {})
        notify(
          EVENT_FINGERPRINT_MISMATCH,
          data: {
            reason: "Entity statement fingerprint mismatch - possible MITM attack or tampering",
            **data
          },
          severity: :error
        )
      end

      # Notify about trust chain validation failure
      #
      # @param data [Hash] Additional context (entity_id, trust_anchor, validation_step, error_message)
      # @return [void]
      def notify_trust_chain_validation_failed(data = {})
        notify(
          EVENT_TRUST_CHAIN_VALIDATION_FAILED,
          data: {
            reason: "Trust chain validation failed - possible MITM attack or configuration issue",
            **data
          },
          severity: :error
        )
      end

      # Notify about endpoint mismatch
      #
      # @param data [Hash] Additional context (endpoint_type, expected, actual, source)
      # @return [void]
      def notify_endpoint_mismatch(data = {})
        notify(
          EVENT_ENDPOINT_MISMATCH,
          data: {
            reason: "Endpoint mismatch detected - possible MITM attack or configuration issue",
            **data
          },
          severity: :warning
        )
      end

      # Notify about unexpected authentication break
      #
      # @param data [Hash] Additional context (stage, error_message, error_class)
      # @return [void]
      def notify_unexpected_authentication_break(data = {})
        notify(
          EVENT_UNEXPECTED_AUTHENTICATION_BREAK,
          data: {
            reason: "Unexpected authentication break - something that should not fail has failed",
            **data
          },
          severity: :error
        )
      end

      # Notify about state mismatch
      #
      # @param data [Hash] Additional context (state_param, state_session)
      # @return [void]
      def notify_state_mismatch(data = {})
        notify(
          EVENT_STATE_MISMATCH,
          data: {
            reason: "State parameter mismatch - possible CSRF attack or session issue",
            **data
          },
          severity: :error
        )
      end

      # Notify about missing required claims
      #
      # @param data [Hash] Additional context (missing_claims, available_claims, token_type)
      # @return [void]
      def notify_missing_required_claims(data = {})
        notify(
          EVENT_MISSING_REQUIRED_CLAIMS,
          data: {
            reason: "Token missing required claims - possible tampering or provider issue",
            **data
          },
          severity: :error
        )
      end

      # Notify about audience mismatch
      #
      # @param data [Hash] Additional context (expected_audience, actual_audience, token_type)
      # @return [void]
      def notify_audience_mismatch(data = {})
        notify(
          EVENT_AUDIENCE_MISMATCH,
          data: {
            reason: "Token audience mismatch - possible MITM attack or configuration issue",
            **data
          },
          severity: :error
        )
      end

      # Notify about issuer mismatch
      #
      # @param data [Hash] Additional context (expected_issuer, actual_issuer, token_type)
      # @return [void]
      def notify_issuer_mismatch(data = {})
        notify(
          EVENT_ISSUER_MISMATCH,
          data: {
            reason: "Token issuer mismatch - possible MITM attack or configuration issue",
            **data
          },
          severity: :error
        )
      end

      # Notify about expired token
      #
      # @param data [Hash] Additional context (exp, current_time, token_type)
      # @return [void]
      def notify_expired_token(data = {})
        notify(
          EVENT_EXPIRED_TOKEN,
          data: {
            reason: "Token expired - possible clock skew or replay attack",
            **data
          },
          severity: :warning
        )
      end

      # Notify about invalid nonce
      #
      # @param data [Hash] Additional context (expected_nonce, actual_nonce)
      # @return [void]
      def notify_invalid_nonce(data = {})
        notify(
          EVENT_INVALID_NONCE,
          data: {
            reason: "Nonce mismatch - possible replay attack",
            **data
          },
          severity: :error
        )
      end

      # Notify about authenticity token error (OmniAuth CSRF protection)
      #
      # @param data [Hash] Additional context (error_type, error_message, phase, request_info)
      # @return [void]
      def notify_authenticity_error(data = {})
        notify(
          EVENT_AUTHENTICITY_ERROR,
          data: {
            reason: "OmniAuth authenticity token validation failed - CSRF protection blocked request",
            **data
          },
          severity: :error
        )
      end

      private

      # Sanitize data to remove sensitive information
      #
      # @param data [Hash] Raw data
      # @return [Hash] Sanitized data
      def sanitize_data(data)
        return {} unless data.is_a?(Hash)

        sensitive_keys = [
          :token, :access_token, :id_token, :refresh_token,
          :private_key, :key, :secret, :password,
          :authorization_code, :code,
          :state, :nonce, :state_param, :state_session,
          :fingerprint, :calculated_fingerprint, :expected_fingerprint
        ]

        data.each_with_object({}) do |(key, value), result|
          key_sym = key.to_sym
          result[key] = if sensitive_keys.include?(key_sym)
            "[REDACTED]"
          elsif value.is_a?(Hash)
            sanitize_data(value)
          elsif value.is_a?(Array)
            value.map { |v| v.is_a?(Hash) ? sanitize_data(v) : v }
          else
            value
          end
        end
      end
    end
  end
end
