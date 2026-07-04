module OmniauthOpenidFederation
  module Strategy
    module FailureHandling
      def fail!(error_type, exception = nil)
        # Determine if this error has already been instrumented
        # Errors instrumented before calling fail! will have a flag set
        already_instrumented = env["omniauth_openid_federation.instrumented"] == true

        unless already_instrumented
          # Extract error information
          error_message = exception&.message || error_type.to_s
          error_class = exception&.class&.name || "UnknownError"

          # Determine the phase (request or callback)
          phase = request.path.end_with?("/callback") ? "callback_phase" : "request_phase"

          # Build request info
          request_info = {
            remote_ip: request.env["REMOTE_ADDR"],
            user_agent: request.env["HTTP_USER_AGENT"],
            path: request.path,
            method: request.request_method
          }

          # Instrument based on error type
          case error_type.to_sym
          when :authenticity_error
            # OmniAuth CSRF protection error (from middleware)
            OmniauthOpenidFederation::Instrumentation.notify_authenticity_error(
              error_type: error_type.to_s,
              error_message: error_message,
              error_class: error_class,
              phase: phase,
              request_info: request_info
            )
          when :csrf_detected
            # This should already be instrumented before calling fail!, but instrument here as fallback
            # (e.g., if fail! is called directly without prior instrumentation)
            OmniauthOpenidFederation::Instrumentation.notify_csrf_detected(
              error_type: error_type.to_s,
              error_message: error_message,
              phase: phase,
              request_info: request_info
            )
          when :missing_code, :token_exchange_error
            # These should already be instrumented before calling fail!, but instrument here as fallback
            # (e.g., if fail! is called directly without prior instrumentation)
            OmniauthOpenidFederation::Instrumentation.notify_unexpected_authentication_break(
              stage: phase,
              error_message: error_message,
              error_class: error_class,
              error_type: error_type.to_s,
              request_info: request_info
            )
          else
            # Unknown error type - instrument as unexpected authentication break
            OmniauthOpenidFederation::Instrumentation.notify_unexpected_authentication_break(
              stage: phase,
              error_message: error_message,
              error_class: error_class,
              error_type: error_type.to_s,
              request_info: request_info
            )
          end
        end

        # Mark as instrumented to prevent double instrumentation
        env["omniauth_openid_federation.instrumented"] = true

        # Call parent fail! method
        super
      end
    end
  end
end
