module OmniauthOpenidFederation
  module Strategy
    module CallbackHandling
      def callback_phase
        # Security: Validate user input from HTTP request
        state_param_raw = request.params["state"]
        code_param_raw = request.params["code"]
        error_param_raw = request.params["error"]
        error_description_raw = request.params["error_description"]

        state_param = state_param_raw ? OmniauthOpenidFederation::Validators.sanitize_request_param(state_param_raw) : nil
        code_param = code_param_raw ? OmniauthOpenidFederation::Validators.sanitize_request_param(code_param_raw) : nil
        error_param = error_param_raw ? OmniauthOpenidFederation::Validators.sanitize_request_param(error_param_raw) : nil
        error_description_param = error_description_raw ? OmniauthOpenidFederation::Validators.sanitize_request_param(error_description_raw) : nil
        if error_param
          error_msg = "Authorization error: #{error_param}"
          error_msg += " - #{error_description_param}" if error_description_param
          OmniauthOpenidFederation::Instrumentation.notify_unexpected_authentication_break(
            stage: "callback_phase",
            error_message: error_msg,
            error_class: "AuthorizationError",
            request_info: {
              remote_ip: request.env["REMOTE_ADDR"],
              user_agent: request.env["HTTP_USER_AGENT"],
              path: request.path
            }
          )
          env["omniauth_openid_federation.instrumented"] = true
          return fail!(:authorization_error, OmniauthOpenidFederation::ValidationError.new(error_msg))
        end

        # CSRF protection: constant-time state comparison
        state_session = session["omniauth.state"]

        if OmniauthOpenidFederation::StringHelpers.blank?(state_param) ||
            state_session.nil? ||
            !OmniauthOpenidFederation::SecureCompare.secure_compare(state_param.to_s, state_session.to_s)
          # Instrument CSRF detection
          OmniauthOpenidFederation::Instrumentation.notify_csrf_detected(
            state_param: state_param ? "[PRESENT]" : "[MISSING]",
            state_session: state_session ? "[PRESENT]" : "[MISSING]",
            request_info: {
              remote_ip: request.env["REMOTE_ADDR"],
              user_agent: request.env["HTTP_USER_AGENT"],
              path: request.path
            }
          )
          # Mark as instrumented to prevent double instrumentation in fail!
          env["omniauth_openid_federation.instrumented"] = true
          return fail!(:csrf_detected, OmniauthOpenidFederation::SecurityError.new("CSRF detected"))
        end

        # Clear state from session
        session.delete("omniauth.state")

        if OmniauthOpenidFederation::StringHelpers.blank?(code_param)
          # Instrument unexpected authentication break
          OmniauthOpenidFederation::Instrumentation.notify_unexpected_authentication_break(
            stage: "callback_phase",
            error_message: "Missing authorization code",
            error_class: "ValidationError",
            request_info: {
              remote_ip: request.env["REMOTE_ADDR"],
              user_agent: request.env["HTTP_USER_AGENT"],
              path: request.path
            }
          )
          # Mark as instrumented to prevent double instrumentation in fail!
          env["omniauth_openid_federation.instrumented"] = true
          return fail!(:missing_code, OmniauthOpenidFederation::ValidationError.new("Missing authorization code"))
        end

        begin
          @access_token = exchange_authorization_code(code_param)
        rescue => e
          # Instrument unexpected authentication break
          OmniauthOpenidFederation::Instrumentation.notify_unexpected_authentication_break(
            stage: "token_exchange",
            error_message: e.message,
            error_class: e.class.name,
            request_info: {
              remote_ip: request.env["REMOTE_ADDR"],
              user_agent: request.env["HTTP_USER_AGENT"],
              path: request.path
            }
          )
          # Mark as instrumented to prevent double instrumentation in fail!
          env["omniauth_openid_federation.instrumented"] = true
          return fail!(:token_exchange_error, e)
        end

        env["omniauth.auth"] = auth_hash
        call_app!
      end

      private

      def exchange_authorization_code(authorization_code)
        client_options_hash = options.client_options || {}
        normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)
        configured_redirect_uri = normalized_options[:redirect_uri] || callback_url

        oidc_client.authorization_code = authorization_code
        oidc_client.redirect_uri = configured_redirect_uri

        begin
          oidc_client.access_token!(
            options.client_auth_method || :jwt_bearer
          )
        rescue => e
          error_msg = "Failed to exchange authorization code for access token: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::NetworkError, error_msg, e.backtrace
        end
      end

      def new_state
        # Generate a random state value and store it in the session
        state = SecureRandom.hex(self.class::STATE_BYTES)
        session["omniauth.state"] = state
        state
      end

      def new_nonce
        nonce = SecureRandom.hex(self.class::NONCE_BYTES)
        session["omniauth.nonce"] = nonce if options.send_nonce
        nonce
      end

      def omniauth_rack_session
        env.is_a?(Hash) ? env["rack.session"] : nil
      end
    end
  end
end
