require "omniauth-oauth2"
require "openid_connect"
require "jwt"
require "jwe"
require "base64"
require "securerandom"
require "rack/utils"
require "tempfile"
require "digest"
require_relative "string_helpers"
require_relative "logger"
require_relative "errors"
require_relative "constants"
require_relative "configuration"
require_relative "validators"
require_relative "http_client"
require_relative "jws"
require_relative "jwks/fetch"
require_relative "endpoint_resolver"
require_relative "federation/trust_chain_resolver"
require_relative "federation/metadata_policy_merger"

# OpenID Federation strategy for OAuth 2.0 / OpenID Connect providers
# @see https://openid.net/specs/openid-federation-1_0.html OpenID Federation 1.0 Specification
# @see https://openid.github.io/federation/main.html OpenID Federation Documentation
# @see https://datatracker.ietf.org/doc/html/rfc9101 RFC 9101 - OAuth 2.0 Authorization Request
#
# This strategy implements OpenID Federation features for providers requiring
# compliance with regulatory requirements and security best practices.
#
# Features implemented:
# - Signed Request Objects (RFC 9101, Section 12.1.1.1.1) - Required for secure authorization requests
# - ID Token Encryption/Decryption (RSA-OAEP + A128CBC-HS256) - Required for token security
# - Client Assertion (private_key_jwt) - Required for token endpoint authentication
# - OpenID Federation Entity Statements (Section 3) - Optional but recommended
# - Signed JWKS Support (Section 5.2.1.1) - Required for key rotation compliance
#
# Features implemented:
# - Trust Chain Resolution (Section 10) - Resolves trust chains when trust_anchors configured
# - Metadata Policy Merging (Section 5.1) - Applies metadata policies from trust chain
# - Automatic Client Registration (Section 11.1) - Uses Entity ID as client_id
#
# Features NOT implemented (optional):
# - Trust marks (Section 7) - Optional feature (parsed but not validated)
# - Federation endpoints (Section 8) - Server-side feature (Fetch Endpoint implemented separately)
#
# This strategy uses the openid_connect gem and extends it with federation-specific features.
module OmniAuth
  module Strategies
    class OpenIDFederation < OmniAuth::Strategies::OAuth2
      # Override the name option from the base class
      option :name, "openid_federation"

      # Constants for token format validation
      JWT_PARTS_COUNT = 3 # Standard JWT has 3 parts: header.payload.signature
      JWE_PARTS_COUNT = 5 # Encrypted JWT (JWE) has 5 parts

      # Constants for random value generation
      STATE_BYTES = 32 # Number of hex bytes for state parameter (CSRF protection)
      NONCE_BYTES = 32 # Number of hex bytes for nonce parameter (replay protection)

      # Additional options for OpenID Federation
      option :scope, "openid"
      option :response_type, "code"
      option :discovery, true
      option :send_nonce, true
      option :client_auth_method, :jwt_bearer
      option :client_signing_alg, :RS256
      option :audience, nil # Audience for JWT request objects (defaults to token_endpoint)
      option :fetch_userinfo, true # Whether to fetch userinfo endpoint (default: true for backward compatibility, set to false if ID token contains all needed data)
      option :key_source, :local # Key source: :local (use local static private_key) or :federation (use federation/JWKS) - used as default for both signing and decryption
      option :signing_key_source, nil # Signing key source: :local, :federation, or nil (uses key_source)
      option :decryption_key_source, nil # Decryption key source: :local, :federation, or nil (uses key_source)
      option :entity_statement_path, nil # Path to provider entity statement JWT file (cached copy)
      option :entity_statement_url, nil # URL to provider entity statement (source of truth, Section 9)
      option :entity_statement_fingerprint, nil # Expected SHA-256 fingerprint for verification
      option :issuer, nil # Provider issuer URI (used to build entity statement URL if entity_statement_url not provided)
      option :always_encrypt_request_object, false # Always encrypt request objects if encryption keys available (default: false, only encrypts if provider requires)
      option :client_registration_type, :explicit # Client registration type: :explicit (default) or :automatic (requires client_entity_statement_path)
      option :client_entity_statement_path, nil # Path to client's entity statement JWT file (for automatic registration and client_jwk_signing_key)
      option :client_entity_statement_url, nil # URL to client's entity statement (for dynamic federation endpoints)
      option :client_entity_identifier, nil # Client's entity identifier (required for automatic registration, defaults to entity statement 'sub' claim)
      option :client_jwk_signing_key, nil # Client JWKS for token endpoint authentication (auto-extracted from client entity statement if available)
      option :trust_anchors, [] # Array of Trust Anchor configurations for trust chain resolution: [{entity_id: "...", jwks: {...}}]
      option :enable_trust_chain_resolution, true # Enable trust chain resolution when issuer/client_id is an Entity ID
      option :request_object_params, nil # Array of parameter names to include in signed request object from request.params (allow-list)
      option :prepare_request_object_params, nil # Proc to modify params before adding to signed request object: proc { |params| modified_params }

      # Override client_jwk_signing_key to automatically extract from client entity statement
      # This automates client JWKS extraction according to OpenID Federation spec
      # The underlying openid_connect gem will use this for client authentication (private_key_jwt)
      # This method is called when the option is accessed, ensuring automatic extraction
      def client_jwk_signing_key
        # Return manually configured value if present (allows override)
        configured_value = options.client_jwk_signing_key
        return configured_value if OmniauthOpenidFederation::StringHelpers.present?(configured_value)

        # Automatically extract from client entity statement if available
        extracted_value = extract_client_jwk_signing_key
        return extracted_value if OmniauthOpenidFederation::StringHelpers.present?(extracted_value)

        # Return nil if not available (allows fallback to other authentication methods)
        nil
      end

      # Override options accessor to ensure client_jwk_signing_key is dynamically extracted
      # This ensures the underlying openid_connect gem gets the extracted value when accessing options.client_jwk_signing_key
      def options
        opts = super
        # Dynamically set client_jwk_signing_key if not already set and we can extract it
        if opts[:client_jwk_signing_key].nil? && (opts[:client_entity_statement_path] || opts[:client_entity_statement_url])
          extracted = extract_client_jwk_signing_key
          opts[:client_jwk_signing_key] = extracted if OmniauthOpenidFederation::StringHelpers.present?(extracted)
        end
        opts
      end

      def client
        @client ||= begin
          client_options_hash = options.client_options || {}

          # Automatically resolve endpoints, issuer, scheme, and host from entity statement metadata if available
          # This allows endpoints and issuer to be discovered from entity statement without manual configuration
          # client_options still takes precedence for overrides
          resolved_endpoints = resolve_endpoints_from_metadata(client_options_hash)

          # Merge resolved endpoints with client_options (client_options takes precedence)
          # resolved_endpoints may contain: endpoints, issuer, scheme, host
          # client_options will override any resolved values
          merged_options = resolved_endpoints.merge(client_options_hash)

          # Build base URL from scheme, host, and port
          base_url = build_base_url(merged_options)

          # For automatic registration, identifier is the entity identifier (determined at request time)
          # For explicit registration, identifier comes from client_options
          # Note: For automatic registration, the actual entity identifier will be extracted
          # in authorize_uri and used in the request object. The client identifier here is
          # used for client assertion at the token endpoint, which should also use the entity identifier.
          # However, since the client is cached, we'll handle this in authorize_uri by updating
          # the client's identifier if needed.
          client_identifier = merged_options[:identifier] || merged_options["identifier"]

          # Create OpenID Connect client (extends OAuth2::Client, so compatible with OmniAuth::Strategies::OAuth2)
          # Build endpoints - use resolved values or nil if not available
          auth_endpoint = build_endpoint(base_url, merged_options[:authorization_endpoint] || merged_options["authorization_endpoint"])
          token_endpoint = build_endpoint(base_url, merged_options[:token_endpoint] || merged_options["token_endpoint"])
          userinfo_endpoint = build_endpoint(base_url, merged_options[:userinfo_endpoint] || merged_options["userinfo_endpoint"])
          jwks_uri_endpoint = build_endpoint(base_url, merged_options[:jwks_uri] || merged_options["jwks_uri"])

          # Validate that at least authorization_endpoint is present (required)
          unless OmniauthOpenidFederation::StringHelpers.present?(auth_endpoint)
            error_msg = "Authorization endpoint not configured. Provide authorization_endpoint in client_options or entity statement"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            raise OmniauthOpenidFederation::ConfigurationError, error_msg
          end

          oidc_client = ::OpenIDConnect::Client.new(
            identifier: client_identifier,
            secret: nil, # We use private_key_jwt, so no secret needed
            redirect_uri: merged_options[:redirect_uri] || merged_options["redirect_uri"],
            authorization_endpoint: auth_endpoint,
            token_endpoint: token_endpoint,
            userinfo_endpoint: userinfo_endpoint,
            jwks_uri: jwks_uri_endpoint
          )

          # Store private key for client assertion (private_key_jwt authentication)
          oidc_client.private_key = merged_options[:private_key] || merged_options["private_key"]

          # Store strategy options on client for AccessToken to access later
          # This allows AccessToken to get configuration without relying on Devise
          # Ensure all entity statement options are included (to_h might not include all options)
          strategy_options_hash = options.to_h.dup
          # Explicitly include entity statement options that AccessToken needs
          strategy_options_hash[:entity_statement_path] = options.entity_statement_path if options.entity_statement_path
          strategy_options_hash[:entity_statement_url] = options.entity_statement_url if options.entity_statement_url
          strategy_options_hash[:entity_statement_fingerprint] = options.entity_statement_fingerprint if options.entity_statement_fingerprint
          strategy_options_hash[:issuer] = options.issuer if options.issuer
          oidc_client.instance_variable_set(:@strategy_options, strategy_options_hash)

          # OpenIDConnect::Client extends OAuth2::Client, so it's compatible with OmniAuth::Strategies::OAuth2
          oidc_client
        end
      end

      # Store reference to OpenID Connect client for ID token operations
      def oidc_client
        client
      end

      # Override fail! to instrument all authentication failures
      # This catches failures from OmniAuth middleware (like AuthenticityTokenProtection)
      # as well as failures from within the strategy
      #
      # @param error_type [Symbol] Error type identifier
      # @param exception [Exception] Exception object
      # @return [void]
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

      # Override request_phase to use signed request objects (RFC 9101)
      def request_phase
        redirect authorize_uri
      end

      # Override callback_phase to handle token exchange with OpenIDConnect::Client
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
          fail!(:authorization_error, OmniauthOpenidFederation::ValidationError.new(error_msg))
          return
        end

        # CSRF protection: constant-time state comparison
        state_session = session["omniauth.state"]

        if OmniauthOpenidFederation::StringHelpers.blank?(state_param) ||
            state_session.nil? ||
            !Rack::Utils.secure_compare(state_param.to_s, state_session.to_s)
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
          fail!(:csrf_detected, OmniauthOpenidFederation::SecurityError.new("CSRF detected"))
          return
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
          fail!(:missing_code, OmniauthOpenidFederation::ValidationError.new("Missing authorization code"))
          return
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
          fail!(:token_exchange_error, e)
          return
        end

        env["omniauth.auth"] = auth_hash
        call_app!
      end

      def auth_hash
        OmniAuth::AuthHash.new(
          provider: "openid_federation",
          uid: uid,
          info: info,
          credentials: {
            token: @access_token&.access_token,
            refresh_token: @access_token&.refresh_token,
            expires_at: @access_token&.expires_in ? Time.now.to_i + @access_token.expires_in : nil,
            expires: @access_token&.expires_in ? true : false
          },
          extra: extra
        )
      end

      def authorize_uri
        request_params = request.params

        # Security: Only validate user input from HTTP requests, not config values
        # Note: Rack params can return arrays for multi-value parameters
        sanitized_params = {}
        request_params.each do |key, value|
          next unless value
          key_str = key.to_s
          next if key_str.length > 256
          # For arrays (multi-value params), sanitize each element and limit size
          if value.is_a?(Array)
            # Prevent DoS: limit array size
            if value.length > 100
              next
            end
            # Sanitize each element
            sanitized_array = value.map { |v| OmniauthOpenidFederation::Validators.sanitize_request_param(v) }.compact
            next if sanitized_array.empty?
            # Keep as array for acr_values (handled by normalize_acr_values)
            # Convert to space-separated string for other parameters (ui_locales, claims_locales)
            sanitized_params[key_str] = if key_str == "acr_values"
              sanitized_array
            else
              sanitized_array.join(" ")
            end
          else
            sanitized = OmniauthOpenidFederation::Validators.sanitize_request_param(value)
            sanitized_params[key_str] = sanitized if sanitized
          end
        end
        request_params = sanitized_params

        # Apply custom proc to modify params before adding to signed request object
        if options.prepare_request_object_params.respond_to?(:call)
          request_params = options.prepare_request_object_params.call(request_params.dup) || request_params
          request_params = {} unless request_params.is_a?(Hash)
        end

        # Enforce signed request objects (RFC 9101) - unsigned requests are not allowed
        client_options_hash = options.client_options || {}
        normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)
        private_key = normalized_options[:private_key]
        OmniauthOpenidFederation::Validators.validate_private_key!(private_key)

        resolved_issuer = options.issuer
        unless OmniauthOpenidFederation::StringHelpers.present?(resolved_issuer)
          resolved_issuer = resolve_issuer_from_metadata
          options.issuer = resolved_issuer if resolved_issuer
        end

        audience_value = resolve_audience(client_options_hash, resolved_issuer)

        unless OmniauthOpenidFederation::StringHelpers.present?(audience_value)
          error_msg = "Audience is required for signed request objects. " \
                      "Set audience option, provide entity statement with provider issuer, or configure token_endpoint"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        state_value = new_state
        nonce_value = options.send_nonce ? new_nonce : nil
        configured_redirect_uri = normalized_options[:redirect_uri] || callback_url

        # Automatic registration uses entity identifier as client_id (OpenID Federation Section 12.1)
        client_registration_type = options.client_registration_type || :explicit
        client_id_for_request = normalized_options[:identifier]
        client_entity_statement = nil

        if client_registration_type == :automatic
          client_entity_statement = load_client_entity_statement(
            options.client_entity_statement_path,
            options.client_entity_statement_url
          )
          entity_identifier = extract_entity_identifier_from_statement(client_entity_statement, options.client_entity_identifier)
          unless OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)
            error_msg = "Failed to extract entity identifier from client entity statement. " \
                        "Set client_entity_identifier option or ensure entity statement has 'sub' claim"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            raise OmniauthOpenidFederation::ConfigurationError, error_msg
          end
          client_id_for_request = entity_identifier
          if client.respond_to?(:identifier=)
            client.identifier = entity_identifier
          elsif client.respond_to?(:client_id=)
            client.client_id = entity_identifier
          end
          OmniauthOpenidFederation::Logger.debug("[Strategy] Using automatic registration with entity identifier: #{entity_identifier}")
        end

        signing_key_source = options.signing_key_source || options.key_source || :local
        jwks = normalized_options[:jwks] || normalized_options["jwks"]

        # Extract already-sanitized user input params (sanitized above)
        validated_state = state_value.to_s.strip
        validated_nonce = nonce_value&.to_s&.strip
        validated_login_hint = request_params["login_hint"]
        validated_ui_locales = request_params["ui_locales"]
        validated_claims_locales = request_params["claims_locales"]

        # Config values are trusted (no sanitization needed)
        validated_client_id = client_id_for_request.to_s.strip
        validated_redirect_uri = configured_redirect_uri.to_s.strip
        validated_scope = Array(options.scope).join(" ").strip
        validated_response_type = options.response_type.to_s.strip
        validated_prompt = options.prompt&.to_s&.strip
        validated_hd = options.hd&.to_s&.strip
        validated_response_mode = options.response_mode&.to_s&.strip
        validated_issuer = (resolved_issuer || options.issuer)&.to_s&.strip
        validated_audience = audience_value&.to_s&.strip
        normalized_acr_values = OmniauthOpenidFederation::Validators.normalize_acr_values(request_params["acr_values"], skip_sanitization: true) || nil

        jws_builder = OmniauthOpenidFederation::Jws.new(
          client_id: validated_client_id,
          redirect_uri: validated_redirect_uri,
          scope: validated_scope,
          issuer: validated_issuer,
          audience: validated_audience,
          state: validated_state,
          nonce: validated_nonce,
          response_type: validated_response_type,
          response_mode: validated_response_mode,
          login_hint: validated_login_hint,
          ui_locales: validated_ui_locales,
          claims_locales: validated_claims_locales,
          prompt: validated_prompt,
          hd: validated_hd,
          acr_values: normalized_acr_values,
          extra_params: options.extra_authorize_params || {},
          private_key: normalized_options[:private_key],
          jwks: jwks,
          entity_statement_path: options.entity_statement_path,
          key_source: signing_key_source,
          client_entity_statement: client_entity_statement
        )

        # Add dynamic request object params from HTTP request (already sanitized above)
        options.request_object_params&.each do |key|
          key_str = key.to_s
          next if key_str.length > 256
          value = request_params[key_str]
          jws_builder.add_claim(key_str.to_sym, value) if value
        end

        # RFC 9101: Only 'request' parameter in query, all params in JWT
        provider_metadata = load_provider_metadata_for_encryption
        signed_request_object = jws_builder.sign(
          provider_metadata: provider_metadata,
          always_encrypt: options.always_encrypt_request_object
        )
        unless OmniauthOpenidFederation::StringHelpers.present?(signed_request_object)
          error_msg = "Failed to generate signed request object - authentication cannot proceed without signed request"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::SecurityError, error_msg
        end

        # Build URL manually to ensure RFC 9101 compliance (only 'request' param in query)
        auth_endpoint = client.authorization_endpoint
        unless OmniauthOpenidFederation::StringHelpers.present?(auth_endpoint)
          error_msg = "Authorization endpoint not configured. Provide authorization_endpoint in client_options or entity statement"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        begin
          uri = URI.parse(auth_endpoint)
        rescue URI::InvalidURIError => e
          error_msg = "Invalid authorization endpoint URI format: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        max_string_length = ::OmniauthOpenidFederation::Configuration.config.max_string_length
        if signed_request_object.length > max_string_length
          OmniauthOpenidFederation::Logger.warn("[Strategy] Request object exceeds maximum length")
        end

        uri.query = URI.encode_www_form(request: signed_request_object)
        uri.to_s
      end

      uid do
        raw_info["sub"] || raw_info[:sub]
      end

      info do
        {
          name: raw_info["name"] || raw_info[:name],
          email: raw_info["email"] || raw_info[:email],
          first_name: raw_info["given_name"] || raw_info[:given_name],
          last_name: raw_info["family_name"] || raw_info[:family_name],
          nickname: raw_info["preferred_username"] || raw_info[:preferred_username] || raw_info["nickname"] || raw_info[:nickname],
          image: raw_info["picture"] || raw_info[:picture]
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      def raw_info
        @raw_info ||= begin
          # Use access token from callback_phase (already exchanged)
          # If not available, exchange it now (fallback for direct calls)
          access_token = @access_token
          access_token ||= exchange_authorization_code(request.params["code"])

          id_token = decode_id_token(access_token.id_token)
          id_token_claims = id_token.raw_attributes || {}

          if options.fetch_userinfo
            begin
              userinfo = access_token.userinfo!
              userinfo_hash = decode_userinfo(userinfo)
              id_token_claims.merge(userinfo_hash)
            rescue => e
              error_msg = "Failed to fetch or decode userinfo: #{e.class} - #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              OmniauthOpenidFederation::Logger.warn("[Strategy] Falling back to ID token claims only")
              id_token_claims
            end
          else
            OmniauthOpenidFederation::Logger.debug("[Strategy] Userinfo fetching disabled, using ID token claims only")
            id_token_claims
          end
        end
      end

      private

      # Exchange authorization code for access token
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

      # Generate a new state parameter for CSRF protection
      # This method is expected by the base OAuth2 strategy
      def new_state
        # Generate a random state value and store it in the session
        state = SecureRandom.hex(STATE_BYTES)
        session["omniauth.state"] = state
        state
      end

      # Generate a new nonce for replay attack protection
      def new_nonce
        SecureRandom.hex(NONCE_BYTES)
      end

      # Resolve endpoints and issuer from entity statement metadata automatically
      # This allows endpoints and issuer to be discovered from entity statement without manual configuration
      # If trust chain resolution is enabled and trust anchors are configured, resolves trust chain
      # and applies metadata policies to get effective metadata.
      # client_options still takes precedence for overrides
      #
      # @param client_options_hash [Hash] Current client options (used to check what's already configured)
      # @return [Hash] Hash with resolved endpoints, issuer, scheme, and host (may be empty if entity statement not available)
      def resolve_endpoints_from_metadata(client_options_hash)
        # Determine if we should use trust chain resolution
        issuer_entity_id = options.issuer || client_options_hash[:issuer] || client_options_hash["issuer"]
        use_trust_chain = options.enable_trust_chain_resolution &&
          issuer_entity_id &&
          is_entity_id?(issuer_entity_id) &&
          options.trust_anchors.any?

        if use_trust_chain
          return resolve_endpoints_from_trust_chain(issuer_entity_id, client_options_hash)
        end

        # Fall back to direct entity statement resolution
        # Load entity statement from path, URL, or issuer
        entity_statement_content = load_provider_entity_statement
        return {} unless entity_statement_content

        begin
          # Resolve endpoints from entity statement
          # Use temporary file if we have content but no path
          entity_statement_path = if options.entity_statement_path && File.exist?(resolve_entity_statement_path(options.entity_statement_path))
            resolve_entity_statement_path(options.entity_statement_path)
          else
            # Create temporary file for EndpointResolver
            temp_file = Tempfile.new(["entity_statement", ".jwt"])
            temp_file.write(entity_statement_content)
            temp_file.close
            temp_file.path
          end

          resolved = OmniauthOpenidFederation::EndpointResolver.resolve(
            entity_statement_path: entity_statement_path,
            config: {} # Don't pass client_options here - we want entity statement values
          )

          # Clean up temp file if we created one
          if entity_statement_path.start_with?(Dir.tmpdir)
            begin
              File.unlink(entity_statement_path)
            rescue
              nil
            end
          end

          # Resolve issuer from entity statement if not already configured
          resolved_issuer = nil
          unless options.issuer || client_options_hash[:issuer] || client_options_hash["issuer"]
            resolved_issuer = resolve_issuer_from_metadata
          end

          # Build full URLs from paths if needed
          # Use resolved issuer if available, otherwise fall back to configured issuer
          # Note: Config values are trusted, no security validation needed
          issuer_uri = if resolved_issuer
            begin
              URI.parse(resolved_issuer)
            rescue URI::InvalidURIError
              nil
            end
          elsif options.issuer
            begin
              URI.parse(options.issuer.to_s)
            rescue URI::InvalidURIError
              nil
            end
          end

          resolved_hash = {}

          # Add issuer, scheme, and host to resolved hash if resolved from entity statement
          if resolved_issuer && !(client_options_hash[:issuer] || client_options_hash["issuer"])
            resolved_hash[:issuer] = resolved_issuer
            if issuer_uri
              resolved_hash[:scheme] = issuer_uri.scheme unless client_options_hash[:scheme] || client_options_hash["scheme"]
              resolved_hash[:host] = issuer_uri.host unless client_options_hash[:host] || client_options_hash["host"]
            end
          end

          # Convert endpoint paths to full URLs if they're paths
          # Entity statement may contain full URLs (preferred) or paths
          if resolved[:authorization_endpoint] && !(client_options_hash[:authorization_endpoint] || client_options_hash["authorization_endpoint"])
            resolved_hash[:authorization_endpoint] = if resolved[:authorization_endpoint].start_with?("http://", "https://")
              resolved[:authorization_endpoint]
            elsif issuer_uri
              OmniauthOpenidFederation::EndpointResolver.build_endpoint_url(issuer_uri, resolved[:authorization_endpoint])
            else
              resolved[:authorization_endpoint]
            end
          end

          if resolved[:token_endpoint] && !(client_options_hash[:token_endpoint] || client_options_hash["token_endpoint"])
            resolved_hash[:token_endpoint] = if resolved[:token_endpoint].start_with?("http://", "https://")
              resolved[:token_endpoint]
            elsif issuer_uri
              OmniauthOpenidFederation::EndpointResolver.build_endpoint_url(issuer_uri, resolved[:token_endpoint])
            else
              resolved[:token_endpoint]
            end
          end

          if resolved[:userinfo_endpoint] && !(client_options_hash[:userinfo_endpoint] || client_options_hash["userinfo_endpoint"])
            resolved_hash[:userinfo_endpoint] = if resolved[:userinfo_endpoint].start_with?("http://", "https://")
              resolved[:userinfo_endpoint]
            elsif issuer_uri
              OmniauthOpenidFederation::EndpointResolver.build_endpoint_url(issuer_uri, resolved[:userinfo_endpoint])
            else
              resolved[:userinfo_endpoint]
            end
          end

          if resolved[:jwks_uri] && !(client_options_hash[:jwks_uri] || client_options_hash["jwks_uri"])
            resolved_hash[:jwks_uri] = if resolved[:jwks_uri].start_with?("http://", "https://")
              resolved[:jwks_uri]
            elsif issuer_uri
              OmniauthOpenidFederation::EndpointResolver.build_endpoint_url(issuer_uri, resolved[:jwks_uri])
            else
              resolved[:jwks_uri]
            end
          end

          # Set audience if resolved and not already configured
          if resolved[:audience] && !(client_options_hash[:audience] || client_options_hash["audience"])
            resolved_hash[:audience] = resolved[:audience]
          end

          OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved from entity statement: #{resolved_hash.keys.join(", ")}") if resolved_hash.any?
          resolved_hash
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not resolve from entity statement: #{e.message}")
          {}
        end
      end

      # Resolve issuer from entity statement metadata
      # Priority: provider metadata issuer > entity statement iss claim
      #
      # @return [String, nil] Resolved issuer URI or nil if not available
      def resolve_issuer_from_metadata
        entity_statement_content = load_provider_entity_statement
        return nil unless entity_statement_content

        begin
          entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
          parsed = entity_statement.parse
          return nil unless parsed

          # Prefer provider issuer from metadata, fall back to entity issuer (iss claim)
          issuer = parsed.dig(:metadata, :openid_provider, :issuer) || parsed[:issuer]
          return issuer if OmniauthOpenidFederation::StringHelpers.present?(issuer)

          nil
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not resolve issuer from entity statement: #{e.message}")
          nil
        end
      end

      # Resolve audience for signed request objects
      # Priority: explicit config > entity statement > resolved issuer > token endpoint (from entity/resolved/client) > authorization endpoint > client_options issuer
      #
      # @param client_options_hash [Hash] Client options hash
      # @param resolved_issuer [String, nil] Resolved issuer from entity statement
      # @return [String, nil] Resolved audience URI or nil if not available
      def resolve_audience(client_options_hash, resolved_issuer)
        normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)

        OmniauthOpenidFederation::Logger.debug("[Strategy] Resolving audience. Entity statement path: #{options.entity_statement_path}, Resolved issuer: #{resolved_issuer}")

        # 1. Explicitly configured audience (highest priority)
        audience = options.audience
        if OmniauthOpenidFederation::StringHelpers.present?(audience)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Using explicitly configured audience: #{audience}")
          return audience
        end

        # 2. Try to resolve from entity statement metadata
        resolved_token_endpoint = nil
        entity_issuer = nil
        entity_statement_content = load_provider_entity_statement

        if entity_statement_content
          begin
            # Use temporary file for EndpointResolver
            entity_statement_path = if options.entity_statement_path && File.exist?(resolve_entity_statement_path(options.entity_statement_path))
              resolve_entity_statement_path(options.entity_statement_path)
            else
              temp_file = Tempfile.new(["entity_statement", ".jwt"])
              temp_file.write(entity_statement_content)
              temp_file.close
              temp_file.path
            end

            resolved = OmniauthOpenidFederation::EndpointResolver.resolve(
              entity_statement_path: entity_statement_path,
              config: {}
            )
            OmniauthOpenidFederation::Logger.debug("[Strategy] EndpointResolver resolved: #{resolved.keys.join(", ")}")

            if resolved[:audience] && OmniauthOpenidFederation::StringHelpers.present?(resolved[:audience])
              OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved audience from entity statement: #{resolved[:audience]}")
              # Clean up temp file if we created one
              if entity_statement_path.start_with?(Dir.tmpdir)
                begin
                  File.unlink(entity_statement_path)
                rescue
                  nil
                end
              end
              return resolved[:audience]
            end
            # Store token endpoint from entity statement for later use
            resolved_token_endpoint = resolved[:token_endpoint] if resolved[:token_endpoint]
            OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved token endpoint from entity statement: #{resolved_token_endpoint}")

            # Also try to get entity issuer (iss claim) from entity statement as fallback
            begin
              entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
              parsed = entity_statement.parse
              entity_issuer = parsed[:issuer] if parsed
              OmniauthOpenidFederation::Logger.debug("[Strategy] Entity issuer from entity statement: #{entity_issuer}")
            rescue => e
              OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get entity issuer from entity statement: #{e.message}")
            end

            # Clean up temp file if we created one
            if entity_statement_path.start_with?(Dir.tmpdir)
              begin
                File.unlink(entity_statement_path)
              rescue
                nil
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Could not resolve audience from entity statement: #{e.class} - #{e.message}")
            OmniauthOpenidFederation::Logger.debug("[Strategy] Entity statement resolution error backtrace: #{e.backtrace.first(3).join(", ")}")
          end
        else
          OmniauthOpenidFederation::Logger.debug("[Strategy] No entity statement available (path, URL, or issuer not configured)")
        end

        # 3. Use resolved issuer as audience (common in OpenID Federation)
        # Only use if it's a valid URL (not just a path)
        if OmniauthOpenidFederation::StringHelpers.present?(resolved_issuer)
          # Resolved issuer should be a full URL, not just a path
          if resolved_issuer.start_with?("http://", "https://")
            OmniauthOpenidFederation::Logger.debug("[Strategy] Using resolved issuer as audience: #{resolved_issuer}")
            return resolved_issuer
          else
            OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved issuer is not a full URL, skipping: #{resolved_issuer}")
          end
        end

        # 3b. Use entity issuer (iss claim) from entity statement as fallback
        # Only use if it's a valid URL (not just a path)
        if OmniauthOpenidFederation::StringHelpers.present?(entity_issuer)
          # Entity issuer should be a full URL, not just a path
          if entity_issuer.start_with?("http://", "https://")
            OmniauthOpenidFederation::Logger.debug("[Strategy] Using entity issuer (iss claim) as audience: #{entity_issuer}")
            return entity_issuer
          else
            OmniauthOpenidFederation::Logger.debug("[Strategy] Entity issuer is not a full URL, skipping: #{entity_issuer}")
          end
        end

        # 4. Use token endpoint as audience (fallback per OAuth 2.0 spec)
        # Try multiple sources: resolved from entity statement, from client_options, or from OpenID Connect client
        token_endpoint = resolved_token_endpoint ||
          normalized_options[:token_endpoint] ||
          normalized_options["token_endpoint"]

        # If still no token endpoint, try to get it from the OpenID Connect client
        if OmniauthOpenidFederation::StringHelpers.blank?(token_endpoint)
          begin
            # Get resolved endpoints (includes token_endpoint if resolved from entity statement)
            resolved_endpoints = resolve_endpoints_from_metadata(client_options_hash)
            token_endpoint = resolved_endpoints[:token_endpoint] if resolved_endpoints[:token_endpoint]
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get token endpoint from resolved endpoints: #{e.message}")
          end
        end

        # If still no token endpoint, try to get it from the OpenID Connect client
        if OmniauthOpenidFederation::StringHelpers.blank?(token_endpoint)
          begin
            # The client might have been initialized with token_endpoint from discovery or entity statement
            if client.respond_to?(:token_endpoint) && client.token_endpoint
              token_endpoint = client.token_endpoint.to_s
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get token endpoint from client: #{e.message}")
          end
        end

        if OmniauthOpenidFederation::StringHelpers.present?(token_endpoint)
          # Build full URL if it's a path
          if token_endpoint.start_with?("http://", "https://")
            OmniauthOpenidFederation::Logger.debug("[Strategy] Using token endpoint as audience: #{token_endpoint}")
            return token_endpoint
          else
            # Build full URL from base URL
            base_url = build_base_url(normalized_options)
            # If base_url is nil (no host), we can't build a valid URL - skip this fallback
            if base_url
              full_token_endpoint = build_endpoint(base_url, token_endpoint)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using token endpoint as audience: #{full_token_endpoint}")
              return full_token_endpoint
            else
              OmniauthOpenidFederation::Logger.debug("[Strategy] Cannot build token endpoint URL - no host in client_options")
            end
          end
        end

        # 5. Use authorization endpoint as audience (fallback - also valid per OAuth 2.0)
        # Some providers use authorization endpoint as audience
        auth_endpoint = normalized_options[:authorization_endpoint] || normalized_options["authorization_endpoint"]
        if OmniauthOpenidFederation::StringHelpers.blank?(auth_endpoint)
          begin
            resolved_endpoints = resolve_endpoints_from_metadata(client_options_hash)
            auth_endpoint = resolved_endpoints[:authorization_endpoint] if resolved_endpoints[:authorization_endpoint]
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get authorization endpoint from resolved endpoints: #{e.message}")
          end
        end

        if OmniauthOpenidFederation::StringHelpers.blank?(auth_endpoint)
          begin
            if client.respond_to?(:authorization_endpoint) && client.authorization_endpoint
              auth_endpoint = client.authorization_endpoint.to_s
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get authorization endpoint from client: #{e.message}")
          end
        end

        if OmniauthOpenidFederation::StringHelpers.present?(auth_endpoint)
          if auth_endpoint.start_with?("http://", "https://")
            OmniauthOpenidFederation::Logger.debug("[Strategy] Using authorization endpoint as audience: #{auth_endpoint}")
            return auth_endpoint
          else
            base_url = build_base_url(normalized_options)
            if base_url
              full_auth_endpoint = build_endpoint(base_url, auth_endpoint)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using authorization endpoint as audience: #{full_auth_endpoint}")
              return full_auth_endpoint
            end
          end
        end

        # 6. Use issuer from client_options as last resort
        issuer = normalized_options[:issuer] || normalized_options["issuer"]
        if OmniauthOpenidFederation::StringHelpers.present?(issuer)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Using client_options issuer as audience: #{issuer}")
          return issuer
        end

        # No audience found - log what we tried with details
        OmniauthOpenidFederation::Logger.error("[Strategy] Could not resolve audience. Tried: explicit config, entity statement (#{options.entity_statement_path}), resolved issuer (#{resolved_issuer}), entity issuer, token endpoint, authorization endpoint, client_options issuer. Client options keys: #{normalized_options.keys.join(", ")}")
        nil
      end

      # Resolve JWKS for ID token validation
      # Priority: entity statement JWKS (we already have it) > fetch from signed JWKS > fetch from standard JWKS URI
      # We're the client - we should use JWKS from entity statement we already have, not fetch it
      #
      # @param normalized_options [Hash] Normalized client options hash
      # @return [Hash, nil] JWKS hash or nil if not available
      def resolve_jwks_for_validation(normalized_options)
        entity_statement_content = load_provider_entity_statement

        # 1. Extract JWKS directly from entity statement (we already have it - no HTTP request needed)
        if entity_statement_content
          begin
            entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
            parsed = entity_statement.parse
            if parsed && parsed[:jwks]
              entity_jwks = parsed[:jwks]
              # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
              if entity_jwks.is_a?(Hash) && entity_jwks.key?("keys")
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return entity_jwks
              elsif entity_jwks.is_a?(Hash) && entity_jwks.key?(:keys)
                # Convert symbol keys to string keys
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return {"keys" => entity_jwks[:keys]}
              elsif entity_jwks.is_a?(Array)
                OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS from entity statement for ID token validation")
                return {"keys" => entity_jwks}
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not extract JWKS from entity statement: #{e.message}")
          end
        end

        # 2. Try to fetch from signed JWKS (if entity statement has signed_jwks_uri)
        if entity_statement_content
          begin
            parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
              entity_statement_content
            )
            if parsed && parsed[:signed_jwks_uri] && parsed[:entity_jwks]
              OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching signed JWKS for ID token validation")
              signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
                parsed[:signed_jwks_uri],
                parsed[:entity_jwks]
              )
              # Ensure it's in the format expected by JWT.decode
              if signed_jwks.is_a?(Hash) && signed_jwks.key?("keys")
                return signed_jwks
              elsif signed_jwks.is_a?(Hash) && signed_jwks.key?(:keys)
                return {"keys" => signed_jwks[:keys]}
              elsif signed_jwks.is_a?(Array)
                return {"keys" => signed_jwks}
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not fetch signed JWKS: #{e.message}")
          end
        end

        # 3. Fallback: Fetch from standard JWKS URI (only if entity statement doesn't have JWKS)
        jwks_uri = resolve_jwks_uri(normalized_options)
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching JWKS from URI: #{OmniauthOpenidFederation::Utils.sanitize_uri(jwks_uri)}")
          begin
            return fetch_jwks(jwks_uri)
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to fetch JWKS from URI: #{e.message}")
          end
        end

        # No JWKS found
        nil
      end

      # Resolve JWKS for ID token validation with fallback if kid not found
      # This handles key rotation by trying multiple JWKS sources
      #
      # @param normalized_options [Hash] Normalized client options hash
      # @param kid [String] Key ID from ID token header
      # @return [Hash, nil] JWKS hash with the requested kid, or nil if not available
      def resolve_jwks_for_validation_with_kid(normalized_options, kid)
        entity_statement_content = load_provider_entity_statement
        first_valid_jwks = nil # Track first valid JWKS in case kid is not found

        # 1. Try entity statement JWKS first (fastest, no HTTP request)
        if entity_statement_content
          begin
            entity_statement = OmniauthOpenidFederation::Federation::EntityStatement.new(entity_statement_content)
            parsed = entity_statement.parse
            if parsed && parsed[:jwks]
              entity_jwks = parsed[:jwks]
              # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
              jwks_hash = if entity_jwks.is_a?(Hash) && entity_jwks.key?("keys")
                entity_jwks
              elsif entity_jwks.is_a?(Hash) && entity_jwks.key?(:keys)
                {"keys" => entity_jwks[:keys]}
              elsif entity_jwks.is_a?(Array)
                {"keys" => entity_jwks}
              end

              keys = jwks_hash&.dig("keys")
              if keys&.is_a?(Array) && !keys.empty?
                # Track first valid JWKS
                first_valid_jwks ||= jwks_hash
                # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
                if kid.nil?
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning entity statement JWKS for validation attempt")
                  return jwks_hash
                end
                # Check if kid is in this JWKS
                key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
                if key_data
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in entity statement JWKS")
                  return jwks_hash
                else
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in entity statement JWKS, trying signed JWKS")
                end
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not extract JWKS from entity statement: #{e.message}")
          end
        end

        # 2. Try signed JWKS (if entity statement has signed_jwks_uri)
        # This is more likely to have the latest keys during key rotation
        if entity_statement_content
          begin
            parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
              entity_statement_content
            )
            if parsed && parsed[:signed_jwks_uri] && parsed[:entity_jwks]
              OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching signed JWKS for ID token validation (kid: #{kid})")
              signed_jwks = OmniauthOpenidFederation::Federation::SignedJWKS.fetch!(
                parsed[:signed_jwks_uri],
                parsed[:entity_jwks]
              )
              # Ensure it's in the format expected by JWT.decode
              jwks_hash = if signed_jwks.is_a?(Hash) && signed_jwks.key?("keys")
                signed_jwks
              elsif signed_jwks.is_a?(Hash) && signed_jwks.key?(:keys)
                {"keys" => signed_jwks[:keys]}
              elsif signed_jwks.is_a?(Array)
                {"keys" => signed_jwks}
              end

              keys = jwks_hash&.dig("keys")
              if keys&.is_a?(Array) && !keys.empty?
                # Track first valid JWKS
                first_valid_jwks ||= jwks_hash
                # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
                if kid.nil?
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning signed JWKS for validation attempt")
                  return jwks_hash
                end
                # Check if kid is in this JWKS
                key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
                if key_data
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in signed JWKS")
                  return jwks_hash
                else
                  OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in signed JWKS, trying standard JWKS URI")
                end
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not fetch signed JWKS: #{e.message}")
          end
        end

        # 3. Fallback: Fetch from standard JWKS URI
        jwks_uri = resolve_jwks_uri(normalized_options)
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Fetching JWKS from URI for kid '#{kid}': #{OmniauthOpenidFederation::Utils.sanitize_uri(jwks_uri)}")
          begin
            jwks_hash = fetch_jwks(jwks_uri)
            keys = jwks_hash&.dig("keys")
            if keys&.is_a?(Array) && !keys.empty?
              # Track first valid JWKS
              first_valid_jwks ||= jwks_hash
              # If kid is nil, return JWKS anyway (let JWT decoding fail with proper error)
              if kid.nil?
                OmniauthOpenidFederation::Logger.debug("[Strategy] Kid is nil, returning standard JWKS URI for validation attempt")
                return jwks_hash
              end
              # Check if kid is in this JWKS
              key_data = keys.find { |key| (key["kid"] || key[:kid]) == kid }
              if key_data
                OmniauthOpenidFederation::Logger.debug("[Strategy] Found kid '#{kid}' in standard JWKS URI")
                return jwks_hash
              else
                OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in standard JWKS URI")
              end
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to fetch JWKS from URI: #{e.message}")
          end
        end

        # If we found valid JWKS but kid was not found, return it anyway
        # This allows the decoding to fail with "kid not found" instead of "JWKS not available"
        if first_valid_jwks && kid
          OmniauthOpenidFederation::Logger.debug("[Strategy] Kid '#{kid}' not found in any JWKS source, but returning first valid JWKS for validation attempt")
          return first_valid_jwks
        end

        # No JWKS found
        nil
      end

      # Resolve JWKS URI (for fallback fetching)
      # Priority: client_options > entity statement > OpenID Connect client
      #
      # @param normalized_options [Hash] Normalized client options hash
      # @return [String, nil] Resolved JWKS URI or nil if not available
      def resolve_jwks_uri(normalized_options)
        # 1. Try client_options first
        jwks_uri = normalized_options[:jwks_uri] || normalized_options["jwks_uri"]
        if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
          # Build full URL if it's a path
          if jwks_uri.start_with?("http://", "https://")
            return jwks_uri
          else
            base_url = build_base_url(normalized_options)
            return build_endpoint(base_url, jwks_uri) if base_url
          end
        end

        # 2. Try to resolve from entity statement
        if options.entity_statement_path
          begin
            resolved_endpoints = resolve_endpoints_from_metadata(normalized_options)
            jwks_uri = resolved_endpoints[:jwks_uri] if resolved_endpoints[:jwks_uri]
            if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved JWKS URI from entity statement: #{jwks_uri}")
              return jwks_uri
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get JWKS URI from entity statement: #{e.message}")
          end
        end

        # 3. Try to get from OpenID Connect client
        begin
          if client.respond_to?(:jwks_uri) && client.jwks_uri
            jwks_uri = client.jwks_uri.to_s
            if OmniauthOpenidFederation::StringHelpers.present?(jwks_uri)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using JWKS URI from client: #{jwks_uri}")
              return jwks_uri
            end
          end
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not get JWKS URI from client: #{e.message}")
        end

        # No JWKS URI found
        nil
      end

      def build_base_url(client_options_hash)
        normalized = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)
        scheme = normalized[:scheme] || "https"
        host = normalized[:host]
        port = normalized[:port]

        # Return nil if host is missing (can't build valid URL)
        return nil unless OmniauthOpenidFederation::StringHelpers.present?(host)

        url = "#{scheme}://#{host}"
        url += ":#{port}" if port
        url
      end

      def build_endpoint(base_url, path)
        return path if path.to_s.start_with?("http://", "https://")
        return nil unless base_url # Can't build endpoint without base URL

        path = path.to_s
        path = "/#{path}" unless path.start_with?("/")
        "#{base_url}#{path}"
      end

      def decode_id_token(id_token)
        client_options_hash = options.client_options || {}
        normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)

        # Check if ID token is encrypted
        if encrypted_token?(id_token)
          # Decrypt first using encryption key
          # According to OpenID Federation spec: supports separate signing/encryption keys
          # Decryption key source determines whether to use local static private_key or federation/JWKS
          decryption_key_source = options.decryption_key_source || options.key_source || :local
          private_key = normalized_options[:private_key]
          jwks = normalized_options[:jwks] || normalized_options["jwks"]
          metadata = load_metadata_for_key_extraction

          # Extract encryption key based on decryption_key_source configuration
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
            # Decrypt using JWE gem
            decrypted_token = JWE.decrypt(id_token, encryption_key)
            OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decrypted ID token using encryption key")

            # Verify decrypted token is a valid JWT (3 parts: header.payload.signature)
            parts = decrypted_token.to_s.split(".")
            if parts.length != 3
              error_msg = "Decrypted token is not a valid JWT (expected 3 parts, got #{parts.length})"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              # Instrument decryption failure
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
            # Instrument decryption failure
            OmniauthOpenidFederation::Instrumentation.notify_decryption_failed(
              token_type: "id_token",
              error_message: e.message,
              error_class: e.class.name
            )
            raise OmniauthOpenidFederation::DecryptionError, error_msg, e.backtrace
          end
        end

        # Extract kid from JWT header first to find the right key
        header_part = id_token.split(".").first
        header = JSON.parse(Base64.urlsafe_decode64(header_part))
        kid = header["kid"] || header[:kid]

        OmniauthOpenidFederation::Logger.debug("[Strategy] ID token kid: #{kid}")

        # Get JWKS for ID token validation with fallback if kid not found
        # Priority: entity statement JWKS > signed JWKS > standard JWKS URI
        # If kid is not found in entity statement JWKS, try other sources (key rotation handling)
        jwks = resolve_jwks_for_validation_with_kid(normalized_options, kid)

        unless jwks
          error_msg = "JWKS not available for ID token validation. Provide entity statement with provider JWKS or configure jwks_uri"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        # Decode and validate ID token
        # Find matching key in JWKS, then decode with that key
        begin
          OmniauthOpenidFederation::Logger.debug("[Strategy] Decoding ID token with JWKS (keys: #{(jwks.is_a?(Hash) && jwks["keys"]) ? jwks["keys"].length : "N/A"})")

          # Find the key with matching kid in JWKS
          unless jwks.is_a?(Hash) && jwks["keys"]
            error_msg = "JWKS format invalid: expected hash with 'keys' array"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          # If kid is missing from JWT header, raise error
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
            # Instrument kid not found
            OmniauthOpenidFederation::Instrumentation.notify_kid_not_found(
              kid: kid,
              jwks_uri: resolve_jwks_uri(normalized_options),
              available_kids: available_kids,
              token_type: "id_token"
            )
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          # Convert JWK to OpenSSL key
          public_key = OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(key_data)

          # Decode JWT using the specific key
          decoded_payload, _ = JWT.decode(
            id_token,
            public_key,
            true, # Verify signature
            {
              algorithm: "RS256"
            }
          )

          # Normalize keys to strings for consistent access
          normalized_payload = decoded_payload.each_with_object({}) do |(k, v), h|
            h[k.to_s] = v
          end

          OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decoded ID token. Claims: #{normalized_payload.keys.join(", ")}")

          # Validate required claims are present (check both string and symbol keys)
          required_claims = ["iss", "sub", "aud", "exp", "iat"]
          payload_keys = normalized_payload.keys.map(&:to_s)
          missing_claims = required_claims - payload_keys

          if missing_claims.any?
            error_msg = "ID token missing required claims: #{missing_claims.join(", ")}. Available claims: #{payload_keys.join(", ")}"
            OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
            # Instrument missing required claims
            OmniauthOpenidFederation::Instrumentation.notify_missing_required_claims(
              missing_claims: missing_claims,
              available_claims: payload_keys,
              token_type: "id_token"
            )
            raise OmniauthOpenidFederation::ValidationError, error_msg
          end

          # Create IdToken object from decoded payload
          # IdToken.new expects symbol keys based on openid_connect gem implementation
          payload_with_symbols = normalized_payload.each_with_object({}) do |(k, v), h|
            h[k.to_sym] = v
          end

          ::OpenIDConnect::ResponseObject::IdToken.new(payload_with_symbols)
        rescue JWT::DecodeError, JWT::VerificationError => e
          error_msg = "Failed to decode or verify ID token signature: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")

          # Add debug info about JWKS structure if available
          available_kids = []
          if jwks.is_a?(Hash) && jwks["keys"]
            available_kids = jwks["keys"].map { |k| k["kid"] || k[:kid] }.compact
            OmniauthOpenidFederation::Logger.debug("[Strategy] Available keys in JWKS (kids): #{available_kids.join(", ")}")
          end

          # Instrument signature verification failure
          OmniauthOpenidFederation::Instrumentation.notify_signature_verification_failed(
            token_type: "id_token",
            kid: kid,
            jwks_uri: resolve_jwks_uri(normalized_options),
            error_message: e.message,
            error_class: e.class.name,
            available_kids: available_kids
          )

          raise OmniauthOpenidFederation::SignatureError, error_msg, e.backtrace
        rescue => e
          error_msg = "Failed to decode or validate ID token: #{e.class} - #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::SignatureError, error_msg, e.backtrace
        end
      end

      def encrypted_token?(token)
        # Check if token is encrypted (JWE format has 5 parts separated by dots)
        parts = token.to_s.split(".")
        parts.length == JWE_PARTS_COUNT
      end

      # Decode userinfo response, handling both encrypted (JWE) and plain JSON formats
      # According to OpenID Federation spec, userinfo responses can be encrypted
      #
      # @param userinfo [Hash, String, Object] Userinfo response (may be encrypted JWT or plain JSON)
      # @return [Hash] Decoded userinfo hash
      # @raise [DecryptionError] If decryption fails
      def decode_userinfo(userinfo)
        # If userinfo is a string, check if it's encrypted (JWE format)
        if userinfo.is_a?(String)
          if encrypted_token?(userinfo)
            # Decrypt encrypted userinfo using encryption key
            client_options_hash = options.client_options || {}
            normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)

            # Decryption key source determines whether to use local static private_key or federation/JWKS
            decryption_key_source = options.decryption_key_source || options.key_source || :local
            private_key = normalized_options[:private_key]
            jwks = normalized_options[:jwks] || normalized_options["jwks"]
            metadata = load_metadata_for_key_extraction

            # Extract encryption key based on decryption_key_source configuration
            encryption_key = if decryption_key_source == :federation
              # Try federation/JWKS first, then fallback to local private_key
              OmniauthOpenidFederation::KeyExtractor.extract_encryption_key(
                jwks: jwks,
                metadata: metadata,
                private_key: private_key
              ) || private_key
            else
              # :local - Use local private_key directly, ignore JWKS/metadata
              private_key
            end

            OmniauthOpenidFederation::Validators.validate_private_key!(encryption_key)

            begin
              # Decrypt using JWE gem
              userinfo_string = JWE.decrypt(userinfo, encryption_key)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decrypted userinfo using encryption key")

              # Parse the decrypted JSON
              JSON.parse(userinfo_string)
            rescue => e
              error_msg = "Failed to decrypt userinfo: #{e.class} - #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              # Instrument decryption failure
              OmniauthOpenidFederation::Instrumentation.notify_decryption_failed(
                token_type: "userinfo",
                error_message: e.message,
                error_class: e.class.name
              )
              raise OmniauthOpenidFederation::DecryptionError, error_msg, e.backtrace
            end
          else
            # Plain JSON string
            JSON.parse(userinfo)
          end
        elsif userinfo.is_a?(Hash)
          # Already a hash
          userinfo
        elsif userinfo.respond_to?(:raw_attributes)
          # OpenIDConnect::ResponseObject::UserInfo extends ConnectObject which has raw_attributes
          userinfo.raw_attributes || {}
        elsif userinfo.respond_to?(:as_json)
          # Fallback to as_json if raw_attributes not available
          userinfo.as_json(skip_validation: true)
        else
          # Last resort: extract instance variables
          userinfo.instance_variables.each_with_object({}) do |var, hash|
            key = var.to_s.delete_prefix("@").to_sym
            hash[key] = userinfo.instance_variable_get(var)
          end
        end
      end

      # Load metadata for key extraction
      # Load provider entity statement from path or fetch from URL/issuer
      # Priority:
      # 1. File path (if provided) - for manual cache, development, debugging
      # 2. Fetch from URL (if provided) - with fingerprint verification and caching
      # 3. Fetch from issuer (if issuer provided) - builds URL from issuer + /.well-known/openid-federation
      #
      # @return [String, nil] Entity statement JWT string or nil if not available
      # @raise [ConfigurationError] If fetching fails
      def load_provider_entity_statement
        # Priority 1: Use file path if provided
        if OmniauthOpenidFederation::StringHelpers.present?(options.entity_statement_path)
          path = resolve_entity_statement_path(options.entity_statement_path)
          if File.exist?(path)
            OmniauthOpenidFederation::Logger.debug("[Strategy] Loading provider entity statement from file: #{path}")
            return File.read(path).strip
          else
            OmniauthOpenidFederation::Logger.warn("[Strategy] Provider entity statement file not found: #{path}, will try to fetch from URL")
          end
        end

        # Priority 2: Fetch from URL if provided
        if OmniauthOpenidFederation::StringHelpers.present?(options.entity_statement_url)
          return fetch_and_cache_entity_statement(
            options.entity_statement_url,
            fingerprint: options.entity_statement_fingerprint
          )
        end

        # Priority 3: Fetch from issuer if provided (only if issuer is a valid URL)
        if OmniauthOpenidFederation::StringHelpers.present?(options.issuer)
          # Check that issuer is a valid URL format before trying to fetch
          # Note: Config values are trusted, only basic format check needed
          begin
            parsed_issuer = URI.parse(options.issuer)
            unless parsed_issuer.is_a?(URI::HTTP) || parsed_issuer.is_a?(URI::HTTPS)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Issuer is not a valid HTTP/HTTPS URL, skipping entity statement fetch from URL: #{options.issuer}")
              return nil
            end
          rescue URI::InvalidURIError
            OmniauthOpenidFederation::Logger.debug("[Strategy] Issuer is not a valid URL, skipping entity statement fetch from URL: #{options.issuer}")
            return nil
          end

          entity_statement_url = OmniauthOpenidFederation::Utils.build_entity_statement_url(options.issuer)
          OmniauthOpenidFederation::Logger.debug("[Strategy] Building entity statement URL from issuer: #{entity_statement_url}")
          return fetch_and_cache_entity_statement(
            entity_statement_url,
            fingerprint: options.entity_statement_fingerprint
          )
        end

        nil
      end

      # Fetch entity statement from URL and cache it
      #
      # @param url [String] Entity statement URL
      # @param fingerprint [String, nil] Expected fingerprint for verification
      # @return [String] Entity statement JWT string
      # @raise [ConfigurationError] If fetching fails
      def fetch_and_cache_entity_statement(url, fingerprint: nil)
        cache_key = "federation:provider_entity_statement:#{Digest::SHA256.hexdigest(url)}"

        # Check cache first (if Rails.cache is available)
        if defined?(Rails) && Rails.cache
          begin
            cached = Rails.cache.read(cache_key)
            if cached
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using cached provider entity statement from: #{url}")
              return cached
            end
          rescue => e
            OmniauthOpenidFederation::Logger.debug("[Strategy] Cache read failed, fetching fresh: #{e.message}")
          end
        end

        # Fetch from URL
        OmniauthOpenidFederation::Logger.info("[Strategy] Fetching provider entity statement from: #{url}")
        begin
          statement = OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
            url,
            fingerprint: fingerprint,
            timeout: 10
          )

          entity_statement_content = statement.entity_statement

          # Cache the fetched statement (if Rails.cache is available)
          if defined?(Rails) && Rails.cache
            begin
              # Cache for 1 hour (entity statements typically expire after 24 hours)
              Rails.cache.write(cache_key, entity_statement_content, expires_in: 3600)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Cached provider entity statement from: #{url}")
            rescue => e
              OmniauthOpenidFederation::Logger.debug("[Strategy] Cache write failed: #{e.message}")
            end
          end

          entity_statement_content
        rescue OmniauthOpenidFederation::FetchError, OmniauthOpenidFederation::ValidationError => e
          error_msg = "Failed to fetch provider entity statement from #{url}: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end
      end

      # Resolve endpoints from trust chain (for federation scenarios)
      #
      # @param issuer_entity_id [String] Entity Identifier of the OP
      # @param client_options_hash [Hash] Current client options
      # @return [Hash] Hash with resolved endpoints from effective metadata
      def resolve_endpoints_from_trust_chain(issuer_entity_id, client_options_hash)
        OmniauthOpenidFederation::Logger.debug("[Strategy] Resolving endpoints from trust chain for: #{issuer_entity_id}")

        begin
          # Resolve trust chain
          resolver = OmniauthOpenidFederation::Federation::TrustChainResolver.new(
            leaf_entity_id: issuer_entity_id,
            trust_anchors: normalize_trust_anchors(options.trust_anchors)
          )
          trust_chain = resolver.resolve!

          # Extract metadata from leaf entity configuration
          leaf_statement = trust_chain.first
          leaf_parsed = leaf_statement.is_a?(Hash) ? leaf_statement : leaf_statement.parse
          leaf_metadata = extract_metadata_from_parsed(leaf_parsed)

          # Merge metadata policies
          merger = OmniauthOpenidFederation::Federation::MetadataPolicyMerger.new(trust_chain: trust_chain)
          effective_metadata = merger.merge_and_apply(leaf_metadata)

          # Extract OP metadata from effective metadata
          op_metadata = effective_metadata[:openid_provider] || effective_metadata["openid_provider"] || {}

          # Build resolved endpoints hash
          resolved = {}
          resolved[:authorization_endpoint] = op_metadata[:authorization_endpoint] || op_metadata["authorization_endpoint"]
          resolved[:token_endpoint] = op_metadata[:token_endpoint] || op_metadata["token_endpoint"]
          resolved[:userinfo_endpoint] = op_metadata[:userinfo_endpoint] || op_metadata["userinfo_endpoint"]
          resolved[:jwks_uri] = op_metadata[:jwks_uri] || op_metadata["jwks_uri"]
          resolved[:issuer] = op_metadata[:issuer] || op_metadata["issuer"] || issuer_entity_id
          resolved[:audience] = resolved[:issuer] # Audience is typically the issuer

          OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved endpoints from trust chain: #{resolved.keys.join(", ")}")
          resolved
        rescue OmniauthOpenidFederation::ValidationError, OmniauthOpenidFederation::FetchError => e
          OmniauthOpenidFederation::Logger.error("[Strategy] Trust chain resolution failed: #{e.message}")
          # Fall back to direct entity statement
          {}
        end
      end

      # Extract metadata from parsed entity statement
      #
      # @param parsed [Hash] Parsed entity statement
      # @return [Hash] Metadata hash by entity type
      def extract_metadata_from_parsed(parsed)
        metadata = parsed[:metadata] || parsed["metadata"] || {}
        # Ensure it's a hash with entity type keys
        result = {}
        metadata.each do |entity_type, entity_metadata|
          result[entity_type.to_sym] = entity_metadata
        end
        result
      end

      # Normalize trust anchors configuration
      #
      # @param trust_anchors [Array] Trust anchor configurations
      # @return [Array] Normalized trust anchor configurations
      def normalize_trust_anchors(trust_anchors)
        trust_anchors.map do |ta|
          {
            entity_id: ta[:entity_id] || ta["entity_id"],
            jwks: ta[:jwks] || ta["jwks"]
          }
        end
      end

      # Check if a string is an Entity ID (URI)
      #
      # @param str [String] String to check
      # @return [Boolean] true if string is an Entity ID
      def is_entity_id?(str)
        str.is_a?(String) && str.start_with?("http://", "https://")
      end

      # Resolve entity statement path (relative to Rails root if available)
      #
      # @param path [String] Entity statement path
      # @return [String] Absolute path
      def resolve_entity_statement_path(path)
        if path.start_with?("/")
          path
        elsif defined?(Rails) && Rails.root
          Rails.root.join(path).to_s
        else
          File.expand_path(path)
        end
      end

      # Used to extract signing/encryption keys from metadata JWKS
      #
      # @return [Hash, nil] Metadata hash or nil if not available
      def load_metadata_for_key_extraction
        entity_statement_content = load_provider_entity_statement
        return nil unless entity_statement_content

        begin
          # Parse entity statement to extract metadata and JWKS from content
          parsed = OmniauthOpenidFederation::Federation::EntityStatementHelper.parse_for_signed_jwks_from_content(
            entity_statement_content
          )

          return nil unless parsed && parsed[:metadata]

          # Return metadata in format expected by KeyExtractor
          # KeyExtractor expects metadata hash that may contain JWKS
          metadata = parsed[:metadata]
          entity_jwks = parsed[:entity_jwks] || metadata[:jwks] || {}

          # Return metadata with JWKS included
          metadata.merge(jwks: entity_jwks)
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to load metadata from entity statement for key extraction: #{e.message}")
          nil
        end
      end

      # Load client entity statement from file or generate dynamically with caching
      # Priority:
      # 1. File path (if provided) - for manual cache, development, debugging
      # 2. Cache (if available) - respects cache TTL and background job refresh
      # 3. Generate dynamically - always available via FederationEndpoint
      # Note: URL is for external consumers only - we never access it ourselves
      #
      # @param entity_statement_path [String, nil] Path to client entity statement file (optional, for manual cache/dev/debug)
      # @param entity_statement_url [String, nil] URL to client entity statement (for external consumers only, never accessed)
      # @return [String] The entity statement JWT string
      # @raise [ConfigurationError] If entity statement cannot be loaded or generated
      def load_client_entity_statement(entity_statement_path = nil, entity_statement_url = nil)
        # Priority 1: Use file path if provided (for manual cache, development, debugging)
        if OmniauthOpenidFederation::StringHelpers.present?(entity_statement_path)
          return load_client_entity_statement_from_file(entity_statement_path)
        end

        # Priority 2: Check cache (if Rails.cache is available)
        # This respects background job cache refresh and key rotation
        if defined?(Rails) && Rails.cache
          cache_key = "federation:entity_statement"
          config = OmniauthOpenidFederation::FederationEndpoint.configuration

          # Use cache TTL based on entity statement expiration or default to 1 hour
          # The entity statement JWT itself has an expiration, but we cache it for performance
          # Cache TTL should be shorter than JWT expiration to ensure fresh keys
          cache_ttl = config.jwks_cache_ttl || 3600 # Default to 1 hour, same as JWKS cache

          begin
            cached_statement = Rails.cache.fetch(cache_key, expires_in: cache_ttl) do
              # Generate and cache if not in cache
              entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
              OmniauthOpenidFederation::Logger.debug("[Strategy] Generated and cached client entity statement")
              entity_statement
            end

            if cached_statement
              OmniauthOpenidFederation::Logger.debug("[Strategy] Using cached client entity statement")
              return cached_statement
            end
          rescue => e
            OmniauthOpenidFederation::Logger.warn("[Strategy] Cache fetch failed, generating fresh entity statement: #{e.message}")
            # Fall through to generate dynamically
          end
        end

        # Priority 3: Generate dynamically (always available)
        # The entity statement is always generated via FederationEndpoint
        begin
          entity_statement = OmniauthOpenidFederation::FederationEndpoint.generate_entity_statement
          OmniauthOpenidFederation::Logger.debug("[Strategy] Generated client entity statement dynamically")
          entity_statement
        rescue OmniauthOpenidFederation::ConfigurationError => e
          # FederationEndpoint not configured - provide helpful error message
          error_msg = "Failed to generate client entity statement: #{e.message}. " \
                      "Either configure OmniauthOpenidFederation::FederationEndpoint.configure " \
                      "or provide client_entity_statement_path for manual cache/dev/debug."
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        rescue => e
          error_msg = "Failed to generate client entity statement: #{e.message}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end
      end

      # Load client entity statement from file
      #
      # @param entity_statement_path [String] Path to client entity statement file
      # @return [String] The entity statement JWT string
      # @raise [ConfigurationError] If entity statement cannot be loaded
      def load_client_entity_statement_from_file(entity_statement_path)
        # Resolve path (relative to Rails root if available)
        path = if entity_statement_path.start_with?("/")
          entity_statement_path
        elsif defined?(Rails) && Rails.root
          Rails.root.join(entity_statement_path).to_s
        else
          File.expand_path(entity_statement_path)
        end

        unless File.exist?(path)
          error_msg = "Client entity statement file not found: #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement = File.read(path)
        unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement)
          error_msg = "Client entity statement file is empty: #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        # Validate it's a JWT (has 3 parts)
        jwt_parts = entity_statement.strip.split(".")
        unless jwt_parts.length == 3
          error_msg = "Client entity statement is not a valid JWT (expected 3 parts, got #{jwt_parts.length}): #{path}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement.strip
      end

      # Load client entity statement from URL (for dynamic federation endpoints)
      #
      # @param entity_statement_url [String] URL to client entity statement
      # @return [String] The entity statement JWT string
      # @raise [ConfigurationError] If entity statement cannot be loaded
      def load_client_entity_statement_from_url(entity_statement_url)
        response = HttpClient.get(entity_statement_url)
        unless response.status.success?
          error_msg = "Failed to fetch client entity statement from #{entity_statement_url}: HTTP #{response.status}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement = response.body.to_s
        unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement)
          error_msg = "Client entity statement from URL is empty: #{entity_statement_url}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        # Validate it's a JWT (has 3 parts)
        jwt_parts = entity_statement.strip.split(".")
        unless jwt_parts.length == 3
          error_msg = "Client entity statement from URL is not a valid JWT (expected 3 parts, got #{jwt_parts.length}): #{entity_statement_url}"
          OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
          raise OmniauthOpenidFederation::ConfigurationError, error_msg
        end

        entity_statement.strip
      rescue OmniauthOpenidFederation::NetworkError => e
        error_msg = "Failed to fetch client entity statement from #{entity_statement_url}: #{e.message}"
        OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
        raise OmniauthOpenidFederation::ConfigurationError, error_msg
      end

      # Extract JWKS from client entity statement for client_jwk_signing_key
      # According to OpenID Federation spec, client JWKS should come from client entity statement
      # Entity statement is either loaded from file (if provided) or generated dynamically
      #
      # @return [String, nil] JWKS as JSON string, or nil if not available
      def extract_client_jwk_signing_key
        # Access raw options hash to avoid recursion (don't call options method which triggers extraction)
        raw_opts = @options || {}

        # If explicit JWKS is provided, use it
        return raw_opts[:client_jwk_signing_key] if OmniauthOpenidFederation::StringHelpers.present?(raw_opts[:client_jwk_signing_key])

        # Entity statement is always available (either from file or generated dynamically)
        begin
          entity_statement_content = load_client_entity_statement(
            raw_opts[:client_entity_statement_path],
            raw_opts[:client_entity_statement_url]
          )
          return nil unless OmniauthOpenidFederation::StringHelpers.present?(entity_statement_content)

          # Extract JWKS from client entity statement
          jwt_parts = entity_statement_content.split(".")
          return nil if jwt_parts.length != 3

          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          entity_jwks = payload.fetch("jwks", {})
          return nil if entity_jwks.empty?

          # Return JWKS as JSON string (format expected by openid_connect gem)
          JSON.dump(entity_jwks)
        rescue => e
          OmniauthOpenidFederation::Logger.warn("[Strategy] Failed to extract client JWKS from entity statement: #{e.message}")
          nil
        end
      end

      # Extract entity identifier from client entity statement
      # For automatic registration, the client_id is the entity identifier (sub claim)
      #
      # @param entity_statement [String] The entity statement JWT string
      # @param configured_identifier [String, nil] Manually configured entity identifier (takes precedence)
      # @return [String, nil] The entity identifier (sub claim) or configured identifier
      def extract_entity_identifier_from_statement(entity_statement, configured_identifier = nil)
        # Use configured identifier if provided
        return configured_identifier if OmniauthOpenidFederation::StringHelpers.present?(configured_identifier)

        # Extract from entity statement
        begin
          jwt_parts = entity_statement.split(".")
          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          entity_identifier = payload["sub"] || payload[:sub]
          return entity_identifier if OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)

          # Fallback to issuer if sub is not present
          entity_identifier = payload["iss"] || payload[:iss]
          return entity_identifier if OmniauthOpenidFederation::StringHelpers.present?(entity_identifier)

          OmniauthOpenidFederation::Logger.warn("[Strategy] Could not extract entity identifier from entity statement (no 'sub' or 'iss' claim)")
          nil
        rescue => e
          OmniauthOpenidFederation::Logger.error("[Strategy] Failed to extract entity identifier from entity statement: #{e.message}")
          nil
        end
      end

      # Load provider metadata from entity statement for request object encryption
      # According to OpenID Connect Core spec, provider metadata may specify
      # request_object_encryption_alg and request_object_encryption_enc
      #
      # @return [Hash, nil] Provider metadata hash with encryption parameters and JWKS, or nil if not available
      def load_provider_metadata_for_encryption
        entity_statement_content = load_provider_entity_statement
        return nil unless entity_statement_content

        begin
          # Decode entity statement payload to get all provider metadata fields
          # EntityStatement.parse only extracts specific fields, so we need to access raw payload
          jwt_parts = entity_statement_content.split(".")
          return nil if jwt_parts.length != 3

          payload = JSON.parse(Base64.urlsafe_decode64(jwt_parts[1]))
          metadata_section = payload.fetch("metadata", {})
          provider_metadata = metadata_section.fetch("openid_provider", {})
          entity_jwks = payload.fetch("jwks", {})

          # Combine provider metadata with entity JWKS for encryption
          # Note: Provider's encryption requirements would be in their discovery document,
          # but we can also check client metadata as a fallback
          {
            "request_object_encryption_alg" => provider_metadata["request_object_encryption_alg"] ||
              provider_metadata[:request_object_encryption_alg],
            "request_object_encryption_enc" => provider_metadata["request_object_encryption_enc"] ||
              provider_metadata[:request_object_encryption_enc],
            "jwks" => entity_jwks
          }
        rescue => e
          OmniauthOpenidFederation::Logger.debug("[Strategy] Could not load provider metadata for encryption: #{e.message}")
          nil
        end
      end

      def fetch_jwks(jwks_uri)
        # Use our JWKS fetching logic
        # Returns a hash with "keys" array that JWT.decode can use directly
        jwks = OmniauthOpenidFederation::Jwks::Fetch.run(jwks_uri)

        # Ensure it's in the format expected by JWT.decode (hash with "keys" array)
        if jwks.is_a?(Hash) && jwks.key?("keys")
          # Already in correct format - JWT.decode accepts this directly
          jwks
        elsif jwks.is_a?(Array)
          # If it's an array of keys, wrap it in a hash
          {"keys" => jwks}
        else
          # Fallback: wrap in keys array
          {"keys" => [jwks].compact}
        end
      end
    end
  end
end
