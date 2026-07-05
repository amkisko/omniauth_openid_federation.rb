module OmniauthOpenidFederation
  module Strategy
    module AuthorizationRequest
      def authorize_uri
        validate_provider_trust_configuration!

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

        if options.default_request_object_claims.is_a?(Hash)
          options.default_request_object_claims.each do |key, value|
            key_str = key.to_s
            next if key_str.length > 256
            next if OmniauthOpenidFederation::StringHelpers.blank?(value)
            request_params[key_str] ||= value
          end
        end

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

        request_object_claims = request_params.dup
        request_object_claims["acr_values"] = normalized_acr_values if normalized_acr_values
        request_object_claims["ui_locales"] = validated_ui_locales if validated_ui_locales
        request_object_claims["claims_locales"] = validated_claims_locales if validated_claims_locales
        request_object_claims["login_hint"] = validated_login_hint if validated_login_hint
        OmniauthOpenidFederation::Validators.validate_required_request_object_claims!(
          request_object_claims,
          options.required_request_object_claims
        )

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

      def validate_provider_trust_configuration!
        return unless options.require_entity_statement_fingerprint

        using_remote_source = OmniauthOpenidFederation::StringHelpers.present?(options.entity_statement_url) ||
          OmniauthOpenidFederation::StringHelpers.present?(options.issuer)
        return unless using_remote_source

        if OmniauthOpenidFederation::StringHelpers.blank?(options.entity_statement_fingerprint)
          raise OmniauthOpenidFederation::ConfigurationError,
            "entity_statement_fingerprint is required when require_entity_statement_fingerprint is enabled"
        end
      end
    end
  end
end
