module OmniauthOpenidFederation
  module Strategy
    module ClientConstruction
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

      def oidc_client
        client
      end
    end
  end
end
