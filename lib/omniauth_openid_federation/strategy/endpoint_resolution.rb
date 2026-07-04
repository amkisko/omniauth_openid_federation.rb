module OmniauthOpenidFederation
  module Strategy
    module EndpointResolution
      private

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

      def resolve_endpoints_from_trust_chain(issuer_entity_id, client_options_hash)
        OmniauthOpenidFederation::Logger.debug("[Strategy] Resolving endpoints from trust chain for: #{issuer_entity_id}")

        resolver = OmniauthOpenidFederation::Federation::TrustChainResolver.new(
          leaf_entity_id: issuer_entity_id,
          trust_anchors: normalize_trust_anchors(options.trust_anchors)
        )
        trust_chain = resolver.resolve!

        leaf_statement = trust_chain.first
        leaf_parsed = leaf_statement.is_a?(Hash) ? leaf_statement : leaf_statement.parse
        leaf_metadata = extract_metadata_from_parsed(leaf_parsed)

        merger = OmniauthOpenidFederation::Federation::MetadataPolicyMerger.new(trust_chain: trust_chain)
        effective_metadata = merger.merge_and_apply(leaf_metadata)

        op_metadata = effective_metadata[:openid_provider] || effective_metadata["openid_provider"] || {}

        resolved = {}
        resolved[:authorization_endpoint] = op_metadata[:authorization_endpoint] || op_metadata["authorization_endpoint"]
        resolved[:token_endpoint] = op_metadata[:token_endpoint] || op_metadata["token_endpoint"]
        resolved[:userinfo_endpoint] = op_metadata[:userinfo_endpoint] || op_metadata["userinfo_endpoint"]
        resolved[:jwks_uri] = op_metadata[:jwks_uri] || op_metadata["jwks_uri"]
        resolved[:issuer] = op_metadata[:issuer] || op_metadata["issuer"] || issuer_entity_id
        resolved[:audience] = resolved[:issuer]

        OmniauthOpenidFederation::Logger.debug("[Strategy] Resolved endpoints from trust chain: #{resolved.keys.join(", ")}")
        resolved
      end

      def extract_metadata_from_parsed(parsed)
        metadata = parsed[:metadata] || parsed["metadata"] || {}
        # Ensure it's a hash with entity type keys
        result = {}
        metadata.each do |entity_type, entity_metadata|
          result[entity_type.to_sym] = entity_metadata
        end
        result
      end

      def normalize_trust_anchors(trust_anchors)
        trust_anchors.map do |ta|
          {
            entity_id: ta[:entity_id] || ta["entity_id"],
            jwks: ta[:jwks] || ta["jwks"]
          }
        end
      end

      def is_entity_id?(str)
        str.is_a?(String) && str.start_with?("http://", "https://")
      end
    end
  end
end
