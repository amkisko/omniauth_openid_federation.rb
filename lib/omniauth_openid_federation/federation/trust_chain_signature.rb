module OmniauthOpenidFederation
  module Federation
    module TrustChainSignature
      private

      def verify_entity_statement_signature!(statement, issuer_config)
        jwt_string = statement.entity_statement
        kid, algorithm = signature_header(jwt_string)
        public_key = signing_public_key(statement, issuer_config, kid)
        ::JWT.decode(jwt_string, public_key, true, {algorithm: algorithm})
      rescue ::JWT::DecodeError, ::JWT::VerificationError => e
        error_msg = "Entity statement signature validation failed: #{e.class} - #{e.message}"
        OmniauthOpenidFederation::Logger.error("[TrustChainResolver] #{error_msg}")
        raise SignatureError, error_msg, e.backtrace
      end

      def signature_header(jwt_string)
        parts = jwt_string.split(".")
        if parts.length != EntityStatementValidator::JWT_PARTS_COUNT
          raise ValidationError, "Invalid JWT format: expected #{EntityStatementValidator::JWT_PARTS_COUNT} parts, got #{parts.length}"
        end

        header = JSON.parse(Base64.urlsafe_decode64(parts[0]))
        kid = field(header, :kid)
        algorithm = field(header, :alg) || "RS256"

        unless EntityStatementValidator::SUPPORTED_ALGORITHMS.include?(algorithm)
          raise ValidationError, "Unsupported entity statement algorithm: #{algorithm}"
        end

        [kid, algorithm]
      end

      def signing_public_key(statement, issuer_config, kid)
        signing_keys = issuer_signing_keys(statement, issuer_config)
        keys = field(signing_keys, :keys) || []
        signing_key_data = keys.find { |key| field(key, :kid) == kid }
        unless signing_key_data
          raise ValidationError, "Signing key with kid '#{kid}' not found in issuer JWKS for signature verification"
        end

        OmniauthOpenidFederation::KeyExtractor.jwk_to_openssl_key(signing_key_data)
      end

      def issuer_signing_keys(statement, issuer_config)
        parsed = (issuer_config || statement).parse
        trust_anchor = trust_anchor_for(entity_issuer(parsed))
        return normalize_jwks(trust_anchor[:jwks]) if trust_anchor

        field(parsed, :jwks) || {}
      end

      def entity_issuer(parsed)
        parsed[:issuer] || parsed[:iss] || parsed["issuer"] || parsed["iss"]
      end

      def field(hash, key)
        hash[key] || hash[key.to_s]
      end
    end
  end
end
