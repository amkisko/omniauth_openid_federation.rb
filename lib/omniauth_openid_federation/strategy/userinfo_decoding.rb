module OmniauthOpenidFederation
  module Strategy
    module UserinfoDecoding
      private

      def decode_userinfo(userinfo)
        if userinfo.is_a?(String)
          if encrypted_token?(userinfo)
            client_options_hash = options.client_options || {}
            normalized_options = OmniauthOpenidFederation::Validators.normalize_hash(client_options_hash)

            decryption_key_source = options.decryption_key_source || options.key_source || :local
            private_key = normalized_options[:private_key]
            jwks = normalized_options[:jwks] || normalized_options["jwks"]
            metadata = load_metadata_for_key_extraction

            encryption_key = if decryption_key_source == :federation
              OmniauthOpenidFederation::KeyExtractor.extract_encryption_key(
                jwks: jwks,
                metadata: metadata,
                private_key: private_key
              ) || private_key
            else
              private_key
            end

            OmniauthOpenidFederation::Validators.validate_private_key!(encryption_key)

            begin
              userinfo_string = OmniauthOpenidFederation::Jwe.decrypt(userinfo, encryption_key)
              OmniauthOpenidFederation::Logger.debug("[Strategy] Successfully decrypted userinfo using encryption key")
              JSON.parse(userinfo_string)
            rescue => e
              error_msg = "Failed to decrypt userinfo: #{e.class} - #{e.message}"
              OmniauthOpenidFederation::Logger.error("[Strategy] #{error_msg}")
              OmniauthOpenidFederation::Instrumentation.notify_decryption_failed(
                token_type: "userinfo",
                error_message: e.message,
                error_class: e.class.name
              )
              raise OmniauthOpenidFederation::DecryptionError, error_msg, e.backtrace
            end
          else
            JSON.parse(userinfo)
          end
        elsif userinfo.is_a?(Hash)
          userinfo
        elsif userinfo.respond_to?(:raw_attributes)
          userinfo.raw_attributes || {}
        elsif userinfo.respond_to?(:as_json)
          userinfo.as_json(skip_validation: true)
        else
          userinfo.instance_variables.each_with_object({}) do |var, hash|
            key = var.to_s.delete_prefix("@").to_sym
            hash[key] = userinfo.instance_variable_get(var)
          end
        end
      end
    end
  end
end
