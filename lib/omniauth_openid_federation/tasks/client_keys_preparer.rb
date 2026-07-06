require "json"
require "fileutils"
require "openssl"
require_relative "../utils"
require_relative "path_resolver"

module OmniauthOpenidFederation
  module Tasks
    module ClientKeysPreparer
      def self.prepare(key_type:, output_dir:)
        unless %w[single separate].include?(key_type)
          raise ArgumentError, "Invalid key_type: #{key_type}. Valid options: 'single' or 'separate'"
        end

        output_path = PathResolver.resolve(output_dir)

        # Create output directory if it doesn't exist
        FileUtils.mkdir_p(output_path) unless File.directory?(output_path)

        result = if key_type == "single"
          generate_single_key(output_path)
        else
          generate_separate_keys(output_path)
        end

        {
          success: true,
          output_path: output_path,
          **result
        }
      end

      def self.generate_single_key(output_path)
        private_key = OpenSSL::PKey::RSA.new(2048)
        jwk_hash = Utils.rsa_key_to_jwk(private_key, use: "sig")

        # Remove private key components and 'use' field for backward compatibility
        public_jwk = jwk_hash.reject { |k, _v| %w[d p q dp dq qi use].include?(k.to_s) }
        jwks = {keys: [public_jwk]}

        # Save private key
        private_key_path = File.join(output_path, "client-private-key.pem")
        File.write(private_key_path, private_key.to_pem)
        File.chmod(0o600, private_key_path)

        # Save public JWKS
        public_jwks_path = File.join(output_path, "client-jwks.json")
        File.write(public_jwks_path, JSON.pretty_generate(jwks))

        {
          private_key_path: private_key_path,
          public_jwks_path: public_jwks_path,
          jwks: jwks
        }
      end

      def self.generate_separate_keys(output_path)
        signing_private_key = OpenSSL::PKey::RSA.new(2048)
        encryption_private_key = OpenSSL::PKey::RSA.new(2048)

        signing_jwk_hash = Utils.rsa_key_to_jwk(signing_private_key, use: "sig")
        encryption_jwk_hash = Utils.rsa_key_to_jwk(encryption_private_key, use: "enc")

        # Remove private key components and add 'use' field
        signing_public_jwk = signing_jwk_hash.reject { |k, _v| %w[d p q dp dq qi].include?(k.to_s) }.merge("use" => "sig")
        encryption_public_jwk = encryption_jwk_hash.reject { |k, _v| %w[d p q dp dq qi].include?(k.to_s) }.merge("use" => "enc")

        jwks = {keys: [signing_public_jwk, encryption_public_jwk]}

        # Save private keys
        signing_key_path = File.join(output_path, "client-signing-private-key.pem")
        encryption_key_path = File.join(output_path, "client-encryption-private-key.pem")

        File.write(signing_key_path, signing_private_key.to_pem)
        File.write(encryption_key_path, encryption_private_key.to_pem)
        File.chmod(0o600, signing_key_path)
        File.chmod(0o600, encryption_key_path)

        # Save public JWKS
        public_jwks_path = File.join(output_path, "client-jwks.json")
        File.write(public_jwks_path, JSON.pretty_generate(jwks))

        {
          signing_key_path: signing_key_path,
          encryption_key_path: encryption_key_path,
          public_jwks_path: public_jwks_path,
          jwks: jwks
        }
      end

      class << self
        private :generate_single_key, :generate_separate_keys
      end
    end
  end
end
