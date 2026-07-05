require "openssl"

module OmniauthOpenidFederation
  module SecureCompare
    module_function

    def secure_compare(left, right)
      left = left.to_s
      right = right.to_s
      return false unless left.bytesize == right.bytesize

      OpenSSL.fixed_length_secure_compare(left, right)
    end
  end
end
