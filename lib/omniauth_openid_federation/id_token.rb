module OmniauthOpenidFederation
  class IdToken
    CLAIM_READERS = %i[iss sub aud exp iat nonce acr auth_time amr].freeze

    attr_reader :raw_attributes

    def initialize(raw_attributes)
      @raw_attributes = raw_attributes.each_with_object({}) do |(key, value), claims|
        claims[key.to_sym] = value
      end
    end

    CLAIM_READERS.each do |claim_name|
      define_method(claim_name) do
        raw_attributes[claim_name]
      end
    end
  end
end
