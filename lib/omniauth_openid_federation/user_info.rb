module OmniauthOpenidFederation
  class UserInfo
    attr_reader :raw_attributes

    def initialize(raw_attributes)
      @raw_attributes = raw_attributes.each_with_object({}) do |(key, value), claims|
        claims[key.to_sym] = value
      end
    end

    def as_json(_options = {})
      raw_attributes.transform_keys(&:to_s)
    end
  end
end
