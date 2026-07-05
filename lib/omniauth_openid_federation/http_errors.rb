module OmniauthOpenidFederation
  class HttpError < Error
    attr_reader :response

    def initialize(status, message = nil, response = nil)
      @response = response
      super(message || "HTTP error #{status}")
    end
  end

  class BadRequest < HttpError; end
  class Unauthorized < HttpError; end
  class Forbidden < HttpError; end
end
