require "json"
require_relative "string_helpers"
require_relative "logger"
require_relative "validators"
require_relative "utils"
require_relative "http_errors"
require_relative "jwt_response_decoder"

module OmniauthOpenidFederation
  class AccessToken
    attr_reader :access_token, :refresh_token, :expires_in, :id_token, :client

    def initialize(access_token:, client:, refresh_token: nil, expires_in: nil, id_token: nil,
      strategy_options: nil, oauth_token: nil)
      @access_token = access_token
      @refresh_token = refresh_token
      @expires_in = expires_in
      @id_token = id_token
      @client = client
      @strategy_options = strategy_options
      @oauth_token = oauth_token
    end

    def self.from_oauth2_token(oauth_token, strategy_options: nil)
      token_params = oauth_token.params || {}
      id_token_value = token_params["id_token"] || token_params[:id_token]

      new(
        access_token: oauth_token.token,
        refresh_token: oauth_token.refresh_token,
        expires_in: oauth_token.expires_in,
        id_token: id_token_value,
        client: oauth_token.client,
        strategy_options: strategy_options,
        oauth_token: oauth_token
      )
    end

    def userinfo!(params = {}, http_method: :get, headers: {})
      unless [:get, :post].include?(http_method)
        raise ArgumentError, "http_method must be :get or :post"
      end

      endpoint = client.userinfo_endpoint
      unless OmniauthOpenidFederation::StringHelpers.present?(endpoint)
        raise ConfigurationError, "Userinfo endpoint not configured"
      end

      unless @oauth_token
        raise ConfigurationError, "OAuth token reference not available for userinfo request"
      end

      response = case http_method
      when :get
        @oauth_token.get(endpoint.to_s, params: params, headers: headers)
      when :post
        @oauth_token.post(
          endpoint.to_s,
          body: params,
          headers: headers.merge("Content-Type" => "application/x-www-form-urlencoded")
        )
      end

      claims = parse_userinfo_response(response)
      OmniauthOpenidFederation::UserInfo.new(claims)
    end

    def decode_response_body(body)
      JwtResponseDecoder.new(strategy_options: get_strategy_options, client: client).decode(body)
    end

    private

    def parse_userinfo_response(response)
      body = response.respond_to?(:parsed) ? response.parsed : nil
      if body.is_a?(Hash)
        return body
      end

      body_text =
        if body.is_a?(String) && OmniauthOpenidFederation::StringHelpers.present?(body)
          body
        elsif response.respond_to?(:body)
          response.body.to_s
        else
          ""
        end

      return {} if OmniauthOpenidFederation::StringHelpers.blank?(body_text)

      decode_response_body(body_text)
    rescue JSON::ParserError => error
      raise ValidationError, "Failed to parse userinfo response: #{error.message}", error.backtrace
    end

    public

    def resource_request
      res = yield
      status_code = if res.status.is_a?(Integer)
        res.status
      else
        (res.status.respond_to?(:code) ? res.status.code : res.status)
      end
      case status_code
      when 200
        decode_response_body(res.body)
      when 400
        raise BadRequest.new("API Access Faild", res)
      when 401
        raise Unauthorized.new("Access Token Invalid or Expired", res)
      when 403
        raise Forbidden.new("Insufficient Scope", res)
      else
        raise HttpError.new(res.status, "Unknown HttpError", res)
      end
    end

    private

    def get_strategy_options
      if @strategy_options.is_a?(Hash)
        return @strategy_options
      end

      if respond_to?(:client) && client
        strategy_options = client.instance_variable_get(:@strategy_options)
        return strategy_options if strategy_options&.is_a?(Hash)
      end

      if respond_to?(:client) && client
        client_options = {}
        client_options[:jwks_uri] = client.jwks_uri.to_s if client.respond_to?(:jwks_uri) && client.jwks_uri
        client_options[:private_key] = client.private_key if client.respond_to?(:private_key) && client.private_key

        return {
          client_options: client_options
        }
      end

      OmniauthOpenidFederation::Logger.warn("[AccessToken] Could not determine strategy options from client. Some features may not work correctly.")
      {}
    end
  end
end
