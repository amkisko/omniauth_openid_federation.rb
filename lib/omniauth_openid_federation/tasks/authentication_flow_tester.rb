require "uri"
require_relative "../http_client"
require_relative "../string_helpers"
require_relative "../jwe"

module OmniauthOpenidFederation
  module Tasks
    module AuthenticationFlowTester
    def self.run(
      login_page_url:,
      base_url:,
      provider_acr: nil
    )
      require "uri"
      require "cgi"
      require "json"
      require "base64"

      results = {
        steps_completed: [],
        errors: [],
        warnings: [],
        csrf_token: nil,
        cookies: [],
        authorization_url: nil,
        instructions: []
      }

      results[:steps_completed] << "fetch_csrf_token"

      html_body = nil
      cookie_header = nil
      csrf_token = nil
      cookies = []

      begin
        login_response = HttpClient.get(
          login_page_url,
          connect_timeout: 10,
          read_timeout: 10,
          max_retries: 0
        )

        unless login_response.status.success?
          raise "Failed to fetch login page: #{login_response.status.code} #{login_response.status.reason}"
        end

        # Extract cookies
        set_cookie_headers = login_response.headers["Set-Cookie"]
        if set_cookie_headers
          cookie_list = set_cookie_headers.is_a?(Array) ? set_cookie_headers : [set_cookie_headers]
          cookie_list.each do |set_cookie|
            cookie_str = set_cookie.to_s
            # Security: Limit cookie header size to prevent DoS attacks (max 4KB per cookie)
            next if cookie_str.length > 4096
            # Security: Use non-greedy matching with length limits to prevent ReDoS
            cookie_match = cookie_str.match(/^([^=]{1,256})=([^;]{1,4096})/)
            cookies << "#{cookie_match[1]}=#{cookie_match[2]}" if cookie_match
          end
        end

        cookie_header = cookies.join("; ")

        # Extract CSRF token from HTML
        html_body = login_response.body.to_s

        # Security: Limit HTML body size to prevent DoS attacks (max 1MB)
        if html_body.bytesize > 1_048_576
          raise "HTML response too large (#{html_body.bytesize} bytes), possible DoS attack"
        end

        # Try meta tag first
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        csrf_meta_match = html_body.match(/<meta\s+name=["']csrf-token["']\s+content=["']([^"']{1,256})["']/i)
        csrf_token = csrf_meta_match[1] if csrf_meta_match

        # Try form input if not found
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        unless csrf_token
          csrf_input_match = html_body.match(/<input[^>]*name=["']authenticity_token["'][^>]*value=["']([^"']{1,256})["']/i)
          csrf_token = csrf_input_match[1] if csrf_input_match
        end

        unless csrf_token
          raise "Failed to extract CSRF token from login page"
        end

        results[:csrf_token] = csrf_token
        results[:cookies] = cookies
        results[:steps_completed] << "extract_csrf_and_cookies"
      rescue => e
        results[:errors] << "Step 1 (CSRF token): #{e.message}"
        raise
      end

      # Step 2: Find authorization form/button in HTML
      results[:steps_completed] << "find_authorization_form"

      begin
        # Try to find form with action containing "openid_federation"
        # Security: Use non-greedy matching and limit capture group to prevent ReDoS
        form_match = html_body.match(/<form[^>]*action=["']([^"']{0,2048}openid[_-]?federation[^"']{0,2048})["'][^>]*>/i)
        auth_endpoint = nil

        if form_match
          form_action = form_match[1]
          # Note: Rake tasks are developer tools, no security validation needed
          begin
            auth_endpoint = if form_action.start_with?("http://", "https://")
              URI.parse(form_action).to_s
            else
              URI.join(base_url, form_action).to_s
            end
          rescue URI::InvalidURIError => e
            raise "Invalid form action URI: #{e.message}"
          end
        else
          # Try to find button/link with href containing "openid_federation"
          # Security: Use non-greedy matching and limit capture group to prevent ReDoS
          button_match = html_body.match(/<a[^>]*href=["']([^"']{0,2048}openid[_-]?federation[^"']{0,2048})["'][^>]*>/i)
          if button_match
            button_href = button_match[1]
            # Note: Rake tasks are developer tools, no security validation needed
            begin
              auth_endpoint = if button_href.start_with?("http://", "https://")
                URI.parse(button_href).to_s
              else
                URI.join(base_url, button_href).to_s
              end
            rescue URI::InvalidURIError => e
              raise "Invalid button href URI: #{e.message}"
            end
          else
            # Fallback: try common paths
            common_paths = [
              "/users/auth/openid_federation",
              "/auth/openid_federation",
              "/openid_federation"
            ]
            auth_endpoint = nil
            common_paths.each do |path|
              test_url = URI.join(base_url, path).to_s
              begin
                test_response = HttpClient.get(
                  test_url,
                  connect_timeout: 5,
                  read_timeout: 5,
                  max_retries: 0
                )
                if test_response.status.code >= 300 && test_response.status.code < 400
                  auth_endpoint = test_url
                  break
                end
              rescue
                # Continue to next path
              end
            end
            auth_endpoint ||= URI.join(base_url, "/users/auth/openid_federation").to_s
          end
        end

        results[:auth_endpoint] = auth_endpoint
        results[:steps_completed] << "resolve_auth_endpoint"
      rescue => e
        results[:errors] << "Step 2 (Find authorization form): #{e.message}"
        raise
      end

      # Step 3: Request authorization URL
      results[:steps_completed] << "request_authorization"

      begin
        headers = {
          "X-CSRF-Token" => csrf_token,
          "X-Requested-With" => "XMLHttpRequest",
          "Referer" => login_page_url
        }
        headers["Cookie"] = cookie_header unless cookie_header.empty?

        form_data = {}
        # Include acr_values if provided (must be configured in request_object_params to be included in JWT)
        form_data[:acr_values] = provider_acr if StringHelpers.present?(provider_acr)

        auth_response = HttpClient.post(
          auth_endpoint,
          connect_timeout: 10,
          read_timeout: 10,
          max_retries: 0,
          headers: headers,
          form: form_data
        )

        authorization_url = nil

        if auth_response.status.code >= 300 && auth_response.status.code < 400
          location = auth_response.headers["Location"]
          if location
            # Security: Validate location header
            if location.length > 2048
              raise "Location header exceeds maximum length"
            end
            authorization_url = if location.start_with?("http://", "https://")
              # Note: Rake tasks are developer tools, no security validation needed
              location
            else
              URI.join(base_url, location).to_s
            end
          end
        elsif auth_response.status.code == 200
          authorization_url = auth_response.headers["Location"] || auth_response.body.to_s
          authorization_url = nil unless authorization_url&.start_with?("http")
        end

        unless authorization_url
          raise "Failed to get authorization URL: #{auth_response.status.code} #{auth_response.status.reason}"
        end

        results[:authorization_url] = authorization_url
        results[:steps_completed] << "authorization_url_received"
      rescue => e
        results[:errors] << "Step 3 (Authorization request): #{e.message}"
        raise
      end

      # Return results with instructions
      results[:instructions] = [
        "1. Copy the authorization URL and open it in your browser",
        "2. Complete the authentication with your provider",
        "3. After authentication, you'll be redirected to a callback URL",
        "4. Copy the ENTIRE callback URL (including all parameters) and provide it when prompted"
      ]

      results
    end
    end
  end
end
