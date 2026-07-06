#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone Multiple Auth Endpoints Example with Sinatra
#
# This example demonstrates how to use omniauth_openid_federation
# in a standalone Sinatra application with multiple authentication
# endpoints that differentiate entrance points (portal, admin, mobile).
#
# Features:
# - Multiple auth endpoints with different parameters
# - Entrance point tracking
# - Different redirects based on entrance point after callback
# - No Rails/Devise dependency - pure Sinatra
#
# Usage:
#   ruby examples/standalone_multiple_endpoints_example.rb
#
# Access:
#   http://localhost:9294/ - Home page
#   http://localhost:9294/auth/openid_federation_portal - Portal login
#   http://localhost:9294/auth/openid_federation_admin - Admin login
#   http://localhost:9294/auth/openid_federation_mobile - Mobile login

require "bundler/setup"
require "sinatra"
require "omniauth"
require "omniauth_openid_federation"
require "json"
require "securerandom"

# Add the gem to the load path
$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

# Configuration
OP_ENTITY_STATEMENT_URL = ENV["OP_ENTITY_STATEMENT_URL"] || "https://provider.example.com/.well-known/openid-federation"
OP_ENTITY_STATEMENT_FINGERPRINT = ENV["OP_ENTITY_STATEMENT_FINGERPRINT"] # Optional: for verification
CLIENT_ID = ENV["OPENID_CLIENT_ID"] || "your-client-id"
REDIRECT_URI_BASE = ENV["OPENID_REDIRECT_URI_BASE"] || "http://localhost:9294"

# Load private key (auto-provisioned from environment or auto-generated)
def load_private_key
  if ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]
    require "base64"
    require "openssl"
    OpenSSL::PKey::RSA.new(Base64.decode64(ENV["OPENID_CLIENT_PRIVATE_KEY_BASE64"]))
  else
    # Auto-generate keys if not provided (for development/testing)
    # In production, always provide OPENID_CLIENT_PRIVATE_KEY_BASE64
    require "openssl"
    @auto_generated_key ||= OpenSSL::PKey::RSA.new(2048)
  end
end

# Fetch and refresh OP entity statement (called on each request)
def fetch_op_entity_statement
  return nil unless OP_ENTITY_STATEMENT_URL
  
  begin
    OmniauthOpenidFederation::Federation::EntityStatement.fetch!(
      OP_ENTITY_STATEMENT_URL,
      fingerprint: OP_ENTITY_STATEMENT_FINGERPRINT,
      timeout: 10
    )
  rescue => e
    puts "Warning: Failed to fetch OP entity statement: #{e.message}"
    nil
  end
end

# Configure session
set :session_secret, ENV.fetch("SESSION_SECRET") { SecureRandom.hex(32) }
enable :sessions

# Fetch/refresh OP entity statement on each request
before do
  # Fetch OP entity statement to ensure we have latest metadata and keys
  # This happens automatically in the strategy, but we can also do it here
  # to warm up the cache and verify connectivity
  fetch_op_entity_statement if request.path.start_with?("/auth/")
end

# Configure OmniAuth
OmniAuth.config.allowed_request_methods = [:get, :post]
OmniAuth.config.silence_get_warning = true

# Configure CSRF protection for request phase
OmniAuth.config.request_validation_phase = lambda do |env|
  request = Rack::Request.new(env)
  return true if request.path.end_with?("/callback")
  
  session = env["rack.session"] || {}
  token = request.params["authenticity_token"] || request.get_header("X-CSRF-Token")
  expected_token = session[:_csrf_token] || session["_csrf_token"]
  
  if token && expected_token
    Rack::Utils.secure_compare(token.to_s, expected_token.to_s)
  else
    false
  end
end

# Configure multiple OpenID Federation strategies
use OmniAuth::Builder do
  # Strategy 1: Portal entrance point
  provider(:openid_federation_portal,
    strategy_class: OmniAuth::Strategies::OpenIDFederation,
    name: :openid_federation_portal,
    scope: [:openid, :profile, :email],
    response_type: "code",
    discovery: true,
    client_auth_method: :jwt_bearer,
    client_signing_alg: :RS256,
    entity_statement_url: OP_ENTITY_STATEMENT_URL,
    entity_statement_fingerprint: OP_ENTITY_STATEMENT_FINGERPRINT,
    always_encrypt_request_object: false,
    request_object_params: ["entrance_point", "portal_id", "acr_values"],
    prepare_request_object_params: proc do |params|
      # Always set entrance_point for portal
      params["entrance_point"] = "portal"
      
      # Combine config acr_values with form acr_values
      form_acr_values = params["acr_values"]&.to_s&.strip
      config_acr_values = (ENV["OPENID_ACR_VALUES_PORTAL"] || "").to_s.strip
      
      if !config_acr_values.empty? && !form_acr_values.to_s.empty?
        params["acr_values"] = "#{config_acr_values} #{form_acr_values}".strip
      elsif !config_acr_values.empty?
        params["acr_values"] = config_acr_values
      end
      
      # Add portal-specific parameter if provided
      portal_id = ENV["OPENID_PORTAL_ID"]
      params["portal_id"] = portal_id if portal_id && !portal_id.empty?
      
      params
    end,
    client_options: {
      identifier: CLIENT_ID,
      redirect_uri: "#{REDIRECT_URI_BASE}/auth/openid_federation_portal/callback",
      private_key: load_private_key
    })

  # Strategy 2: Admin entrance point
  provider(:openid_federation_admin,
    strategy_class: OmniAuth::Strategies::OpenIDFederation,
    name: :openid_federation_admin,
    scope: [:openid, :profile, :email],
    response_type: "code",
    discovery: true,
    client_auth_method: :jwt_bearer,
    client_signing_alg: :RS256,
    entity_statement_url: OP_ENTITY_STATEMENT_URL,
    entity_statement_fingerprint: OP_ENTITY_STATEMENT_FINGERPRINT,
    always_encrypt_request_object: false,
    request_object_params: ["entrance_point", "acr_values", "prompt"],
    prepare_request_object_params: proc do |params|
      # Always set entrance_point for admin
      params["entrance_point"] = "admin"
      
      # Admin requires higher ACR level
      admin_acr = ENV["OPENID_ACR_VALUES_ADMIN"] || "urn:mace:incommon:iap:silver"
      params["acr_values"] = admin_acr
      
      # Force re-authentication for admin
      params["prompt"] = "login consent"
      
      params
    end,
    client_options: {
      identifier: CLIENT_ID,
      redirect_uri: "#{REDIRECT_URI_BASE}/auth/openid_federation_admin/callback",
      private_key: load_private_key
    })

  # Strategy 3: Mobile app entrance point
  provider(:openid_federation_mobile,
    strategy_class: OmniAuth::Strategies::OpenIDFederation,
    name: :openid_federation_mobile,
    scope: [:openid, :profile, :email],
    response_type: "code",
    discovery: true,
    client_auth_method: :jwt_bearer,
    client_signing_alg: :RS256,
    entity_statement_url: OP_ENTITY_STATEMENT_URL,
    entity_statement_fingerprint: OP_ENTITY_STATEMENT_FINGERPRINT,
    always_encrypt_request_object: false,
    request_object_params: ["entrance_point", "device_id", "app_version"],
    prepare_request_object_params: proc do |params|
      # Always set entrance_point for mobile
      params["entrance_point"] = "mobile"
      
      # Add device-specific parameters if provided
      params["device_id"] = params["device_id"] if params["device_id"] && !params["device_id"].to_s.empty?
      params["app_version"] = params["app_version"] if params["app_version"] && !params["app_version"].to_s.empty?
      
      params
    end,
    client_options: {
      identifier: CLIENT_ID,
      redirect_uri: "#{REDIRECT_URI_BASE}/auth/openid_federation_mobile/callback",
      private_key: load_private_key
    })
end

# Helper to generate CSRF token
def csrf_token
  session[:_csrf_token] ||= SecureRandom.hex(32)
end

# Helper to get entrance point redirect URL
def redirect_for_entrance_point(entrance_point, user_info = {})
  case entrance_point
  when "portal"
    "/portal/dashboard"
  when "admin"
    "/admin/dashboard"
  when "mobile"
    "/mobile/home"
  else
    "/dashboard"
  end
end

# Home page
get "/" do
  erb :index
end

# Portal dashboard (example)
get "/portal/dashboard" do
  content_type :json
  {
    status: "success",
    entrance_point: "portal",
    message: "Welcome to Portal Dashboard",
    user: params[:user]
  }.to_json
end

# Admin dashboard (example)
get "/admin/dashboard" do
  content_type :json
  {
    status: "success",
    entrance_point: "admin",
    message: "Welcome to Admin Dashboard",
    user: params[:user]
  }.to_json
end

# Mobile home (example)
get "/mobile/home" do
  content_type :json
  {
    status: "success",
    entrance_point: "mobile",
    message: "Welcome to Mobile App",
    user: params[:user]
  }.to_json
end

# Default dashboard (fallback)
get "/dashboard" do
  content_type :json
  {
    status: "success",
    message: "Welcome",
    user: params[:user]
  }.to_json
end

# Callback handlers for each entrance point
get "/auth/:provider/callback" do
  auth = request.env["omniauth.auth"]
  
  if auth
    # Extract entrance point from strategy name or raw_info
    provider_name = params[:provider]
    entrance_point = case provider_name
    when "openid_federation_portal"
      "portal"
    when "openid_federation_admin"
      "admin"
    when "openid_federation_mobile"
      "mobile"
    else
      # Try to get from raw_info if provider returns it
      raw_info = auth.extra[:raw_info] || {}
      raw_info["entrance_point"] || "unknown"
    end
    
    # Extract user information
    user_info = {
      provider: auth.provider,
      uid: auth.uid,
      email: auth.info.email,
      name: auth.info.name,
      first_name: auth.info.first_name,
      last_name: auth.info.last_name,
      raw_info: auth.extra[:raw_info]
    }
    
    # Store user info in session
    session[:user] = user_info
    session[:entrance_point] = entrance_point
    
    # Extract additional parameters from raw_info if provider returns them
    raw_info = auth.extra[:raw_info] || {}
    session[:portal_id] = raw_info["portal_id"] if raw_info["portal_id"]
    session[:device_id] = raw_info["device_id"] if raw_info["device_id"]
    
    # Redirect based on entrance point
    redirect redirect_for_entrance_point(entrance_point, user_info)
  else
    redirect "/auth/failure"
  end
end

# Failure handler
get "/auth/failure" do
  error_type = request.env["omniauth.error.type"]
  error_message = request.env["omniauth.error"]&.message || "Authentication failed"
  
  content_type :json
  {
    status: "error",
    error_type: error_type,
    message: error_message
  }.to_json
end

# User info endpoint (example)
get "/user/info" do
  if session[:user]
    content_type :json
    {
      status: "success",
      user: session[:user],
      entrance_point: session[:entrance_point],
      portal_id: session[:portal_id],
      device_id: session[:device_id]
    }.to_json
  else
    status 401
    content_type :json
    { status: "error", message: "Not authenticated" }.to_json
  end
end

# Run the server
if __FILE__ == $0
  require "sinatra"
  
  puts "Starting standalone multiple endpoints example server..."
  puts "Server: http://localhost:9294"
  puts ""
  puts "Endpoints:"
  puts "  GET  / - Home page with login links"
  puts "  POST /auth/openid_federation_portal - Portal login"
  puts "  POST /auth/openid_federation_admin - Admin login"
  puts "  POST /auth/openid_federation_mobile - Mobile login"
  puts "  GET  /auth/:provider/callback - OAuth callback (redirects based on entrance point)"
  puts "  GET  /auth/failure - Authentication failure handler"
  puts "  GET  /user/info - Current user info (JSON)"
  puts ""
  puts "Environment variables:"
  puts "  OP_ENTITY_STATEMENT_URL - Provider entity statement URL (required)"
  puts "  OP_ENTITY_STATEMENT_FINGERPRINT - Expected fingerprint for verification (optional)"
  puts "  OPENID_CLIENT_ID - Your client ID (required)"
  puts "  OPENID_REDIRECT_URI_BASE - Base URL for redirect URIs (default: http://localhost:9294)"
  puts "  OPENID_CLIENT_PRIVATE_KEY_BASE64 - Base64-encoded private key (auto-generated if not set)"
  puts "  OPENID_ACR_VALUES_PORTAL - ACR values for portal (optional)"
  puts "  OPENID_ACR_VALUES_ADMIN - ACR values for admin (optional)"
  puts "  OPENID_PORTAL_ID - Portal ID (optional)"
  puts "  SESSION_SECRET - Session secret (auto-generated if not set)"
  puts ""
  puts "Note: OP entity statement and keys are automatically fetched/refreshed on each request."
  puts ""
  
  set :port, ENV.fetch("PORT", 9294).to_i
  set :bind, ENV.fetch("HOST", "localhost")
end

# View templates
__END__

@@index
<!DOCTYPE html>
<html>
<head>
  <title>Multiple Auth Endpoints Example</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 800px;
      margin: 50px auto;
      padding: 20px;
    }
    h1 {
      color: #333;
    }
    .login-section {
      margin: 30px 0;
      padding: 20px;
      border: 1px solid #ddd;
      border-radius: 5px;
    }
    .login-section h2 {
      margin-top: 0;
      color: #555;
    }
    .login-button {
      display: inline-block;
      padding: 10px 20px;
      background-color: #007bff;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      margin: 5px 0;
    }
    .login-button:hover {
      background-color: #0056b3;
    }
    .info {
      background-color: #f0f0f0;
      padding: 15px;
      border-radius: 4px;
      margin: 20px 0;
    }
  </style>
</head>
<body>
  <h1>OpenID Federation - Multiple Auth Endpoints Example</h1>
  
  <div class="info">
    <p>This example demonstrates multiple authentication endpoints with different entrance points.</p>
    <p>Each endpoint sends different parameters and redirects to different destinations after authentication.</p>
  </div>

  <div class="login-section">
    <h2>Portal Login</h2>
    <p>Login via portal entrance point. Will redirect to <code>/portal/dashboard</code> after authentication.</p>
    <form method="post" action="/auth/openid_federation_portal">
      <input type="hidden" name="authenticity_token" value="<%= csrf_token %>">
      <input type="hidden" name="portal_id" value="main_portal">
      <input type="hidden" name="acr_values" value="urn:mace:incommon:iap:bronze">
      <button type="submit" class="login-button">Login via Portal</button>
    </form>
  </div>

  <div class="login-section">
    <h2>Admin Login</h2>
    <p>Login via admin entrance point. Will redirect to <code>/admin/dashboard</code> after authentication.</p>
    <p><strong>Note:</strong> Admin login requires higher ACR level and forces re-authentication.</p>
    <form method="post" action="/auth/openid_federation_admin">
      <input type="hidden" name="authenticity_token" value="<%= csrf_token %>">
      <button type="submit" class="login-button">Login as Admin</button>
    </form>
  </div>

  <div class="login-section">
    <h2>Mobile Login</h2>
    <p>Login via mobile entrance point. Will redirect to <code>/mobile/home</code> after authentication.</p>
    <form method="post" action="/auth/openid_federation_mobile">
      <input type="hidden" name="authenticity_token" value="<%= csrf_token %>">
      <input type="hidden" name="device_id" value="device_123">
      <input type="hidden" name="app_version" value="1.0.0">
      <button type="submit" class="login-button">Login via Mobile</button>
    </form>
  </div>

  <div class="info">
    <h3>How it works:</h3>
    <ul>
      <li>Each endpoint has a different <code>name</code> (portal, admin, mobile)</li>
      <li>Each endpoint sends different custom parameters in the signed request object</li>
      <li>The <code>prepare_request_object_params</code> proc customizes parameters per endpoint</li>
      <li>After callback, users are redirected based on their entrance point</li>
      <li>User info and entrance point are stored in session</li>
    </ul>
  </div>

  <% if session[:user] %>
    <div class="info">
      <h3>Current Session:</h3>
      <p><strong>Entrance Point:</strong> <%= session[:entrance_point] %></p>
      <p><strong>User:</strong> <%= session[:user][:email] || session[:user][:uid] %></p>
      <p><a href="/user/info">View full user info (JSON)</a></p>
    </div>
  <% end %>
</body>
</html>

