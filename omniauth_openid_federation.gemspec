require_relative "lib/omniauth_openid_federation/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth_openid_federation"
  spec.version = OmniauthOpenidFederation::VERSION
  spec.authors = ["Andrei Makarov"]
  spec.email = ["contact@kiskolabs.com"]

  spec.summary = "OmniAuth strategy for OpenID Federation providers with signed request objects and ID token encryption."
  spec.description = "Custom OmniAuth strategy for OpenID Federation providers using openid_connect gem, supporting signed request objects (RFC 9101), ID token encryption/decryption, client assertion (private_key_jwt), and OpenID Federation entity statements. Framework-agnostic and works with Rails, Sinatra, Rack, and other Rack-compatible frameworks."
  spec.homepage = "https://github.com/amkisko/omniauth_openid_federation.rb"
  spec.license = "MIT"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["lib/**/*", "sig/**/*", "README.md", "LICENSE*", "CHANGELOG.md", "SECURITY.md", "examples/**/*"].select { |f| File.file?(f) }
  end
  spec.require_paths = ["lib"]
  spec.required_ruby_version = ">= 3.0"
  spec.required_rubygems_version = ">= 3.3.0"

  spec.metadata = {
    "source_code_uri" => "https://github.com/amkisko/omniauth_openid_federation.rb",
    "changelog_uri" => "https://github.com/amkisko/omniauth_openid_federation.rb/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "https://github.com/amkisko/omniauth_openid_federation.rb/issues",
    "rubygems_mfa_required" => "true",
    "documentation_uri" => "https://rubydoc.info/gems/omniauth_openid_federation"
  }

  spec.add_runtime_dependency "omniauth-oauth2", "~> 1.8"
  spec.add_runtime_dependency "openid_connect", "~> 2.3"
  spec.add_runtime_dependency "jwt", "~> 3.1"
  spec.add_runtime_dependency "jwe", "~> 1.1"
  spec.add_runtime_dependency "http", "~> 5.3"
  spec.add_runtime_dependency "rack", ">= 2.0", "< 4"

  spec.add_development_dependency "rspec", "~> 3.13"
  spec.add_development_dependency "webmock", "~> 3.26"
  spec.add_development_dependency "rake", "~> 13.3"
  spec.add_development_dependency "simplecov", "~> 0.22"
  spec.add_development_dependency "rspec_junit_formatter", "~> 0.6"
  spec.add_development_dependency "simplecov-cobertura", "~> 3.1"
  spec.add_development_dependency "standard", "~> 1.52"
  spec.add_development_dependency "appraisal", "~> 2.5"
  spec.add_development_dependency "memory_profiler", "~> 1.1"
  spec.add_development_dependency "rbs", "~> 3.9"
  spec.add_development_dependency "webrick", "~> 1.9"
end
