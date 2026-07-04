# frozen_string_literal: true

module JwtTestHelpers
  def signing_kid_for(key)
    public_key = key.respond_to?(:private?) && key.private? ? key.public_key : key
    OmniauthOpenidFederation::Utils.rsa_key_to_jwk(public_key)[:kid]
  end

  def encode_entity_statement(payload, key: private_key)
    signing_key = key
    public_key = key.respond_to?(:private?) && key.private? ? key.public_key : key
    kid = signing_kid_for(public_key)
    statement = payload.transform_keys(&:to_sym)
    statement[:iat] ||= Time.now.to_i
    statement[:exp] ||= Time.now.to_i + 3600
    JWT.encode(statement, signing_key, "RS256", {alg: "RS256", typ: "entity-statement+jwt", kid: kid})
  end

  def encode_rs256(payload, key: private_key, kid: nil)
    signing_key = key
    public_key = key.respond_to?(:private?) && key.private? ? key.public_key : key
    kid ||= signing_kid_for(public_key)
    JWT.encode(payload, signing_key, "RS256", {kid: kid})
  end

  def stub_rails_config_dir(config_dir)
    return unless defined?(Rails)

    rails_root = double("Rails.root")
    project_root = File.dirname(config_dir)
    allow(Rails).to receive(:root).and_return(rails_root)
    allow(rails_root).to receive(:join) do |*parts|
      Pathname.new(File.join(project_root, *parts))
    end
  end

  def entity_statement_path_under_config
    @entity_statement_config_dir ||= begin
      dir = Dir.mktmpdir
      config_dir = File.join(dir, "config")
      FileUtils.mkdir_p(config_dir)
      stub_rails_config_dir(config_dir)
      @entity_statement_temp_dir = dir
      config_dir
    end
    File.join(@entity_statement_config_dir, "entity-#{SecureRandom.hex(4)}.jwt")
  end
end

RSpec.configure do |config|
  config.include JwtTestHelpers

  config.after do
    next unless @entity_statement_temp_dir

    FileUtils.rm_rf(@entity_statement_temp_dir)
    @entity_statement_temp_dir = nil
    @entity_statement_config_dir = nil
  end
end
