# frozen_string_literal: true

require "spec_helper"
require "open3"

RSpec.describe "tasks entrypoint" do
  let(:lib_path) { File.expand_path("../../lib", __dir__) }

  it "does not load TasksHelper from the main gem require" do
    script = <<~RUBY
      require "omniauth_openid_federation"
      if defined?(OmniauthOpenidFederation::TasksHelper)
        warn "TasksHelper loaded by main entry"
        exit 2
      end
      loaded = $LOADED_FEATURES.select { |path| path.include?("omniauth_openid_federation") }
      if loaded.any? { |path| path.include?("tasks_helper") || path.include?("/tasks/") }
        warn "tasks features loaded by main entry: \#{loaded.grep(/tasks/)}"
        exit 3
      end
      puts "ok"
    RUBY

    output, status = Open3.capture2e(Gem.ruby, "-I#{lib_path}", "-e", script)

    expect(status.exitstatus).to eq(0), output
    expect(output).to include("ok")
  end

  it "loads TasksHelper from omniauth_openid_federation/tasks" do
    script = <<~RUBY
      require "omniauth_openid_federation"
      if defined?(OmniauthOpenidFederation::TasksHelper)
        warn "TasksHelper already loaded before tasks entry"
        exit 2
      end
      require "omniauth_openid_federation/tasks"
      unless defined?(OmniauthOpenidFederation::TasksHelper)
        warn "TasksHelper missing after tasks entry"
        exit 3
      end
      puts "ok"
    RUBY

    output, status = Open3.capture2e(Gem.ruby, "-I#{lib_path}", "-e", script)

    expect(status.exitstatus).to eq(0), output
    expect(output).to include("ok")
  end
end
