# frozen_string_literal: true

require "spec_helper"

RSpec.describe "gem packaging" do
  let(:specification) do
    path = File.expand_path("../../omniauth_openid_federation.gemspec", __dir__)
    Gem::Specification.load(path)
  end

  it "does not package examples into the gem" do
    example_paths = specification.files.select { |path| path.start_with?("examples/") }

    expect(example_paths).to eq([])
  end

  it "keeps sig and lib in the packaged file list" do
    expect(specification.files).to include(a_string_matching(%r{\Alib/}))
    expect(specification.files).to include(a_string_matching(%r{\Asig/}))
  end

  it "does not package rfcs into the gem" do
    rfc_paths = specification.files.select { |path| path.start_with?("rfcs/") }

    expect(rfc_paths).to eq([])
  end
end
