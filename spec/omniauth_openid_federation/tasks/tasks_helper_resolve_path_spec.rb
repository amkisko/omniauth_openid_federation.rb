require "spec_helper"

RSpec.describe OmniauthOpenidFederation::TasksHelper do
  describe ".resolve_path" do
    context "with absolute path" do
      it "returns the path as-is" do
        expect(described_class.resolve_path("/absolute/path")).to eq("/absolute/path")
      end
    end

    context "with relative path" do
      context "when Rails.root is available" do
        before do
          rails_root = double("Rails.root")
          allow(rails_root).to receive(:join).with("relative/path").and_return(double(to_s: "/rails/root/relative/path"))
          stub_const("Rails", double(root: rails_root))
        end

        after do
          # Restore Rails state after tests that stub Rails
          # RSpec should automatically restore stub_const, but we reset mocks for allow().to receive()

          if defined?(Rails)
            # Reset Rails mocks - RSpec will handle stub_const cleanup automatically
            RSpec::Mocks.space.proxy_for(Rails)&.reset
          end
        rescue
          # If restoration fails, continue - RSpec will handle stub cleanup
        end

        it "uses Rails.root.join" do
          expect(described_class.resolve_path("relative/path")).to eq("/rails/root/relative/path")
        end
      end

      context "when config.root_path is set" do
        before do
          hide_const("Rails")
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = "/config/root"
        end

        after do
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = nil
        end

        it "uses config.root_path" do
          expect(described_class.resolve_path("relative/path")).to eq("/config/root/relative/path")
        end
      end

      context "when neither Rails nor config.root_path is available" do
        before do
          hide_const("Rails")
          config = OmniauthOpenidFederation::Configuration.config
          config.root_path = nil
        end

        it "uses File.expand_path" do
          result = described_class.resolve_path("relative/path")
          aggregate_failures do
            expect(result).to be_a(String)
            expect(result).to include("relative/path")
          end
        end
      end
    end
  end

end
