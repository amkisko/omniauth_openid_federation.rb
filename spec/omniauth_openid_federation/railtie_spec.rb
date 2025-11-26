require "spec_helper"

# Only run these tests if Rails is available
if defined?(Rails)
  RSpec.describe OmniauthOpenidFederation::Railtie do
    before do
      # Reset autoload paths
      if Rails.application.config.respond_to?(:autoload_once_paths)
        Rails.application.config.autoload_once_paths.delete_if { |path| path.include?("omniauth_openid_federation") }
      end
    end

    describe "initializer" do
      it "adds controllers path to autoload_once_paths when path exists" do
        controllers_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers")

        # Create the directory if it doesn't exist
        FileUtils.mkdir_p(controllers_path) unless File.exist?(controllers_path)

        # Trigger the initializer
        Rails.application.initialize!

        expect(Rails.application.config.autoload_once_paths).to include(controllers_path)
      end

      it "does not add controllers path when path does not exist" do
        # Temporarily rename the controllers directory
        controllers_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers")
        temp_path = "#{controllers_path}.tmp"

        if File.exist?(controllers_path)
          FileUtils.mv(controllers_path, temp_path)
        end

        begin
          # Reset autoload paths
          Rails.application.config.autoload_once_paths.delete_if { |path| path.include?("omniauth_openid_federation") }

          # Trigger the initializer
          Rails.application.initialize!

          expect(Rails.application.config.autoload_once_paths).not_to include(controllers_path)
        ensure
          # Restore the directory
          if File.exist?(temp_path)
            FileUtils.mv(temp_path, controllers_path)
          end
        end
      end
    end

    describe "config.to_prepare" do
      it "requires controller when path exists" do
        controller_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers", "omniauth_openid_federation", "federation_controller.rb")

        if File.exist?(controller_path)
          expect(File).to receive(:exist?).with(controller_path).and_return(true)
          expect(Kernel).to receive(:require).with(controller_path)

          # Trigger to_prepare callbacks
          Rails.application.config.to_prepare.call
        end
      end

      it "does not require controller when path does not exist" do
        controller_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers", "omniauth_openid_federation", "federation_controller.rb")

        expect(File).to receive(:exist?).with(controller_path).and_return(false)
        expect(Kernel).not_to receive(:require).with(controller_path)

        # Trigger to_prepare callbacks
        Rails.application.config.to_prepare.call
      end
    end

    describe "rake_tasks" do
      it "loads rake task files when they exist" do
        task_files = Dir[File.join(File.dirname(__FILE__), "..", "..", "lib", "tasks", "**", "*.rake")]

        if task_files.any?
          task_files.each do |task_file|
            expect(Kernel).to receive(:load).with(task_file)
          end

          # Trigger rake_tasks block
          Rails.application.load_tasks
        end
      end

      it "does not load rake tasks when no files exist" do
        # Mock Dir[] to return empty array
        allow(Dir).to receive(:[]).and_return([])
        expect(Kernel).not_to receive(:load)

        # Trigger rake_tasks block
        Rails.application.load_tasks
      end
    end
  end
end
