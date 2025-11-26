# Railtie to load rake tasks and provide Rails integration
if defined?(Rails)
  module OmniauthOpenidFederation
    class Railtie < Rails::Railtie
      # Add gem's controllers to autoload paths
      # This ensures the controller can be found by Rails routing
      initializer "omniauth_openid_federation.add_autoload_paths", before: :set_autoload_paths do |app|
        controllers_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers")
        app.config.autoload_once_paths << controllers_path if File.exist?(controllers_path)
      end

      # Load controller when Rails is available (for development reloading)
      config.to_prepare do
        controller_path = File.join(File.dirname(__FILE__), "..", "..", "app", "controllers", "omniauth_openid_federation", "federation_controller.rb")
        require controller_path if File.exist?(controller_path)
      end

      rake_tasks do
        # Load rake tasks from lib/tasks
        # Rails automatically loads lib/tasks/**/*.rake, but we ensure they're loaded here too
        # File.dirname(__FILE__) = lib/omniauth_openid_federation
        # .. = lib
        # tasks = lib/tasks
        task_files = Dir[File.join(File.dirname(__FILE__), "..", "tasks", "**", "*.rake")]
        task_files.each { |task_file| load task_file } if task_files.any?
      end
    end
  end
end
