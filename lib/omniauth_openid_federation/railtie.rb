# Railtie to load rake tasks
# Note: Controllers and routes are now handled by the Engine (lib/omniauth_openid_federation/engine.rb)
# This Railtie is kept for backward compatibility and for loading rake tasks
if defined?(Rails)
  module OmniauthOpenidFederation
    class Railtie < Rails::Railtie
      rake_tasks do
        # Load rake tasks from lib/tasks
        # Rails automatically loads lib/tasks/**/*.rake, but we ensure they're loaded here too
        task_files = Dir[File.join(File.dirname(__FILE__), "..", "tasks", "**", "*.rake")]
        task_files.each { |task_file| load task_file } if task_files.any?
      end
    end
  end
end
