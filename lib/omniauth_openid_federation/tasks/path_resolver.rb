require_relative "../configuration"

module OmniauthOpenidFederation
  module Tasks
    module PathResolver
      def self.resolve(file_path)
        return file_path if file_path.start_with?("/")

        config = Configuration.config
        if defined?(Rails) && Rails.root
          Rails.root.join(file_path).to_s
        elsif config.root_path
          File.join(config.root_path, file_path)
        else
          File.expand_path(file_path)
        end
      end
    end
  end
end
