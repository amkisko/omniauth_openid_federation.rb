RSpec.configure do |config|
  config.before do |example|
    @spec_file_path = example.metadata[:example_group][:file_path]
    @spec_line_number = example.metadata[:example_group][:line_number]

    def spec_dirname
      File.dirname(@spec_file_path)
    end

    def spec_basename
      File.basename(@spec_file_path)
    end

    if ENV["DEBUG"]
      Rails.logger.level = 0
      ActiveRecord::Base.logger = Logger.new($stdout) if defined?(ActiveRecord::Base)
    end

    if ENV["DEBUG"] || ENV["SHOW_SPEC_INFO"]
      puts "Running #{@spec_file_path}:#{@spec_line_number}"
    end
  end
end

def print_current_spec
  puts ">>> #{@spec_file_path}:#{@spec_line_number}"
end
