# frozen_string_literal: true

RSpec.shared_context "with rake tasks helpers" do
  let(:temp_dir) { Dir.mktmpdir }
  let(:output_file) { File.join(temp_dir, "output.jwt") }
  let(:entity_statement_file) { File.join(temp_dir, "entity-statement.jwt") }

  before do
    # Define :environment task if it doesn't exist (for non-Rails environments)
    unless Rake::Task.task_defined?(:environment)
      Rake::Task.define_task(:environment) do
        # No-op for testing
      end
    end

    # Clear any existing task definitions
    Rake::Task.tasks.each do |task|
      task.clear if task.respond_to?(:clear) && task.name != "environment"
    end

    # Load rake tasks
    rake_file = File.expand_path("../../../lib/tasks/omniauth_openid_federation.rake", __dir__)
    load rake_file if File.exist?(rake_file)

    # Clear environment variables
    ENV.delete("ENTITY_STATEMENT_URL")
    ENV.delete("ENTITY_STATEMENT_FINGERPRINT")
    ENV.delete("ENTITY_STATEMENT_OUTPUT")
    ENV.delete("ENTITY_STATEMENT_PATH")
    ENV.delete("JWKS_URI")
    ENV.delete("JWKS_OUTPUT")
    ENV.delete("KEY_TYPE")
    ENV.delete("KEYS_OUTPUT_DIR")
  end

  after do
    FileUtils.rm_rf(temp_dir) if Dir.exist?(temp_dir)
  end

  def capture_output
    stdout = StringIO.new
    stderr = StringIO.new
    original_stdout = $stdout
    original_stderr = $stderr
    $stdout = stdout
    $stderr = stderr

    begin
      yield
      {stdout: stdout.string, stderr: stderr.string, exit_code: 0}
    rescue SystemExit => e
      {stdout: stdout.string, stderr: stderr.string, exit_code: e.status}
    ensure
      $stdout = original_stdout
      $stderr = original_stderr
    end
  end

  def run_rake_task(task_name, *args)
    task = Rake::Task[task_name]
    task.reenable # Allow task to run again
    capture_output do
      # Rake tasks that exit will raise SystemExit
      task.invoke(*args)
    end
  end
end
