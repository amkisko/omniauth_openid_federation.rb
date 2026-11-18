#!/usr/bin/env ruby

require "fileutils"
require_relative "../lib/release_version_check"

def execute_command(command, allow_failure: false)
  green = "\033[0;32m"
  red = "\033[1;31m"
  yellow = "\033[1;33m"
  nc = "\033[0m"

  puts "#{green}#{command}#{nc}"
  shell_command = command.include?("|") ? "set -o pipefail; #{command}" : command
  return true if system("bash", "-c", shell_command)

  if allow_failure
    puts "#{yellow}Command failed: #{command}#{nc}"
    return false
  end

  puts "#{red}Command failed: #{command}#{nc}"
  exit 1
end

execute_command("bundle")
execute_command("bundle exec appraisal generate")
execute_command("BUNDLE_GEMFILE=gemfiles/rails8.gemfile bundle install")
execute_command("bundle exec rubocop -a 2>&1 | tee tmp/rubocop.log")
execute_command("bundle exec rbs validate")
execute_command("POLYRUN_COVERAGE=1 bundle exec appraisal rails8 -- bundle exec polyrun parallel-rspec --workers 5 --merge-failures 2>&1 | tee tmp/polyrun-rspec.log")

puts "Tests passed. Checking git status..."

git_status = `git status --porcelain --untracked-files=all 2>/dev/null`.strip
unless git_status.empty?
  puts "\033[1;31mgit working directory not clean, please commit your changes first \033[0m"
  puts "\033[1;33mNote: rubocop -a may have modified files. Review and commit changes before releasing.\033[0m"
  exit 1
end

gem_name = "omniauth_openid_federation"
version_file = "lib/omniauth_openid_federation/version.rb"
version_content = File.read(version_file)
version = version_content.match(/VERSION\s*=\s*"([0-9.]+)"/)[1]
gem_file = "#{gem_name}-#{version}.gem"

ReleaseVersionCheck.require_changelog_version!(version: version)
changelog_notes = ReleaseVersionCheck.require_changelog_notes!(version: version)
ReleaseVersionCheck.warn_if_already_released(version: version, package_name: gem_name, registry: :rubygems)

execute_command("gem build #{gem_name}.gemspec")

puts "Ready to release #{gem_file} #{version}"
print "Continue? [Y/n] "
answer = $stdin.gets&.chomp
if answer.nil? || (answer != "" && !answer.casecmp?("y"))
  puts "Exiting"
  exit 1
end

FileUtils.mkdir_p("tmp")
notes_path = "tmp/github-release-notes.md"
File.write(notes_path, changelog_notes)

execute_command("gem push #{gem_file}")
execute_command("git tag #{version}")
# origin may have multiple push URLs (GitHub, GitLab, Codeberg). One mirror
# failing must not skip the GitHub release after gem push and local tag succeed.
push_ok = execute_command(
  "git push origin HEAD \"refs/tags/#{version}\"",
  allow_failure: true
)
unless push_ok
  yellow = "\033[1;33m"
  nc = "\033[0m"
  puts "#{yellow}Continuing with GitHub release despite git push failure#{nc}"
end
execute_command("gh release create #{version} --title #{version} --notes-file #{notes_path}")
exit 1 unless push_ok
