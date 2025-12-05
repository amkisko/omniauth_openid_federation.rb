#!/usr/bin/env ruby
#
# Show Uncovered Lines
#
# Displays non-covered lines from the coverage report with context.
# Shows 1 line before, the uncovered line, and 1 line after.
# Groups nearby uncovered lines together in blocks.
#
# Usage:
#   ./usr/scripts/show_uncovered_lines.rb
#   ./usr/scripts/show_uncovered_lines.rb --threshold 5
#   ./usr/scripts/show_uncovered_lines.rb --file app/models/project.rb
#
# Options:
#   --threshold N    Group lines within N lines of each other (default: 3)
#   --file PATH      Only show uncovered lines for specific file
#   --coverage PATH  Path to coverage.json (default: coverage/coverage.json)

require "optparse"
require "json"
require "pathname"
require "fileutils"
require "time"

# Default options
options = {
  threshold: 3,
  coverage_path: "coverage/coverage.json",
  file_filter: nil,
  metrics_dir: "tmp/coverage_metrics",
  compare_metrics: false
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options]"

  opts.on("-t", "--threshold N", Integer, "Group lines within N lines of each other (default: 3)") do |n|
    options[:threshold] = n
  end

  opts.on("-f", "--file PATH", "Only show uncovered lines for specific file") do |path|
    options[:file_filter] = path
  end

  opts.on("-c", "--coverage PATH", "Path to coverage.json (default: coverage/coverage.json)") do |path|
    options[:coverage_path] = path
  end

  opts.on("-m", "--metrics-dir PATH", "Directory for coverage metrics snapshots (default: tmp/coverage_metrics)") do |path|
    options[:metrics_dir] = path
  end

  opts.on("--compare-metrics", "Compare all snapshot JSON files in metrics dir and show progress") do
    options[:compare_metrics] = true
  end

  opts.on("-h", "--help", "Prints this help") do
    puts opts
    exit
  end
end.parse!

def load_metrics_snapshot(path)
  JSON.parse(File.read(path))
rescue => e
  warn "Warning: failed to read metrics file #{path}: #{e.class}: #{e.message}"
  nil
end

def compare_metrics_snapshots(metrics_dir)
  unless Dir.exist?(metrics_dir)
    warn "Metrics directory not found: #{metrics_dir}"
    return
  end

  pattern = File.join(metrics_dir, "coverage_*.json")
  files = Dir.glob(pattern).sort

  if files.length < 2
    warn "Not enough metrics files to compare in #{metrics_dir} (found #{files.length}, need at least 2)"
    return
  end

  snapshots = files.map { |path| [path, load_metrics_snapshot(path)] }.reject { |_, data| data.nil? }

  if snapshots.length < 2
    warn "Not enough valid metrics snapshots to compare (need at least 2)"
    return
  end

  first_path, first = snapshots.first
  last_path, last = snapshots.last

  first_uncovered_count = first["total_uncovered"] || 0
  last_uncovered_count = last["total_uncovered"] || 0

  first_pairs = Set.new
  (first["uncovered"] || {}).each do |file, lines|
    Array(lines).each do |line|
      first_pairs << "#{file}:#{line}"
    end
  end

  last_pairs = Set.new
  (last["uncovered"] || {}).each do |file, lines|
    Array(lines).each do |line|
      last_pairs << "#{file}:#{line}"
    end
  end

  newly_uncovered = last_pairs - first_pairs
  fixed_lines = first_pairs - last_pairs

  delta = first_uncovered_count - last_uncovered_count

  puts "=" * 80
  puts "Coverage metrics comparison"
  puts "=" * 80
  puts "Metrics directory: #{metrics_dir}"
  puts "Oldest snapshot: #{first_path}"
  puts "Latest  snapshot: #{last_path}"
  puts
  puts "Uncovered lines (oldest): #{first_uncovered_count}"
  puts "Uncovered lines (latest): #{last_uncovered_count}"
  puts "Net change: #{delta} #{if delta.positive?
                                 "(improved)"
                               else
                                 delta.negative? ? "(regressed)" : "(no change)"
                               end}"
  puts
  puts "Lines fixed (were uncovered, now covered): #{fixed_lines.size}"
  puts "Lines newly uncovered: #{newly_uncovered.size}"
  puts "=" * 80

  unless fixed_lines.empty?
    puts "\nFixed lines:"
    puts "-" * 80
    fixed_lines.sort.group_by { |entry| entry.split(":")[0] }.each do |file, entries|
      puts file
      entries.sort.each do |entry|
        # entry is "file:line"
        _, line = entry.split(":", 2)
        puts "  - #{file}:#{line}"
      end
    end
  end

  unless newly_uncovered.empty?
    puts "\nNewly uncovered lines:"
    puts "-" * 80
    newly_uncovered.sort.group_by { |entry| entry.split(":")[0] }.each do |file, entries|
      puts file
      entries.sort.each do |entry|
        _, line = entry.split(":", 2)
        puts "  - #{file}:#{line}"
      end
    end
  end
end

if options[:compare_metrics]
  compare_metrics_snapshots(options[:metrics_dir])
  exit 0
end

# Load coverage data
unless File.exist?(options[:coverage_path])
  warn "Error: Coverage file not found: #{options[:coverage_path]}"
  warn "Run tests first to generate coverage report: bin/rspec"
  exit 1
end

coverage_data = JSON.parse(File.read(options[:coverage_path]))
base_path = Pathname.new(Dir.pwd)

# Collect all uncovered lines
uncovered_lines = []

coverage_data["coverage"].each do |file_path, file_data|
  # Normalize file path
  normalized_path = file_path
  if file_path.start_with?("/")
    # Absolute path - make relative to base
    begin
      normalized_path = Pathname.new(file_path).relative_path_from(base_path).to_s
    rescue ArgumentError
      # If relative path calculation fails, use as-is
      normalized_path = file_path
    end
  end

  # Apply file filter if specified
  if options[:file_filter] && !normalized_path.include?(options[:file_filter])
    next
  end

  lines = file_data["lines"] || []
  lines.each_with_index do |hits, line_number|
    # Line numbers are 1-indexed in the array (index 0 = line 1)
    actual_line_number = line_number + 1

    # hits is 0 for uncovered lines, null for non-executable lines
    if hits == 0
      uncovered_lines << {
        file: normalized_path,
        line: actual_line_number,
        absolute_path: file_path
      }
    end
  end
end

# Group uncovered lines by file
uncovered_by_file = uncovered_lines.group_by { |item| item[:file] }

# Sort files alphabetically
sorted_files = uncovered_by_file.keys.sort

# Persist metrics snapshot for future comparison
FileUtils.mkdir_p(options[:metrics_dir])
timestamp = Time.now.utc.strftime("%Y%m%d%H%M%S")
snapshot_path = File.join(options[:metrics_dir], "coverage_#{timestamp}.json")

snapshot_data = {
  "timestamp" => Time.now.utc.iso8601,
  "coverage_path" => options[:coverage_path],
  "total_uncovered" => uncovered_lines.length,
  "files_with_uncovered" => sorted_files.length,
  "uncovered" => uncovered_by_file.transform_values { |items| items.map { |i| i[:line] }.sort }
}

File.write(snapshot_path, JSON.pretty_generate(snapshot_data))

# Process each file
sorted_files.each do |file|
  lines = uncovered_by_file[file].map { |item| item[:line] }.sort
  absolute_path = uncovered_by_file[file].first[:absolute_path]

  # Check if file exists
  unless File.exist?(absolute_path)
    warn "Warning: File not found: #{absolute_path}"
    next
  end

  # Read file content
  file_content = File.readlines(absolute_path, chomp: false)

  # Group consecutive or nearby lines
  groups = []
  current_group = [lines.first]

  lines[1..-1].each do |line_num|
    last_in_group = current_group.last
    if line_num - last_in_group <= options[:threshold]
      # Add to current group
      current_group << line_num
    else
      # Start new group
      groups << current_group
      current_group = [line_num]
    end
  end
  groups << current_group if current_group.any?

  # Print each group
  groups.each do |group|
    first_line = group.first
    last_line = group.last

    # Calculate range to show (1 line before first, uncovered lines, 1 line after last)
    start_line = [1, first_line - 1].max
    end_line = [file_content.length, last_line + 1].min

    puts "\n" + "=" * 80
    puts "#{file}:#{first_line}"
    if group.length > 1
      puts "#{file}:#{last_line}"
    end
    puts "=" * 80

    # Print lines with context
    (start_line..end_line).each do |line_num|
      line_content = file_content[line_num - 1] # Convert to 0-indexed
      line_content ||= "" # Handle nil

      if group.include?(line_num)
        # Uncovered line - mark it
        marker = ">>> #{file}:#{line_num}"
        puts "#{marker.ljust(40)} | #{line_content.rstrip}"
      else
        # Context line
        puts "#{line_num.to_s.rjust(6)} | #{line_content.rstrip}"
      end
    end
  end
end

# Summary
puts "\n" + "=" * 80
puts "Summary"
puts "=" * 80
puts "Total uncovered lines: #{uncovered_lines.length}"
puts "Files with uncovered lines: #{sorted_files.length}"
puts "=" * 80
