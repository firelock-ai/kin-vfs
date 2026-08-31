#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow_root="${1:-${repo_root}/.github/workflows}"
action_root="${2:-$(dirname "${workflow_root}")/actions}"

ruby - "${workflow_root}" "${action_root}" <<'RUBY'
require "psych"
require "yaml"

workflow_root = File.expand_path(ARGV.fetch(0))
action_root = File.expand_path(ARGV.fetch(1))
abort("FAIL: workflow directory does not exist: #{workflow_root}") unless Dir.exist?(workflow_root)

expected_counts = {
  "cache-seed.yml" => [1, 1],
  "ci.yml" => [4, 0],
  "fuzz.yml" => [1, 0],
}.freeze
allowed_paths = ["~/.cargo/registry", "~/.cargo/git"].freeze
restore_action = "actions/cache/restore@v6"
save_action = "actions/cache/save@v6"
restore_key = "${{ runner.os }}-${{ runner.arch }}-cargo-sources-v1"
restore_prefix = "${{ runner.os }}-${{ runner.arch }}-cargo-sources-"
save_key = "${{ steps.cargo-sources.outputs.cache-primary-key }}"
save_condition = (
  "github.ref == 'refs/heads/main' && " \
  "steps.cargo-sources.outputs.cache-hit != 'true' && " \
  "steps.fetch_sources.outcome == 'success'"
).freeze

errors = []
counts = {}
workflow_files = Dir[File.join(workflow_root, "*.{yml,yaml}")].sort
abort("FAIL: no workflow files found under #{workflow_root}") if workflow_files.empty?

def inspect_yaml_node(node, file_name, errors)
  case node
  when Psych::Nodes::Alias
    errors << "#{file_name}:#{node.start_line + 1}: YAML aliases are forbidden in workflow policy"
  when Psych::Nodes::Mapping
    seen = {}
    node.children.each_slice(2) do |key_node, value_node|
      unless key_node.is_a?(Psych::Nodes::Scalar)
        errors << "#{file_name}:#{key_node.start_line + 1}: complex YAML mapping keys are forbidden"
        inspect_yaml_node(value_node, file_name, errors)
        next
      end

      key = key_node.value
      if seen.key?(key)
        errors << (
          "#{file_name}:#{key_node.start_line + 1}: duplicate YAML mapping key #{key.inspect}; " \
          "first declared at line #{seen.fetch(key)}"
        )
      else
        seen[key] = key_node.start_line + 1
      end
      inspect_yaml_node(value_node, file_name, errors)
    end
  else
    Array(node.children).each { |child| inspect_yaml_node(child, file_name, errors) }
  end
end

def lines(value)
  return nil unless value.is_a?(String)

  value.lines.map(&:strip).reject(&:empty?)
end

def each_mapping(value, &block)
  case value
  when Hash
    yield(value)
    value.each_value { |child| each_mapping(child, &block) }
  when Array
    value.each { |child| each_mapping(child, &block) }
  end
end

def cache_like_action?(value)
  value.is_a?(String) && value.downcase.include?("cache")
end

def parse_yaml(path, display_name, errors)
  content = File.read(path, encoding: "UTF-8")
  syntax_tree = Psych.parse_stream(content, filename: path)
  inspect_yaml_node(syntax_tree, display_name, errors)
  YAML.safe_load(
    content,
    permitted_classes: [],
    permitted_symbols: [],
    aliases: false,
    filename: path,
  )
rescue Psych::Exception => error
  errors << "#{display_name}: YAML parse failed: #{error.message}"
  nil
end

workflow_files.each do |workflow|
  file_name = File.basename(workflow)
  document = parse_yaml(workflow, file_name, errors)
  unless document.is_a?(Hash)
    counts[file_name] = [0, 0]
    next
  end

  jobs = document["jobs"]
  unless jobs.is_a?(Hash)
    errors << "#{file_name}: jobs must be a YAML mapping"
    counts[file_name] = [0, 0]
    next
  end

  restore_count = 0
  save_count = 0
  audited_mappings = {}

  jobs.each do |job_name, job|
    next unless job.is_a?(Hash)

    steps = job["steps"]
    next if steps.nil?
    unless steps.is_a?(Array)
      errors << "#{file_name}: job #{job_name.inspect} steps must be a YAML sequence"
      next
    end

    steps.each_with_index do |step, index|
      next unless step.is_a?(Hash)

      action = step["uses"]
      next unless cache_like_action?(action)

      audited_mappings[step.object_id] = true
      location = "#{file_name}: job #{job_name.inspect} step #{index + 1}"
      with = step["with"]
      cache_paths = lines(with["path"]) if with.is_a?(Hash)
      key = with["key"] if with.is_a?(Hash)

      case action
      when restore_action
        restore_count += 1
        errors << "#{location}: restore id must be cargo-sources" unless step["id"] == "cargo-sources"
        errors << "#{location}: cache restore must run on every workflow ref" if step.key?("if")
        if steps.take(index).any? { |prior| prior.is_a?(Hash) && prior.key?("run") }
          errors << "#{location}: cache restore must precede every run step"
        end
        if key != restore_key
          errors << "#{location}: restore key must be the bounded platform epoch #{restore_key}"
        end
        restore_keys = lines(with["restore-keys"]) if with.is_a?(Hash)
        if restore_keys != [restore_prefix]
          errors << "#{location}: restore prefix must be #{restore_prefix}"
        end
        unless with.is_a?(Hash) && with.keys.sort == ["key", "path", "restore-keys"]
          errors << "#{location}: restore inputs must be exactly path, key, and restore-keys"
        end
      when save_action
        save_count += 1
        if step["if"] != save_condition
          errors << "#{location}: cache save must be restricted to a successful main cache miss"
        end
        errors << "#{location}: save key must come from the restore primary key" unless key == save_key
        errors << "#{location}: cache save must be the last declared job step" unless index == steps.length - 1
        unless steps.take(index).any? do |prior|
                 prior.is_a?(Hash) && prior["id"] == "cargo-sources" && prior["uses"] == restore_action
               end
          errors << "#{location}: cache save must follow cargo-sources restore in the same job"
        end
        unless with.is_a?(Hash) && with.keys.sort == ["key", "path"]
          errors << "#{location}: save inputs must be exactly path and key"
        end
      else
        errors << (
          "#{location}: unapproved cache action #{action.inspect}; use #{restore_action} or #{save_action}"
        )
      end

      if cache_paths != allowed_paths
        errors << (
          "#{location}: cache paths must be exactly #{allowed_paths.inspect}; target output is forbidden"
        )
      end
      if cache_paths&.any? { |path| path.downcase.split(/[\\\/]/).include?("target") }
        errors << "#{location}: target output is forbidden in Actions caches"
      end
    end
  end

  # Catch cache actions hidden anywhere other than a direct audited job step.
  each_mapping(document) do |mapping|
    next unless cache_like_action?(mapping["uses"])
    next if audited_mappings.key?(mapping.object_id)

    errors << "#{file_name}: cache action appears outside an audited workflow job step"
  end

  counts[file_name] = [restore_count, save_count]
end

# A repo-local composite action could otherwise reintroduce an unbounded cache
# without changing any workflow's direct steps.
Dir[File.join(action_root, "**", "*.{yml,yaml}")].sort.each do |action_file|
  relative_name = action_file.delete_prefix("#{action_root}/")
  document = parse_yaml(action_file, relative_name, errors)
  next if document.nil?

  each_mapping(document) do |mapping|
    action = mapping["uses"]
    next unless cache_like_action?(action)

    errors << (
      "#{relative_name}: repo-local composite actions must not invoke cache actions; " \
      "declare bounded caches in an audited workflow job"
    )
  end
end

expected_counts.each do |workflow_name, expected|
  actual = counts.fetch(workflow_name, [0, 0])
  next if actual == expected

  errors << (
    "#{workflow_name}: expected #{expected[0]} restore and #{expected[1]} save steps; " \
    "found #{actual[0]} restore and #{actual[1]} save steps"
  )
end

counts.each do |workflow_name, actual|
  next if expected_counts.key?(workflow_name) || actual == [0, 0]

  errors << "#{workflow_name}: unexpected cache action; add it to the bounded policy deliberately"
end

unless errors.empty?
  warn("FAIL: GitHub Actions cache policy is not bounded:")
  errors.each { |error| warn("  - #{error}") }
  exit(1)
end

puts(
  "OK: Actions caches are source-only and platform-bounded; all refs restore, " \
  "and only the successful main seed saves (6 restores, 1 save)."
)
RUBY
