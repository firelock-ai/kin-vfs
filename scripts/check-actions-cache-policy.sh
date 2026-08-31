#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflow_root="${1:-${repo_root}/.github/workflows}"
action_root="${2:-$(dirname "${workflow_root}")/actions}"

ruby - "${workflow_root}" "${action_root}" <<'RUBY'
require "psych"
require "set"
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
  "steps.cargo-sources.outputs.cache-hit != 'true'"
).freeze
approved_step_actions = Set.new([
  "./.github/actions/rust-toolchain",
  "EmbarkStudios/cargo-deny-action@v2",
  "actions/cache/restore@v6",
  "actions/cache/save@v6",
  "actions/checkout@v7",
  "actions/upload-artifact@v7",
  "softprops/action-gh-release@v3",
]).freeze
approved_reusable_workflows = Set.new([
  "firelock-ai/kin-actions/.github/workflows/cargo-dependency-wave.yml@v0.1.32",
  "firelock-ai/kin-actions/.github/workflows/cargo-registry-release.yml@v0.1.32",
  "firelock-ai/kin-actions/.github/workflows/merge-queue-ejection-notice.yml@v0.1.31",
]).freeze

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

def false_value?(value)
  value == false || value.to_s.strip.downcase == "false"
end

def true_value?(value)
  value == true || value.to_s.strip.downcase == "true"
end

def cache_input_keys(mapping)
  with = mapping["with"]
  return [] unless with.is_a?(Hash)

  with.keys.select do |key|
    normalized = key.to_s.downcase
    next false unless normalized.include?("cache")

    value = with[key]
    next false if normalized == "cache-disabled" && true_value?(value)
    next false if normalized != "cache-disabled" && false_value?(value)

    true
  end
end


def inspect_default_cache_action(mapping, location, errors)
  action = mapping["uses"]
  return unless action.is_a?(String)

  action_name = action.downcase.split("@", 2).first
  with = mapping["with"].is_a?(Hash) ? mapping["with"] : {}
  case action_name
  when "actions/setup-node"
    unless with.key?("package-manager-cache") && false_value?(with["package-manager-cache"])
      errors << "#{location}: actions/setup-node must set package-manager-cache: false"
    end
  when "actions/setup-go"
    unless with.key?("cache") && false_value?(with["cache"])
      errors << "#{location}: actions/setup-go must set cache: false"
    end
  when "gradle/actions/setup-gradle"
    unless with.key?("cache-disabled") && true_value?(with["cache-disabled"])
      errors << "#{location}: gradle/actions/setup-gradle must set cache-disabled: true"
    end
  when "astral-sh/setup-uv"
    unless with.key?("enable-cache") && false_value?(with["enable-cache"])
      errors << "#{location}: astral-sh/setup-uv must set enable-cache: false"
    end
  when "docker/setup-buildx-action"
    unless with.key?("cache-binary") && false_value?(with["cache-binary"])
      errors << "#{location}: docker/setup-buildx-action must set cache-binary: false"
    end
  when "docker/setup-qemu-action"
    unless with.key?("cache-image") && false_value?(with["cache-image"])
      errors << "#{location}: docker/setup-qemu-action must set cache-image: false"
    end
  when "actions-rust-lang/setup-rust-toolchain", "jdx/mise-action", "goto-bus-stop/setup-zig"
    unless with.key?("cache") && false_value?(with["cache"])
      errors << "#{location}: #{action_name} must set cache: false"
    end
  when "oven-sh/setup-bun"
    unless with.key?("no-cache") && true_value?(with["no-cache"])
      errors << "#{location}: oven-sh/setup-bun must set no-cache: true"
    end
  end
end


def inspect_cached_target_redirect(mapping, location, errors)
  values = []
  env = mapping["env"]
  if env.is_a?(Hash)
    env.each do |key, value|
      values << value if key.to_s.casecmp("CARGO_TARGET_DIR").zero?
    end
  end
  run = mapping["run"]
  values << run if run.is_a?(String) && run.match?(/CARGO_TARGET_DIR\s*=/i)

  values.each do |value|
    normalized = value.to_s.downcase.tr("\\", "/")
    if normalized.include?(".cargo/git") || normalized.include?(".cargo/registry")
      errors << "#{location}: CARGO_TARGET_DIR must not redirect build output into cached Cargo sources"
    end
  end
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

    reusable = job["uses"]
    if reusable
      unless reusable.is_a?(String) && approved_reusable_workflows.include?(reusable)
        errors << "#{file_name}: job #{job_name.inspect} uses unapproved reusable workflow #{reusable.inspect}"
      end
      next
    end

    steps = job["steps"]
    next if steps.nil?
    unless steps.is_a?(Array)
      errors << "#{file_name}: job #{job_name.inspect} steps must be a YAML sequence"
      next
    end

    steps.each_with_index do |step, index|
      next unless step.is_a?(Hash)

      location = "#{file_name}: job #{job_name.inspect} step #{index + 1}"
      inspect_default_cache_action(step, location, errors)
      inspect_cached_target_redirect(step, location, errors)
      action = step["uses"]
      if action && (!action.is_a?(String) || !approved_step_actions.include?(action))
        errors << "#{location}: unapproved action identity #{action.inspect}"
      end
      next unless cache_like_action?(action)

      audited_mappings[step.object_id] = true
      with = step["with"]
      cache_paths = lines(with["path"]) if with.is_a?(Hash)
      key = with["key"] if with.is_a?(Hash)

      case action
      when restore_action
        restore_count += 1
        errors << "#{location}: restore id must be cargo-sources" unless step["id"] == "cargo-sources"
        errors << "#{location}: cache restore must run on every workflow ref" if step.key?("if")
        if steps.take(index).any? do |prior|
             prior.is_a?(Hash) && prior.key?("run") && prior["name"] != "Actions cache policy"
           end
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

  if file_name == "ci.yml"
    check_job = jobs["check"]
    if check_job.is_a?(Hash)
      %w[if continue-on-error needs uses].each do |attribute|
        if check_job.key?(attribute)
          errors << "ci.yml: required check job must not declare #{attribute}"
        end
      end
      matrix_entries = check_job.dig("strategy", "matrix", "include")
      ubuntu_entries = Array(matrix_entries).count do |entry|
        entry.is_a?(Hash) && entry["os"] == "ubuntu-latest"
      end
      unless ubuntu_entries == 1
        errors << "ci.yml: check matrix must contain exactly one ubuntu-latest policy runner"
      end

      policy_steps = Array(check_job["steps"]).select do |step|
        step.is_a?(Hash) && step["name"] == "Actions cache policy"
      end
      if policy_steps.length != 1
        errors << "ci.yml: check job must contain exactly one Actions cache policy step"
      else
        policy_step = policy_steps.first
        checkout_step = Array(check_job["steps"])[0]
        unless checkout_step.is_a?(Hash) && checkout_step.keys == ["uses"] &&
               checkout_step["uses"] == "actions/checkout@v7"
          errors << "ci.yml: required check job must begin with an exact current-ref checkout"
        end
        unless Array(check_job["steps"])[1].equal?(policy_step)
          errors << "ci.yml: Actions cache policy must be the first step after checkout"
        end
        expected_condition = "${{ matrix.os == 'ubuntu-latest' }}"
        expected_commands = [
          "scripts/check-actions-cache-policy.sh",
          "scripts/test-actions-cache-policy.sh",
        ]
        unless policy_step["if"] == expected_condition
          errors << "ci.yml: Actions cache policy must run on the required ubuntu-latest matrix leg"
        end
        unless lines(policy_step["run"]) == expected_commands
          errors << "ci.yml: Actions cache policy must run both exact guard commands without softening"
        end
        unless policy_step.keys.sort == ["if", "name", "run"]
          errors << "ci.yml: Actions cache policy step permits only name, if, and run"
        end
      end

      triggers = document["on"] || document[true]
      unless triggers.is_a?(Hash) && triggers.key?("pull_request") && triggers.key?("merge_group")
        errors << "ci.yml: cache policy authority requires pull_request and merge_group triggers"
      end
    else
      errors << "ci.yml: required check job is missing"
    end
  end

  if file_name == "cache-seed.yml"
    seed_job = jobs["seed"]
    if seed_job.is_a?(Hash)
      fetch_steps = Array(seed_job["steps"]).select do |step|
        step.is_a?(Hash) && step["id"] == "fetch_sources"
      end
      if fetch_steps.length != 1
        errors << "cache-seed.yml: seed job must contain exactly one fetch_sources step"
      else
        fetch_step = fetch_steps.first
        unless fetch_step["name"] == "Fetch dependency sources" &&
               fetch_step["run"] == "cargo fetch --locked" &&
               fetch_step.keys.sort == ["id", "name", "run"]
          errors << (
            "cache-seed.yml: fetch_sources must be an exact fail-hard locked fetch"
          )
        end
      end
    else
      errors << "cache-seed.yml: seed job is missing"
    end
  end

  # Catch cache actions hidden anywhere other than a direct audited job step.
  each_mapping(document) do |mapping|
    action = mapping["uses"]
    inspect_default_cache_action(mapping, file_name, errors)
    inspect_cached_target_redirect(mapping, file_name, errors)
    input_keys = cache_input_keys(mapping)
    if !input_keys.empty? && !audited_mappings.key?(mapping.object_id)
      errors << (
        "#{file_name}: cache-enabling setup inputs are forbidden outside audited cache steps: " \
        "#{input_keys.map(&:to_s).sort.join(', ')}"
      )
    end

    next unless cache_like_action?(action)
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
    inspect_default_cache_action(mapping, relative_name, errors)
    inspect_cached_target_redirect(mapping, relative_name, errors)
    if action && (!action.is_a?(String) || !approved_step_actions.include?(action))
      errors << "#{relative_name}: unapproved composite action identity #{action.inspect}"
    end
    input_keys = cache_input_keys(mapping)
    unless input_keys.empty?
      errors << (
        "#{relative_name}: repo-local composite actions must not expose cache-enabling setup inputs"
      )
    end
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
