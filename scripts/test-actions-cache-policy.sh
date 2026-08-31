#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
check="${repo_root}/scripts/check-actions-cache-policy.sh"
fixtures="$(mktemp -d)"
trap 'rm -rf "${fixtures}"' EXIT

make_case() {
  local name="$1"
  local case_root="${fixtures}/${name}"
  local workflow_root="${case_root}/.github/workflows"
  local action_root="${case_root}/.github/actions"
  mkdir -p "${workflow_root}" "${action_root}"
  cp "${repo_root}"/.github/workflows/*.yml "${workflow_root}/"
  cp -R "${repo_root}/.github/actions/." "${action_root}/"
  printf '%s\n' "${workflow_root}"
}

expect_rejection() {
  local name="$1"
  local workflow_root="$2"
  local expected="$3"
  local output
  if output="$("${check}" "${workflow_root}" 2>&1)"; then
    echo "FAIL: ${name} falsifier was accepted" >&2
    exit 1
  fi
  if ! grep -Fq "${expected}" <<<"${output}"; then
    echo "FAIL: ${name} failed for the wrong reason" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  echo "OK: ${name} rejected"
}

"${check}" "${repo_root}/.github/workflows"

case_root="$(make_case target-output)"
perl -0pi -e 's#(~/.cargo/git\n)#$1            target\n#' "${case_root}/ci.yml"
expect_rejection target-output "${case_root}" "target output is forbidden"

case_root="$(make_case dynamic-sha-key)"
perl -0pi -e 's/cargo-sources-v1/cargo-sources-\$\{\{ github.sha \}\}/' "${case_root}/ci.yml"
expect_rejection dynamic-sha-key "${case_root}" "restore key must be the bounded platform epoch"

case_root="$(make_case dynamic-ref-key)"
perl -0pi -e 's/cargo-sources-v1/cargo-sources-\$\{\{ github.ref \}\}/' "${case_root}/ci.yml"
expect_rejection dynamic-ref-key "${case_root}" "restore key must be the bounded platform epoch"

case_root="$(make_case monolithic-action)"
perl -0pi -e 's#actions/cache/restore\@v6#actions/cache\@v6#' "${case_root}/ci.yml"
expect_rejection monolithic-action "${case_root}" "unapproved cache action"

case_root="$(make_case third-party-target-cache)"
perl -0pi -e 's#actions/cache/restore\@v6#Swatinem/rust-cache\@v2#' "${case_root}/ci.yml"
expect_rejection third-party-target-cache "${case_root}" "unapproved cache action"

case_root="$(make_case uppercase-cache-action)"
perl -0pi -e 's#actions/cache/restore\@v6#Actions/CACHE/restore\@v6#' "${case_root}/ci.yml"
expect_rejection uppercase-cache-action "${case_root}" "unapproved cache action"

case_root="$(make_case escaped-cache-action)"
perl -0pi -e 's#uses: actions/cache/restore\@v6#uses: "actions/\\u0063ache\@v6"#' "${case_root}/ci.yml"
expect_rejection escaped-cache-action "${case_root}" "unapproved cache action"

case_root="$(make_case conditional-restore)"
perl -0pi -e "s/(      - name: Restore cargo sources\n)/\$1        if: github.event_name == 'pull_request'\n/" "${case_root}/ci.yml"
expect_rejection conditional-restore "${case_root}" "cache restore must run on every workflow ref"

case_root="$(make_case wrong-prefix)"
perl -0pi -e 's/cargo-sources-\n/cargo-pr-sources-\n/' "${case_root}/ci.yml"
expect_rejection wrong-prefix "${case_root}" "restore prefix must be"

case_root="$(make_case non-main-save)"
perl -0pi -e "s/if: github.ref == 'refs\/heads\/main'.*steps.fetch_sources.outcome == 'success'/if: always()/" "${case_root}/cache-seed.yml"
expect_rejection non-main-save "${case_root}" "cache save must be restricted to a successful main cache miss"

case_root="$(make_case hardcoded-save-key)"
perl -0pi -e 's/\$\{\{ steps\.cargo-sources\.outputs\.cache-primary-key \}\}/hardcoded-cache-key/' "${case_root}/cache-seed.yml"
expect_rejection hardcoded-save-key "${case_root}" "save key must come from the restore primary key"

case_root="$(make_case late-step-after-save)"
printf '%s\n' '      - name: Late work' '        run: cargo fetch --locked' >> "${case_root}/cache-seed.yml"
expect_rejection late-step-after-save "${case_root}" "cache save must be the last declared job step"

case_root="$(make_case run-before-restore)"
perl -0pi -e 's/(      - name: Restore cargo sources\n)/      - name: Cargo work before restore\n        run: cargo fetch --locked\n\n$1/' "${case_root}/ci.yml"
expect_rejection run-before-restore "${case_root}" "cache restore must precede every run step"

case_root="$(make_case duplicate-condition-key)"
perl -0pi -e "s/(      - name: Restore cargo sources\n)/\$1        if: true\n        if: false\n/" "${case_root}/ci.yml"
expect_rejection duplicate-condition-key "${case_root}" "duplicate YAML mapping key"

case_root="$(make_case yaml-alias)"
perl -0pi -e 's/name: Cache Seed/name: \&cache_name Cache Seed\nrun-name: *cache_name/' "${case_root}/cache-seed.yml"
expect_rejection yaml-alias "${case_root}" "YAML aliases are forbidden in workflow policy"

case_root="$(make_case composite-cache-action)"
printf '%s\n' \
  '    - name: Hidden target cache' \
  '      uses: actions/cache@v6' \
  '      with:' \
  '        path: target' \
  '        key: hidden-target' >> "${case_root}/../actions/rust-toolchain/action.yml"
expect_rejection composite-cache-action "${case_root}" "repo-local composite actions must not invoke cache actions"

case_root="$(make_case unexpected-workflow-cache)"
# Literal GitHub expressions belong in the fixture and must not expand here.
# shellcheck disable=SC2016
printf '%s\n' \
  'name: Hidden cache' \
  'on: workflow_dispatch' \
  'jobs:' \
  '  hidden:' \
  '    runs-on: ubuntu-latest' \
  '    steps:' \
  '      - uses: actions/cache/restore@v6' \
  '        id: cargo-sources' \
  '        with:' \
  '          path: |' \
  '            ~/.cargo/registry' \
  '            ~/.cargo/git' \
  '          key: ${{ runner.os }}-${{ runner.arch }}-cargo-sources-v1' \
  '          restore-keys: |' \
  '            ${{ runner.os }}-${{ runner.arch }}-cargo-sources-' > "${case_root}/hidden.yml"
expect_rejection unexpected-workflow-cache "${case_root}" "unexpected cache action"

echo "OK: all Actions cache policy falsifiers were rejected."
