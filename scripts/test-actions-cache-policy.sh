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

case_root="$(make_case lookup-only-drift)"
perl -0pi -e 's/(        with:\n          path: \|)/        with:\n          lookup-only: true\n          path: |/' "${case_root}/ci.yml"
expect_rejection lookup-only-drift "${case_root}" "restore inputs must be exactly path, key, and restore-keys"

case_root="$(make_case fail-on-cache-miss-drift)"
perl -0pi -e 's/(        with:\n          path: \|)/        with:\n          fail-on-cache-miss: true\n          path: |/' "${case_root}/ci.yml"
expect_rejection fail-on-cache-miss-drift "${case_root}" "restore inputs must be exactly path, key, and restore-keys"

case_root="$(make_case setup-action-cache-input)"
perl -0pi -e 's#(      - uses: \./\.github/actions/rust-toolchain\n        with:\n)#$1          cache: cargo\n#' "${case_root}/ci.yml"
expect_rejection setup-action-cache-input "${case_root}" "cache-enabling setup inputs are forbidden"

case_root="$(make_case wrong-prefix)"
perl -0pi -e 's/cargo-sources-\n/cargo-pr-sources-\n/' "${case_root}/ci.yml"
expect_rejection wrong-prefix "${case_root}" "restore prefix must be"

case_root="$(make_case non-main-save)"
perl -0pi -e "s/if: github.ref == 'refs\/heads\/main' && steps.cargo-sources.outputs.cache-hit != 'true'/if: always()/" "${case_root}/cache-seed.yml"
expect_rejection non-main-save "${case_root}" "cache save must be restricted to a successful main cache miss"

case_root="$(make_case soft-fetch-step)"
perl -0pi -e 's/(        id: fetch_sources\n)/$1        continue-on-error: true\n/' "${case_root}/cache-seed.yml"
expect_rejection soft-fetch-step "${case_root}" "fetch_sources must be an exact fail-hard locked fetch"

case_root="$(make_case partial-fetch-softening)"
perl -0pi -e 's/run: cargo fetch --locked/run: cargo fetch --locked || true/' "${case_root}/cache-seed.yml"
expect_rejection partial-fetch-softening "${case_root}" "fetch_sources must be an exact fail-hard locked fetch"

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

case_root="$(make_case missing-policy-step)"
perl -0pi -e 's#      - name: Actions cache policy\n        if: \$\{\{ matrix\.os == '\''ubuntu-latest'\'' \}\}\n        run: \|\n          scripts/check-actions-cache-policy\.sh\n          scripts/test-actions-cache-policy\.sh\n##' "${case_root}/ci.yml"
expect_rejection missing-policy-step "${case_root}" "must contain exactly one Actions cache policy step"

case_root="$(make_case softened-policy-step)"
perl -0pi -e 's/(      - name: Actions cache policy\n)/$1        continue-on-error: true\n/' "${case_root}/ci.yml"
expect_rejection softened-policy-step "${case_root}" "permits only name, if, and run"

case_root="$(make_case skipped-policy-job)"
perl -0pi -e 's/(  check:\n)/$1    if: false\n/' "${case_root}/ci.yml"
expect_rejection skipped-policy-job "${case_root}" "required check job must not declare if"

case_root="$(make_case soft-policy-job)"
perl -0pi -e 's/(  check:\n)/$1    continue-on-error: true\n/' "${case_root}/ci.yml"
expect_rejection soft-policy-job "${case_root}" "required check job must not declare continue-on-error"

case_root="$(make_case checkout-main)"
perl -0pi -e 's/(      - uses: actions\/checkout\@v7\n)/$1        with:\n          ref: main\n/' "${case_root}/ci.yml"
expect_rejection checkout-main "${case_root}" "must begin with an exact current-ref checkout"

case_root="$(make_case late-policy-step)"
perl -0pi -e 's/(      - name: Actions cache policy\n.*?          scripts\/test-actions-cache-policy\.sh\n)/$block=$1; ""/se; s/(      - name: Format\n)/$1$block/' "${case_root}/ci.yml"
expect_rejection late-policy-step "${case_root}" "must be the first step after checkout"

case_root="$(make_case softened-policy-command)"
perl -0pi -e 's#scripts/check-actions-cache-policy\.sh#scripts/check-actions-cache-policy.sh || true#' "${case_root}/ci.yml"
expect_rejection softened-policy-command "${case_root}" "must run both exact guard commands without softening"

case_root="$(make_case displaced-policy-runner)"
perl -0pi -e "s/matrix\.os == 'ubuntu-latest'/matrix.os == 'windows-latest'/" "${case_root}/ci.yml"
expect_rejection displaced-policy-runner "${case_root}" "must run on the required ubuntu-latest matrix leg"

case_root="$(make_case missing-policy-runner)"
perl -0pi -e 's/os: ubuntu-latest/os: ubuntu-22.04/' "${case_root}/ci.yml"
expect_rejection missing-policy-runner "${case_root}" "check matrix must contain exactly one ubuntu-latest policy runner"

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

case_root="$(make_case composite-cache-input)"
printf '%s\n' \
  '    - name: Hidden setup cache' \
  '      uses: actions/setup-node@v6' \
  '      with:' \
  '        CaChE: npm' >> "${case_root}/../actions/rust-toolchain/action.yml"
expect_rejection composite-cache-input "${case_root}" "repo-local composite actions must not expose cache-enabling setup inputs"

case_root="$(make_case setup-node-default-cache)"
perl -0pi -e 's!\z!\n      - uses: actions/setup-node\@v6\n!' "${case_root}/ci.yml"
expect_rejection setup-node-default-cache "${case_root}" "actions/setup-node must set package-manager-cache: false"

case_root="$(make_case setup-go-default-cache)"
perl -0pi -e 's!\z!\n      - uses: actions/setup-go\@v6\n!' "${case_root}/ci.yml"
expect_rejection setup-go-default-cache "${case_root}" "actions/setup-go must set cache: false"

case_root="$(make_case setup-gradle-default-cache)"
perl -0pi -e 's!\z!\n      - uses: gradle/actions/setup-gradle\@v4\n!' "${case_root}/ci.yml"
expect_rejection setup-gradle-default-cache "${case_root}" "gradle/actions/setup-gradle must set cache-disabled: true"

case_root="$(make_case setup-uv-default-cache)"
perl -0pi -e 's!\z!\n      - uses: astral-sh/setup-uv\@v6\n!' "${case_root}/ci.yml"
expect_rejection setup-uv-default-cache "${case_root}" "astral-sh/setup-uv must set enable-cache: false"

case_root="$(make_case setup-buildx-default-cache)"
perl -0pi -e 's!\z!\n      - uses: docker/setup-buildx-action\@v3\n!' "${case_root}/ci.yml"
expect_rejection setup-buildx-default-cache "${case_root}" "docker/setup-buildx-action must set cache-binary: false"

case_root="$(make_case cached-target-redirect)"
perl -0pi -e 's/(      - name: Format\n)/$1        env:\n          CARGO_TARGET_DIR: \/home\/runner\/.cargo\/git\/target\n/' "${case_root}/ci.yml"
expect_rejection cached-target-redirect "${case_root}" "CARGO_TARGET_DIR must not redirect build output into cached Cargo sources"

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
