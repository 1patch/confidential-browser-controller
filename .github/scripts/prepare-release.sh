#!/usr/bin/env bash
set -euo pipefail

# This is an operator dispatch from the default branch, never a PR trigger.
# Existing tags and ambiguous API replies stop the release; nothing is retried.
[[ "${GITHUB_REF:-}" == "refs/heads/${DEFAULT_BRANCH:?}" ]] || exit 1
[[ "${GITHUB_SHA:-}" =~ ^[a-f0-9]{40}$ ]] || exit 1
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
[[ "${VERSION:-}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$ ]] || exit 1
git check-ref-format "refs/tags/$VERSION"

existing=$(gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$VERSION" \
  --jq ".[] | select(.ref == \"refs/tags/$VERSION\") | .object.sha")
if [[ -n "$existing" ]]; then
  echo 'Release tag already exists; inspect its evidence before any further action.' >&2
  exit 1
fi
gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \
  -f "ref=refs/tags/$VERSION" -f "sha=$GITHUB_SHA" --silent
gh workflow run tinfoil-release-publish.yml --repo "$GITHUB_REPOSITORY" --ref "$VERSION"
