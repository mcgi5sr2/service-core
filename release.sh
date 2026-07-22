#!/bin/bash
set -euo pipefail

# service-core is a LIBRARY: there is no image, no registry and no k3s manifest.
# A release here is a version bump, an annotated tag and a push — consumers pin
# that tag, so nothing moves until each service bumps its own `Cargo.toml`.
#
# Usage:
#   ./release.sh              # patch bump (0.3.2 -> 0.3.3)
#   ./release.sh minor        # minor bump (0.3.2 -> 0.4.0); pre-1.0 this may break consumers
#   ./release.sh 0.4.0        # explicit version
#
# Prerequisites (one-time): an `origin` remote with push rights over SSH.

BUMP="${1:-patch}"

# --- freshness guard ---------------------------------------------------------
# A tag must name EXACTLY what the branch says. A dirty tree tags uncommitted
# edits; a stale checkout tags a commit that lacks work the branch claims to
# have. Both have bitten this estate. RELEASE_FORCE=1 overrides, knowingly.
if [ "${RELEASE_FORCE:-0}" != "1" ]; then
  if [ -n "$(git status --porcelain)" ]; then
    echo "release: REFUSING — working tree is dirty; commit or stash first (RELEASE_FORCE=1 overrides):" >&2
    git status --short >&2
    exit 1
  fi
  branch=$(git branch --show-current)
  if [ "$branch" != "main" ]; then
    echo "release: REFUSING — on branch '$branch'; consumers pin tags cut from main (RELEASE_FORCE=1 overrides)." >&2
    exit 1
  fi
  git fetch origin --quiet || echo "release: WARN — could not fetch origin; freshness unverified" >&2
  if git rev-parse --verify -q "origin/$branch" >/dev/null; then
    behind=$(git rev-list --count "HEAD..origin/$branch")
    if [ "$behind" -gt 0 ]; then
      echo "release: REFUSING — checkout is $behind commit(s) behind origin/$branch; pull first (RELEASE_FORCE=1 overrides)." >&2
      exit 1
    fi
  fi
fi
# -----------------------------------------------------------------------------

# --- gates -------------------------------------------------------------------
# Run BEFORE the version bump, so a failure leaves the tree untouched. Both
# feature sets are exercised: consumers differ (vigil takes `wg`, scribe and
# cadence take `wg` + `llm`), and a default-features-only check would miss a
# break in exactly the code this crate exists to share.
echo "==> tests + clippy (default features)"
cargo test --quiet
cargo clippy --all-targets -- -D warnings

echo "==> tests + clippy (all features)"
cargo test --quiet --all-features
cargo clippy --all-targets --all-features -- -D warnings

echo "==> cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
  # Fleet rule: no HIGH/CRITICAL advisories ship. Accepted no-fix advisories
  # belong in an audit.toml ignore list with a comment, not in an override here.
  cargo audit || {
    echo "release: REFUSING — cargo audit reported advisories; resolve or record them first." >&2
    exit 1
  }
else
  echo "release: WARN — cargo-audit not installed; RustSec advisories unchecked." >&2
  echo "         install with: cargo install cargo-audit --locked" >&2
fi
# -----------------------------------------------------------------------------

case "$BUMP" in
  patch|minor|major) cargo set-version --bump "$BUMP" ;;
  *)                 cargo set-version "$BUMP" ;;
esac
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
TAG="v$VERSION"

trap 'echo "RELEASE FAILED — reverting uncommitted version bump"; git checkout -- Cargo.toml Cargo.lock' ERR

# A tag is what consumers resolve against, so it must never be moved once
# pushed. Refuse rather than clobber.
if git rev-parse --verify -q "refs/tags/$TAG" >/dev/null; then
  echo "release: REFUSING — tag $TAG already exists locally." >&2
  exit 1
fi
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
  echo "release: REFUSING — tag $TAG already exists on origin." >&2
  exit 1
fi

echo "Releasing service-core $TAG"
git add Cargo.toml Cargo.lock
git commit -m "chore: $VERSION"
git tag -a "$TAG" -m "$TAG"
git push origin main
git push origin "$TAG"
trap - ERR

cat <<EOF

Done — service-core $TAG is on origin.

Nothing picks it up until each consumer bumps its pin. In the consuming repo:

  service-core = { git = "https://github.com/mcgi5sr2/service-core.git", tag = "$TAG", ... }

then \`cargo check\` to refresh Cargo.lock, and release that service as usual.
Consumers today: vigil, scribe, cadence.
EOF
