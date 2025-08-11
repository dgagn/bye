#!/usr/bin/env bash
set -euo pipefail

# Usage: ./release.sh <new-version>
if [ $# -ne 1 ]; then
  echo "Usage: $0 {major|minor|patch|<explicit-version>}"
  exit 1
fi

ARG=$1

trap 'echo "Release failed. Removing tag v$NEW_VERSION"; git tag -d "v$NEW_VERSION" >/dev/null 2>&1 || true; exit 1' ERR

CUR_VER=$(grep '^version' Cargo.toml | head -n1 | sed -E 's/version *= *"([^"]+)"/\1/')
if [[ ! $CUR_VER =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Couldn't parse current version from Cargo.toml"
  exit 1
fi

IFS='.' read -r MAJOR MINOR PATCH <<< "$CUR_VER"

case "$ARG" in
  major)
    NEW_MAJOR=$((MAJOR + 1))
    NEW_MINOR=0
    NEW_PATCH=0
    ;;
  minor)
    NEW_MAJOR=$MAJOR
    NEW_MINOR=$((MINOR + 1))
    NEW_PATCH=0
    ;;
  patch)
    NEW_MAJOR=$MAJOR
    NEW_MINOR=$MINOR
    NEW_PATCH=$((PATCH + 1))
    ;;
  *)
    if [[ $ARG =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      NEW_MAJOR=${ARG%%.*}
      NEW_MINOR=$(echo "$ARG" | cut -d. -f2)
      NEW_PATCH=${ARG##*.}
    else
      echo "Invalid argument: must be major, minor, patch, or explicit  X.Y.Z"
      exit 1
    fi
    ;;
esac

NEW_VERSION="$NEW_MAJOR.$NEW_MINOR.$NEW_PATCH"
echo "Bumping version: $CUR_VER to $NEW_VERSION"

if ! command -v cargo-set-version &> /dev/null; then
  echo "Installing cargo-set-version (cargo-edit)"
  cargo install cargo-edit
fi

cargo set-version "$NEW_VERSION"

git add Cargo.toml
git commit -m "chore(release): v$NEW_VERSION"

git tag "v$NEW_VERSION"
git push origin HEAD
git push origin "v$NEW_VERSION"

echo "Publishing v$NEW_VERSION to crates.io"
if ! cargo publish; then
  echo "Publish failed, retrying with --allow-dirty"
  cargo publish --allow-dirty
fi

echo "Released v$NEW_VERSION"
