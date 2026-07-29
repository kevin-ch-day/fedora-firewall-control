#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cmake -S "$repo_root" -B "$repo_root/build" -G Ninja -DBUILD_TESTING=ON
cmake --build "$repo_root/build"
ctest --test-dir "$repo_root/build" --output-on-failure
