#!/usr/bin/env bash
# Keep the old entry point; the checker and its config can be moved together.
set -e
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$script_dir/build-check/check_build.py" "$@"
