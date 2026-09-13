#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MAX_CONFIG=32
source "$directory/toolchain/use-llvm.sh"

usage() {
    echo "Usage: ./genreport.sh [PROFILE_SESSION BUILD_CONFIG|a|all]"
    echo "With no arguments, report every config in the latest completed session."
    echo "Example: ./genreport.sh logs/profiles/20260912T190000Z-1234 12"
    exit 1
}

report_config() {
    local profile_session="$1"
    local build_config="$2"
    local profile_dir="$profile_session/run_$build_config"
    local run_dir="$directory/run/run_$build_config"
    local binary="$run_dir/bin/httpd"
    local report_dir="$directory/logs/coverage/$(basename "$profile_session")/run_$build_config"
    local profile
    local profiles

    if [[ ! "$build_config" =~ ^[1-9][0-9]*$ ]] ||
            [ "$build_config" -lt 1 ] || [ "$build_config" -gt "$MAX_CONFIG" ]; then
        echo "Build config must be 1-$MAX_CONFIG."
        exit 1
    fi
    if [ ! -x "$binary" ]; then
        echo "Missing fuzzer binary: $binary"
        exit 1
    fi

    mapfile -t profiles < <(find "$profile_dir" -type f -name '*.profraw' | sort)
    if [ "${#profiles[@]}" -eq 0 ]; then
        echo "No profiles found in $profile_dir"
        exit 1
    fi

    for profile in "${profiles[@]}"; do
        if [ ! -s "$profile" ]; then
            echo "Empty profile: $profile"
            exit 1
        fi
        llvm-profdata show "$profile" >/dev/null
    done

    mkdir -p "$report_dir"
    llvm-profdata merge -sparse -failure-mode=any "${profiles[@]}" \
        -o "$report_dir/coverage.profdata"
    llvm-cov report "$binary" \
        -instr-profile="$report_dir/coverage.profdata" >"$report_dir/coverage.txt"
    llvm-cov show "$binary" -format=html \
        -instr-profile="$report_dir/coverage.profdata" >"$report_dir/coverage.html"

    echo "Coverage report: $report_dir/coverage.txt"
}

report_all_configs() {
    local profile_session="$1"
    local config
    local configs

    mapfile -t configs < <(
        find "$profile_session" -mindepth 1 -maxdepth 1 -type d -name 'run_*' \
            -printf '%f\n' | sed 's/^run_//' | sort -n
    )
    if [ "${#configs[@]}" -eq 0 ]; then
        echo "No config profiles found in $profile_session"
        exit 1
    fi
    for config in "${configs[@]}"; do
        report_config "$profile_session" "$config"
    done
}

if [ "$#" -eq 0 ]; then
    mapfile -t completed_sessions < <(
        find "$directory/logs/profiles" -mindepth 2 -maxdepth 2 -type f \
            -name .complete -printf '%h\n' | sort -r
    )
    profile_session="${completed_sessions[0]:-}"

    if [ -z "$profile_session" ]; then
        echo "No completed profile session found."
        exit 1
    fi

    report_all_configs "$profile_session"
elif [ "$#" -eq 2 ]; then
    profile_session="$(realpath "$1")"
    if [ "$2" = a ] || [ "$2" = all ]; then
        report_all_configs "$profile_session"
    else
        report_config "$profile_session" "$2"
    fi
else
    usage
fi
