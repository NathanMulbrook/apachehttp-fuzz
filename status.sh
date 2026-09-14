#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MAX_CONFIG=35
CONFIG="all"

for arg in "$@"; do
    case "$arg" in
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --help | -h)
        echo "Usage: ./status.sh [--config=N|a|all]"
        echo "  N selects one configuration from 1-$MAX_CONFIG."
        exit 0
        ;;
    *)
        echo "Unknown argument: $arg" >&2
        exit 1
        ;;
    esac
done

config_ids=()
for ((config_id = 1; config_id <= MAX_CONFIG; config_id++)); do
    config_ids+=("$config_id")
done

if [ "$CONFIG" != "all" ] && [ "$CONFIG" != "a" ]; then
    found=0
    for config_id in "${config_ids[@]}"; do
        if [ "$config_id" = "$CONFIG" ]; then
            config_ids=("$config_id")
            found=1
            break
        fi
    done
    if [ "$found" -eq 0 ]; then
        echo "Configuration '$CONFIG' is not available." >&2
        exit 1
    fi
fi

if [ -d "$directory/corpus" ]; then
    read -r corpus_files corpus_latest < <(
        find "$directory/corpus" -maxdepth 1 -type f -printf '%T@\n' |
            awk '{ count++; if ($1 > latest) latest=$1 }
                 END { printf "%d %d\n", count, int(latest) }'
    )
    corpus_size="$(du -sh "$directory/corpus" | awk '{print $1}')"
else
    corpus_files=0
    corpus_latest=0
    corpus_size=0
fi
now="$(date +%s)"
boot_time="$(awk '$1 == "btime" { print $2; exit }' /proc/stat 2>/dev/null || true)"
clock_ticks="$(getconf CLK_TCK 2>/dev/null || true)"
if [ "$corpus_latest" -gt 0 ]; then
    corpus_age="$((now - corpus_latest))"
    if [ "$corpus_age" -lt 0 ]; then
        corpus_age=0
    fi
else
    corpus_age=0
fi

fuzzing=0
server_only=0
stopped=0
lines=()

for config_id in "${config_ids[@]}"; do
    run_dir="$directory/run/run_$config_id"
    pid_file="$run_dir/logs/httpd.pid"
    state="stopped"
    detail=""
    process_start=0

    if [ -f "$pid_file" ]; then
        read -r pid < "$pid_file"
        case "$pid" in
        '' | *[!0-9]*) pid="" ;;
        esac
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            expected_exe="$(realpath -m "$run_dir/bin/httpd")"
            actual_exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
            actual_exe="${actual_exe% (deleted)}"
            if [ "$actual_exe" = "$expected_exe" ]; then
                start_ticks="$(awk '{ print $22 }' "/proc/$pid/stat" 2>/dev/null || true)"
                if [[ "$boot_time" =~ ^[0-9]+$ ]] &&
                        [[ "$clock_ticks" =~ ^[1-9][0-9]*$ ]] &&
                        [[ "$start_ticks" =~ ^[0-9]+$ ]]; then
                    process_start="$((boot_time + start_ticks / clock_ticks))"
                fi
                if tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -Fqx -- '-DNO_FUZZ'; then
                    state="server-only"
                    server_only="$((server_only + 1))"
                else
                    state="fuzzing"
                    fuzzing="$((fuzzing + 1))"
                fi
                read -r child_count max_cpu < <(
                    ps --ppid "$pid" -o %cpu= 2>/dev/null |
                        awk '{ count++; if ($1 > max) max=$1 }
                             END { printf "%d %.1f\n", count, max }'
                )
                detail="pid=$pid children=$child_count max-cpu=${max_cpu}%"
            fi
        fi
    fi

    if [ "$state" = "stopped" ]; then
        stopped="$((stopped + 1))"
    elif [ "$state" = "fuzzing" ]; then
        testcase_log="$directory/logs/testCases$config_id"
        if [ -f "$testcase_log" ]; then
            testcase_mtime="$(stat -c %Y "$testcase_log")"
            testcase_age="$((now - testcase_mtime))"
            if [ "$testcase_age" -lt 0 ]; then
                testcase_age=0
            fi
            detail+=" input-age=${testcase_age}s"
            if [ "$testcase_age" -gt 120 ]; then
                detail+=" STALE"
            fi
        else
            detail+=" no-input-log"
        fi

        error_log="$directory/logs/error$config_id"
        rotated_error_log="$directory/logs/old/error/error$config_id.1"
        if [ -f "$rotated_error_log" ]; then
            rotated_mtime="$(stat -c %Y "$rotated_error_log")"
            if [ "$process_start" -eq 0 ] || [ "$rotated_mtime" -le "$process_start" ]; then
                rotated_error_log=""
            fi
        fi
        if [ -f "$error_log" ] || [ -f "$rotated_error_log" ]; then
            progress="$({
                [ ! -f "$rotated_error_log" ] || tail -n 20000 "$rotated_error_log"
                [ ! -f "$error_log" ] || tail -n 20000 "$error_log"
            } |
                grep -aE '^#[0-9]+.*(pulse|INITED|NEW|REDUCE)' | tail -n 1 || true)"
            if [ -n "$progress" ]; then
                detail+=" ${progress:0:180}"
            else
                detail+=" starting"
            fi
        fi
    fi
    lines+=("$(printf 'config %2d  %-11s %s' "$config_id" "$state" "$detail")")
done

asan_errors=0
ubsan_reports=0
current_inputs=0
runtime_logs=()
for config_id in "${config_ids[@]}"; do
    shopt -s nullglob
    sanitizer_logs=("$directory"/logs/asan"$config_id".log.*)
    current_input_files=("$directory"/logs/currentInput"$config_id"-*)
    shopt -u nullglob
    runtime_logs+=("${sanitizer_logs[@]}")
    expected_exe="$(realpath -m "$directory/run/run_$config_id/bin/httpd")"
    for current_input_file in "${current_input_files[@]}"; do
        current_input_pid="${current_input_file##*-}"
        case "$current_input_pid" in
        '' | *[!0-9]*) actual_exe="" ;;
        *) actual_exe="$(readlink -f "/proc/$current_input_pid/exe" 2>/dev/null || true)" ;;
        esac
        actual_exe="${actual_exe% (deleted)}"
        if [ "$actual_exe" != "$expected_exe" ]; then
            current_inputs="$((current_inputs + 1))"
        fi
    done
    if [ -f "$directory/logs/error$config_id" ]; then
        runtime_logs+=("$directory/logs/error$config_id")
    fi
done
for runtime_log in "${runtime_logs[@]}"; do
    count="$(grep -ac 'ERROR: AddressSanitizer' "$runtime_log" 2>/dev/null || true)"
    asan_errors="$((asan_errors + count))"
    count="$(grep -ac 'runtime error:' "$runtime_log" 2>/dev/null || true)"
    ubsan_reports="$((ubsan_reports + count))"
done
crash_artifacts="$(find "$directory" -maxdepth 1 -type f \
    \( -name 'crash-*' -o -name 'timeout-*' -o -name 'leak-*' -o -name 'oom-*' \) |
    wc -l)"

echo "Configs: $fuzzing fuzzing, $server_only server-only, $stopped stopped"
echo "Corpus: $corpus_files files, $corpus_size, newest file ${corpus_age}s ago"
echo "Findings in selected logs: $asan_errors ASan errors, $ubsan_reports UBSan reports; $crash_artifacts global crash artifacts, $current_inputs preserved current inputs"
printf '%s\n' "${lines[@]}"
