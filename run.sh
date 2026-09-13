#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory" || exit 1
FUZZ=""
CONFIG="all"
LOG_OUTPUT=1
PACKET_CAPTURE=0
MULTIPROCESS=""

for arg in "$@"; do
    case "$arg" in
    --fuzz | -f)
        FUZZ="-DNO_FUZZ"
        ;;
    --packet | -p)
        PACKET_CAPTURE=1
        ;;
    --multiprocess | -m)
        MULTIPROCESS="-DFUZZ_MULTIPROCESS"
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --LOG_OUPTUT | --log-output | -s)
        LOG_OUTPUT=0
        ;;
    --help | -h)
        echo "Usage: ./run.sh [--fuzz] [--packet] [--multiprocess] [--config=N|all] [--LOG_OUPTUT]"
        echo "  --fuzz runs Apache without the embedded fuzzer, matching the 389-ds interface."
        echo "  --multiprocess starts three Apache workers with shared covbridge feedback."
        exit
        ;;
    esac
done
case "$CONFIG" in
a | all | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20) ;;
*)
    echo "Config must be 1-20, a, or all." >&2
    exit 1
    ;;
esac

mkdir -p \
    "$directory/logs/old/build" \
    "$directory/logs/old/error" \
    "$directory/logs/old/asan" \
    "$directory/logs/old/testCases"
profile_dir="$directory/logs/profiles/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$profile_dir"

mkdir -p "$directory/run"
sed "s!tacos!$directory!g" "$directory/logrotate.conf" >"$directory/run/logrotate.conf"
logrotate --force "$directory/run/logrotate.conf" -s "$directory/logs/old/logrotate.status"

fuzzerpids=()
selected_configs=()

stop_pid_file() {
    local pid_file="$1"
    local expected="$2"
    local pid
    local executable
    local attempt

    [ -f "$pid_file" ] || return 0
    read -r pid <"$pid_file" || return 0
    case "$pid" in
    *[!0-9]* | "") return 0 ;;
    esac
    executable="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
    if [ "$executable" = "$expected" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        for attempt in {1..50}; do
            kill -0 "$pid" 2>/dev/null || return
            sleep 0.1
        done
        echo "Timed out stopping existing process $pid for $expected." >&2
        return 1
    fi
}

_term() {
    local result="${1:-0}"
    local attempt
    local config
    local profile
    local complete=1
    trap - SIGINT SIGTERM
    for fuzzerpid in "${fuzzerpids[@]}"; do
        kill -TERM "$fuzzerpid" 2>/dev/null || true
    done
    for fuzzerpid in "${fuzzerpids[@]}"; do
        for attempt in {1..50}; do
            kill -0 "$fuzzerpid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$fuzzerpid" 2>/dev/null; then
            echo "Timed out waiting for process $fuzzerpid to stop." >&2
            complete=0
        else
            wait "$fuzzerpid" 2>/dev/null || true
        fi
    done
    if [ "$result" = 0 ]; then
        for config in "${selected_configs[@]}"; do
            if ! find "$profile_dir/run_$config" -type f -name '*.profraw' \
                    -size +0c -print -quit | grep -q .; then
                complete=0
                break
            fi
            while IFS= read -r profile; do
                if [ ! -s "$profile" ]; then
                    complete=0
                    break 2
                fi
            done < <(find "$profile_dir/run_$config" -type f -name '*.profraw')
        done
        if [ "$complete" = 1 ] && [ "${#selected_configs[@]}" -gt 0 ]; then
            touch "$profile_dir/.complete"
        fi
    fi
    exit "$result"
}

trap _term SIGINT SIGTERM

run_fuzzer() {
    local run_dir="$directory/run/run_$BUILD_CONFIG"
    local binary="$run_dir/bin/httpd"
    local config_file="$run_dir/conf/httpd.conf"
    local pid_file="$run_dir/logs/httpd.pid"
    local profile_file
    local started_pid

    if [ ! -x "$binary" ] || [ ! -f "$config_file" ]; then
        echo "Config $BUILD_CONFIG is not built. Run ./build.sh -c=$BUILD_CONFIG -d first." >&2
        return 1
    fi

    stop_pid_file "$pid_file" "$binary" || return 1
    mkdir -p "$profile_dir/run_$BUILD_CONFIG"
    profile_file="$profile_dir/run_$BUILD_CONFIG/default-%m-%p.profraw"

    echo "LLVM_PROFILE_FILE=$profile_file $binary -f $config_file -DFOREGROUND $FUZZ $MULTIPROCESS"
    if [ "$LOG_OUTPUT" = 1 ]; then
        FUZZER_DEBUG=1 \
        LLVM_PROFILE_FILE="$profile_file" \
        ASAN_OPTIONS="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        LSAN_OPTIONS="detect_leaks=0" \
            "$binary" -f "$config_file" -DFOREGROUND $FUZZ $MULTIPROCESS \
            >>"$directory/logs/error$BUILD_CONFIG" 2>&1 &
    else
        FUZZER_DEBUG=1 \
        LLVM_PROFILE_FILE="$profile_file" \
        ASAN_OPTIONS="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        LSAN_OPTIONS="detect_leaks=0" \
            "$binary" -f "$config_file" -DFOREGROUND $FUZZ $MULTIPROCESS &
    fi
    started_pid=$!
    sleep 1
    if ! kill -0 "$started_pid" 2>/dev/null; then
        wait "$started_pid"
        echo "Config $BUILD_CONFIG exited during startup." >&2
        return 1
    fi
    fuzzerpids+=("$started_pid")
    selected_configs+=("$BUILD_CONFIG")
}

if [ "$PACKET_CAPTURE" = 1 ]; then
    if ! command -v tcpdump >/dev/null; then
        echo "tcpdump is required for --packet." >&2
        exit 1
    fi
    tcpdump -G 43200 -i lo ip6 \
        -w "$directory/logs/dump-%Y%m%dT%H%M%S-$$.pcap" -z gzip &
    capture_pid=$!
    sleep 1
    if ! kill -0 "$capture_pid" 2>/dev/null; then
        wait "$capture_pid"
        echo "tcpdump could not start. Give tcpdump scoped capture capabilities or omit --packet; do not run the fuzz stack as root." >&2
        exit 1
    fi
    fuzzerpids+=("$capture_pid")
fi

if [ "$CONFIG" = a ] || [ "$CONFIG" = all ]; then
    for BUILD_CONFIG in {1..20}; do
        run_fuzzer || _term 1
        sleep 0.1
    done
else
    BUILD_CONFIG="$CONFIG"
    run_fuzzer || _term 1
fi

while :; do
    sleep 60
    for fuzzerpid in "${fuzzerpids[@]}"; do
        if ! kill -0 "$fuzzerpid" 2>/dev/null; then
            echo "A fuzzing or capture process exited." >&2
            _term 1
        fi
    done
    "$directory/asanProcess.sh"
    logrotate "$directory/run/logrotate.conf" -s "$directory/logs/old/logrotate.status"
done
