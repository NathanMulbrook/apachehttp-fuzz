#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory" || exit 1
MAX_CONFIG=34
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
        echo "Usage: ./run.sh [--fuzz] [--packet] [--multiprocess] [--config=N|a|all] [--LOG_OUPTUT]"
        echo "  --config selects one configuration (1-$MAX_CONFIG) or all configurations."
        echo "  --fuzz runs Apache without the embedded fuzzer, matching the 389-ds interface."
        echo "  --multiprocess starts three Apache workers with shared covbridge feedback."
        exit
        ;;
    esac
done
if [ "$CONFIG" != a ] && [ "$CONFIG" != all ] &&
        { [[ ! "$CONFIG" =~ ^[1-9][0-9]*$ ]] ||
            [ "$CONFIG" -lt 1 ] || [ "$CONFIG" -gt "$MAX_CONFIG" ]; }; then
    echo "Config must be 1-$MAX_CONFIG, a, or all." >&2
    exit 1
fi

mkdir -p "$directory/run"
if [ "${APACHEHTTP_FUZZ_RUN_LOCKED:-0}" != 1 ]; then
    APACHEHTTP_FUZZ_RUN_LOCKED=1 flock -n -o -E 75 \
        "$directory/run/run.lock" "$directory/run.sh" "$@"
    lock_status=$?
    if [ "$lock_status" -eq 75 ]; then
        echo "Another fuzzing campaign is starting or already running." >&2
    fi
    exit "$lock_status"
fi

mkdir -p "$directory/logs"
running_configs=()
for ((config_id = 1; config_id <= MAX_CONFIG; config_id++)); do
    pid_file="$directory/run/run_$config_id/logs/httpd.pid"
    [ -f "$pid_file" ] || continue
    read -r running_pid <"$pid_file" || continue
    case "$running_pid" in
    *[!0-9]* | "") continue ;;
    esac
    running_exe="$(readlink -f "/proc/$running_pid/exe" 2>/dev/null || true)"
    expected_exe="$(realpath -m "$directory/run/run_$config_id/bin/httpd")"
    if [ "${running_exe% (deleted)}" = "$expected_exe" ]; then
        running_configs+=("$config_id")
    fi
done
if [ "${#running_configs[@]}" -gt 0 ]; then
    echo "A fuzzing campaign is already running (configs: ${running_configs[*]})." >&2
    exit 1
fi

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
fuzzerconfigs=()
selected_configs=()
active_fuzzers=0
runtime_failure=0

log_config_error() {
    local config="$1"
    shift
    printf '%s config %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$config" "$*" |
        tee -a "$directory/logs/error$config" >&2
}

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
        [ -n "$fuzzerpid" ] || continue
        kill -TERM "$fuzzerpid" 2>/dev/null || true
    done
    for fuzzerpid in "${fuzzerpids[@]}"; do
        [ -n "$fuzzerpid" ] || continue
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
    if [ "$runtime_failure" = 1 ]; then
        complete=0
    fi
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
    local startup_status

    if [ ! -x "$binary" ] || [ ! -f "$config_file" ]; then
        log_config_error "$BUILD_CONFIG" \
            "is not built. Run ./build.sh -c=$BUILD_CONFIG -d first."
        runtime_failure=1
        return 1
    fi

    if ! stop_pid_file "$pid_file" "$binary"; then
        log_config_error "$BUILD_CONFIG" "could not stop its previous process; continuing."
        runtime_failure=1
        return 1
    fi
    mkdir -p "$profile_dir/run_$BUILD_CONFIG"
    profile_file="$profile_dir/run_$BUILD_CONFIG/default-%m-%p.profraw"

    echo "LLVM_PROFILE_FILE=$profile_file $binary -f $config_file -DFOREGROUND $FUZZ $MULTIPROCESS"
    if [ "$LOG_OUTPUT" = 1 ]; then
        FUZZER_DEBUG=1 \
        LLVM_PROFILE_FILE="$profile_file" \
        ASAN_OPTIONS="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        LSAN_OPTIONS="detect_leaks=0" \
            "$binary" -f "$config_file" -DFOREGROUND $FUZZ $MULTIPROCESS \
            >>"$directory/logs/error$BUILD_CONFIG" 2>&1 &
    else
        FUZZER_DEBUG=1 \
        LLVM_PROFILE_FILE="$profile_file" \
        ASAN_OPTIONS="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:handle_segv=2:handle_sigbus=2:handle_abort=2:handle_sigill=2:handle_sigfpe=2:log_path=$directory/logs/asan$BUILD_CONFIG.log:halt_on_error=0" \
        UBSAN_OPTIONS="halt_on_error=0:print_stacktrace=1" \
        LSAN_OPTIONS="detect_leaks=0" \
            "$binary" -f "$config_file" -DFOREGROUND $FUZZ $MULTIPROCESS &
    fi
    started_pid=$!
    sleep 1
    if ! kill -0 "$started_pid" 2>/dev/null; then
        wait "$started_pid"
        startup_status=$?
        log_config_error "$BUILD_CONFIG" \
            "process $started_pid exited during startup with status $startup_status."
        runtime_failure=1
        return 1
    fi
    fuzzerpids+=("$started_pid")
    fuzzerconfigs+=("$BUILD_CONFIG")
    selected_configs+=("$BUILD_CONFIG")
    active_fuzzers=$((active_fuzzers + 1))
}

if [ "$PACKET_CAPTURE" = 1 ]; then
    if ! command -v tcpdump >/dev/null; then
        log_config_error Packet "tcpdump is unavailable; continuing without packet capture."
    else
        tcpdump -G 43200 -i lo ip6 \
            -w "$directory/logs/dump-%Y%m%dT%H%M%S-$$.pcap" -z gzip &
        capture_pid=$!
        sleep 1
        if ! kill -0 "$capture_pid" 2>/dev/null; then
            wait "$capture_pid"
            capture_status=$?
            log_config_error Packet \
                "tcpdump exited during startup with status $capture_status; continuing without packet capture."
        else
            fuzzerpids+=("$capture_pid")
            fuzzerconfigs+=("")
        fi
    fi
fi

if [ "$CONFIG" = a ] || [ "$CONFIG" = all ]; then
    for ((BUILD_CONFIG = 1; BUILD_CONFIG <= MAX_CONFIG; BUILD_CONFIG++)); do
        run_fuzzer || true
        sleep 0.1
    done
else
    BUILD_CONFIG="$CONFIG"
    run_fuzzer || _term 1
fi

if [ "$active_fuzzers" = 0 ]; then
    echo "No fuzzing configurations started." >&2
    _term 1
fi

while :; do
    sleep 60
    for index in "${!fuzzerpids[@]}"; do
        fuzzerpid="${fuzzerpids[$index]}"
        [ -n "$fuzzerpid" ] || continue
        if ! kill -0 "$fuzzerpid" 2>/dev/null; then
            wait "$fuzzerpid"
            process_status=$?
            config="${fuzzerconfigs[$index]}"
            if [ -n "$config" ]; then
                log_config_error "$config" \
                    "process $fuzzerpid exited with status $process_status; other configurations continue."
                active_fuzzers=$((active_fuzzers - 1))
                runtime_failure=1
            else
                log_config_error Packet \
                    "tcpdump process $fuzzerpid exited with status $process_status; fuzzing continues."
            fi
            fuzzerpids[$index]=""
        fi
    done
    "$directory/asanProcess.sh"
    logrotate "$directory/run/logrotate.conf" -s "$directory/logs/old/logrotate.status"
done
