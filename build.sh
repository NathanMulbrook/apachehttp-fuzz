#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MAX_CONFIG=34

help() {
    echo "Usage: ./build.sh [options]"
    echo "  --bootstrap-toolchain  Build the pinned LLVM toolchain and exit"
    echo "  --config=N, -c=N       Build configuration N (1-$MAX_CONFIG, a, or all)"
    echo "  --directory, -d        Recreate the installed run directory"
    echo "  --rebuild-directory, -r  Reinstall from an existing build tree"
    echo "  --init, -i             Clone missing source and patch repositories"
    echo "  --jobs, -j             Build with four jobs"
    echo "  --no_patch, -p         Build pristine Apache without the fuzz module"
    exit
}

for arg in "$@"; do
    case "$arg" in
    --help | -h)
        help
        ;;
    --bootstrap-toolchain)
        "$directory/toolchain/build-llvm.sh"
        exit
        ;;
    esac
done

source "$directory/toolchain/use-llvm.sh" || exit

PATCH=1
CONFIG="a"
BUILD_INIT=0
BUILD_DIRECTORY=0
REBUILD_DIRECTORY=0
JOBS=1
HTTPD_BRANCH="2.4.68"
APR_BRANCH="1.7.6"
APR_UTIL_BRANCH="1.6.5"
EXPAT_BRANCH="R_2_8_2"
PATCH_BRANCH="master"
PRIVATE_BRANCH="master"

PATCHDIRS=(
    "apachehttp-fuzz-patches/patches"
    "apachehttp-fuzz-private/patches"
)

source_dir="$directory/httpd"

build_failed() {
    echo "BUILD FAILED!!" >&2
    exit 1
}

list_descendants() {
    local parent="$1"
    local children
    children="$(ps -o pid= --ppid "$parent" 2>/dev/null || true)"
    for pid in $children; do
        list_descendants "$pid"
        echo "$pid"
    done
}

_term() {
    local descendants
    echo "Killing Children"
    descendants="$(list_descendants $$)"
    if [ -n "$descendants" ]; then
        kill $descendants 2>/dev/null || true
    fi
    exit 130
}

trap _term SIGINT SIGTERM

for arg in "$@"; do
    case "$arg" in
    --directory | -d)
        BUILD_DIRECTORY=1
        ;;
    --rebuild-directory | -r)
        REBUILD_DIRECTORY=1
        BUILD_DIRECTORY=1
        PATCH=0
        ;;
    --init | -i)
        BUILD_INIT=1
        ;;
    --jobs | -j)
        JOBS=4
        ;;
    --no_patch | --no-patch | -p)
        PATCH=0
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    esac
done

if [ "$CONFIG" != a ] && [ "$CONFIG" != all ] &&
        { [[ ! "$CONFIG" =~ ^[1-9][0-9]*$ ]] ||
            [ "$CONFIG" -lt 1 ] || [ "$CONFIG" -gt "$MAX_CONFIG" ]; }; then
    echo "Config must be 1-$MAX_CONFIG, a, or all." >&2
    exit 1
fi

if [ "$REBUILD_DIRECTORY" = 1 ] && { [ "$CONFIG" = a ] || [ "$CONFIG" = all ]; }; then
    echo "--rebuild-directory requires one configuration." >&2
    exit 1
fi

init_sources() {
    if [ ! -d "$source_dir/.git" ]; then
        git clone --depth 1 --branch "$HTTPD_BRANCH" https://github.com/apache/httpd.git "$source_dir"
    fi
    if [ ! -d "$source_dir/srclib/apr/.git" ]; then
        git clone --depth 1 --branch "$APR_BRANCH" https://github.com/apache/apr.git "$source_dir/srclib/apr"
    fi
    if [ ! -d "$source_dir/srclib/apr-util/.git" ]; then
        git clone --depth 1 --branch "$APR_UTIL_BRANCH" https://github.com/apache/apr-util.git "$source_dir/srclib/apr-util"
    fi
    if [ ! -d "$source_dir/srclib/expat/.git" ]; then
        git clone --depth 1 --branch "$EXPAT_BRANCH" https://github.com/libexpat/libexpat.git "$source_dir/srclib/expat"
    fi
    if [ ! -d "$directory/apachehttp-fuzz-patches/.git" ]; then
        git clone git@github.com:NathanMulbrook/apachehttp-fuzz-patches.git "$directory/apachehttp-fuzz-patches"
    fi
    if [ ! -d "$directory/apachehttp-fuzz-private/.git" ]; then
        git clone git@github.com:NathanMulbrook/apachehttp-fuzz-private.git "$directory/apachehttp-fuzz-private"
    fi
}

if [ "$BUILD_INIT" = 1 ]; then
    init_sources
fi

for required in \
    "$source_dir/.git" \
    "$source_dir/srclib/apr/.git" \
    "$source_dir/srclib/apr-util/.git" \
    "$source_dir/srclib/expat/.git" \
    "$directory/apachehttp-fuzz-patches/.git" \
    "$directory/apachehttp-fuzz-private/.git"; do
    if [ ! -e "$required" ]; then
        echo "Missing $required; run ./build.sh --init." >&2
        exit 1
    fi
done

git -C "$source_dir" checkout --quiet "$HTTPD_BRANCH"
git -C "$source_dir/srclib/apr" checkout --quiet "$APR_BRANCH"
git -C "$source_dir/srclib/apr-util" checkout --quiet "$APR_UTIL_BRANCH"
git -C "$source_dir/srclib/expat" checkout --quiet "$EXPAT_BRANCH"
if git -C "$directory/apachehttp-fuzz-patches" rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C "$directory/apachehttp-fuzz-patches" checkout --quiet "$PATCH_BRANCH"
fi
if git -C "$directory/apachehttp-fuzz-private" rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C "$directory/apachehttp-fuzz-private" checkout --quiet "$PRIVATE_BRANCH"
fi

export LSAN_OPTIONS=detect_leaks=0
if [ "$PATCH" = 1 ]; then
    fuzz_cflags="-fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard"
    fuzz_ldflags="-fsanitize=address,undefined"
else
    fuzz_cflags="-fsanitize=fuzzer-no-link,address,undefined"
    fuzz_ldflags="-fsanitize=fuzzer-no-link,address,undefined"
fi
export CFLAGS="-g3 -O0 -pipe -Wall -fexceptions -fstack-protector \
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -m64 -mtune=generic \
    -fsanitize-recover=all $fuzz_cflags \
    -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="$fuzz_ldflags \
    -fprofile-instr-generate -fcoverage-mapping"

resource_dir="$("$CC" -print-resource-dir)"
FUZZER_NO_MAIN="$(find "$resource_dir/lib" -type f -name 'libclang_rt.fuzzer_no_main*.a' -print -quit)"
if [ -z "$FUZZER_NO_MAIN" ]; then
    echo "libclang_rt.fuzzer_no_main is missing from $resource_dir." >&2
    exit 1
fi

config_build() {
    case "$BUILD_CONFIG" in
    2 | 18)
        mpm=worker
        ;;
    3 | 19 | 23)
        mpm=prefork
        ;;
    *)
        mpm=event
        ;;
    esac

    config_flags=(
        "--with-included-apr"
        "--with-expat=$build_dir/expat"
        "--with-mpm=$mpm"
        "--enable-mods-static=most"
        "--enable-http2=static"
        "--enable-ssl=static"
        "--enable-brotli=static"
        "--enable-data=static"
        "--enable-imagemap=static"
        "--enable-charset-lite=static"
        "--enable-dav-lock=static"
        "--enable-reflector=static"
        "--disable-shared"
        "--disable-suexec"
    )
    if [ "$PATCH" = 1 ]; then
        config_flags+=("--enable-fuzzer=static")
    fi
}

apply_fuzz_patches() {
    local patch_dir
    local patch_files
    shopt -s nullglob
    for patch_dir in "${PATCHDIRS[@]}"; do
        patch_files=("$directory/$patch_dir"/*.patch)
        if [ "${#patch_files[@]}" -gt 0 ]; then
            git apply -v --reject --ignore-space-change --ignore-whitespace "${patch_files[@]}" || build_failed
            printf 'Applied patches from %s\n' "$patch_dir"
        fi
    done
    shopt -u nullglob
}

install_runtime_config() {
    local run_dir="$1"
    local port="$2"
    local backend_port="$3"
    local backend2_port="$4"

    mkdir -p \
        "$run_dir/conf" \
        "$run_dir/logs/cache" \
        "$run_dir/logs/cache-policy" \
        "$run_dir/logs/cache-lock" \
        "$run_dir/htdocs/dav" \
        "$run_dir/htdocs/backend" \
        "$run_dir/htdocs/backend-response/destination" \
        "$run_dir/htdocs/auth" \
        "$run_dir/htdocs/cache-policy" \
        "$run_dir/htdocs/data" \
        "$run_dir/htdocs/errors" \
        "$run_dir/htdocs/ext/out" \
        "$run_dir/htdocs/fallback-zone/subdir" \
        "$run_dir/htdocs/mapped" \
        "$run_dir/htdocs/rate" \
        "$run_dir/htdocs/rewritten" \
        "$run_dir/htdocs/final" \
        "$run_dir/htdocs/socache" \
        "$run_dir/htdocs/substitute" \
        "$run_dir/userdirs/fuzz" \
        "$run_dir/vhosts/blue.vhost.fuzz.test/htdocs" \
        "$run_dir/cgi-bin"

    sed \
        -e "s#@RUN_DIR@#$run_dir#g" \
        -e "s#@ROOT_DIR@#$directory#g" \
        -e "s#@PORT@#$port#g" \
        -e "s#@CONFIG@#$BUILD_CONFIG#g" \
        "$directory/httpd.conf.in" >"$run_dir/conf/httpd.conf"
    sed \
        -e "s#@RUN_DIR@#$run_dir#g" \
        -e "s#@PORT@#$port#g" \
        -e "s#@BACKEND_PORT@#$backend_port#g" \
        -e "s#@BACKEND2_PORT@#$backend2_port#g" \
        "$directory/fuzz-configs.conf.in" >"$run_dir/conf/fuzz-configs.conf"

    printf 'Apache fuzz target config %s\nfuzz fuzz fuzz\n' "$BUILD_CONFIG" >"$run_dir/htdocs/index.txt"
    printf '<html><body>fuzz html config %s</body></html>\n' "$BUILD_CONFIG" >"$run_dir/htdocs/index.html"
    printf 'fuzz backend response\n' >"$run_dir/htdocs/backend/index.txt"
    printf 'fuzz backend response rewrite\n' >"$run_dir/htdocs/backend-response/index.txt"
    printf 'fuzz proxy destination\n' >"$run_dir/htdocs/backend-response/destination/index.txt"
    printf 'fuzz owner authorization target\n' >"$run_dir/htdocs/auth/owner"
    printf 'fuzz cache policy target\n' >"$run_dir/htdocs/cache-policy/index.txt"
    printf 'fuzz external output filter\n' >"$run_dir/htdocs/ext/out/index.txt"
    printf 'fuzz mapped hit\n' >"$run_dir/htdocs/mapped/hit.txt"
    printf 'fuzz mapped lowercase\n' >"$run_dir/htdocs/mapped/fuzz.txt"
    printf 'fuzz mapped miss\n' >"$run_dir/htdocs/mapped/miss.txt"
    printf 'fuzz virtual document root\n' >"$run_dir/vhosts/blue.vhost.fuzz.test/htdocs/index.txt"
    printf 'fuzz absolute user directory\n' >"$run_dir/userdirs/fuzz/index.txt"
    printf 'fuzz substitution target\n' >"$run_dir/htdocs/substitute/index.txt"
    printf 'fuzz socache response\n' >"$run_dir/htdocs/socache/index.txt"
    printf 'fuzz dav seed\n' >"$run_dir/htdocs/dav/seed.txt"
    printf 'fuzz HTTP/2 push target\n' >"$run_dir/htdocs/h2-push"
    printf 'hello\n' >"$run_dir/htdocs/variant.en.txt"
    printf 'bonjour\n' >"$run_dir/htdocs/variant.fr.txt"
    printf '<!--#echo var="REQUEST_METHOD" --> fuzz\n' >"$run_dir/htdocs/include.shtml"
    printf '<!--#echo var="REDIRECT_STATUS" --> <!--#include virtual="/index.txt" -->\n' \
        >"$run_dir/htdocs/errors/400.shtml"
    cp "$run_dir/htdocs/errors/400.shtml" "$run_dir/htdocs/errors/404.shtml"
    cp "$run_dir/htdocs/errors/400.shtml" "$run_dir/htdocs/errors/405.shtml"
    printf '<!--#echo var="REQUEST_URI" --> fallback fuzz\n' \
        >"$run_dir/htdocs/fallback.shtml"
    printf '<!--#include virtual="/index.txt" --> directory fuzz\n' \
        >"$run_dir/htdocs/fallback-zone/index.shtml"
    printf '<!--#include virtual="/index.txt" --> subdirectory fuzz\n' \
        >"$run_dir/htdocs/fallback-zone/subdir/index.shtml"
    printf 'fuzz rate limit output\n' >"$run_dir/htdocs/rate/large.txt"
    truncate -s 65536 "$run_dir/htdocs/rate/large.txt"
    : >"$run_dir/htdocs/data/length-0.txt"
    printf x >"$run_dir/htdocs/data/length-1.bin"
    truncate -s 2 "$run_dir/htdocs/data/length-2.txt"
    truncate -s 3 "$run_dir/htdocs/data/length-3.bin"
    truncate -s 5999 "$run_dir/htdocs/data/length-5999.txt"
    truncate -s 6000 "$run_dir/htdocs/data/length-6000.txt"
    truncate -s 6001 "$run_dir/htdocs/data/length-6001.bin"
    cat >"$run_dir/htdocs/shapes.map" <<'EOF'
default /index.txt "Default"
rect /index.html 0,0 100,100 "Rectangle"
circle /data/length-1.bin 50,50 75,50 "Circle"
poly /mapped/hit.txt 0,0 100,0 100,100 0,100 "Polygon"
point /mapped/miss.txt 2147483647,2147483647 "Point"
EOF
    cat >"$run_dir/htdocs/complex.shtml" <<'EOF'
<!--#config errmsg="fuzz-error" timefmt="%Y-%m-%d" sizefmt="bytes" -->
<!--#set var="fuzz_name" value="fuzz-value" -->
<!--#if expr="-n v('fuzz_name') && v('REQUEST_METHOD') = 'GET'" -->
<!--#echo var="fuzz_name" encoding="entity" -->
<!--#include virtual="/index.txt" -->
<!--#else --><!--#printenv --><!--#endif -->
EOF
    printf 'fuzz action target\n' >"$run_dir/htdocs/action.fuzz"
    cat >"$run_dir/htdocs/login.html" <<'EOF'
<form method="POST" action="/auth/login">
<input name="httpd_username"><input name="httpd_password" type="password">
</form>
EOF
    printf 'fuzz:$apr1$fuzzsalt$QfPAb9cvzhzTUVlaDLg260\nadmin:$apr1$fuzzsalt$QfPAb9cvzhzTUVlaDLg260\n' \
        >"$run_dir/conf/users"
    printf 'fuzzers: admin fuzz\n' >"$run_dir/conf/groups"
    printf 'fuzz:fuzz:afdad1c8772340a1d722a0afc8594089\n' >"$run_dir/conf/digest-users"
    printf 'hit /mapped/hit.txt\ndbm /mapped/hit.txt\nFUZZ.TXT /mapped/fuzz.txt\n' \
        >"$run_dir/conf/rewrite-map.txt"
    "$run_dir/bin/httxt2dbm" -f SDBM -i "$run_dir/conf/rewrite-map.txt" \
        -o "$run_dir/conf/rewrite-map.dbm"
    printf 'express.fuzz.test http://[::1]:%s\nblue.express.fuzz.test http://[::1]:%s\n' \
        "$backend_port" "$backend_port" >"$run_dir/conf/express-map.txt"
    "$run_dir/bin/httxt2dbm" -f SDBM -i "$run_dir/conf/express-map.txt" \
        -o "$run_dir/conf/express-map.dbm"

    cat >"$run_dir/conf/filter.sh" <<'EOF'
#!/usr/bin/env bash
exec /bin/cat
EOF
    chmod 0755 "$run_dir/conf/filter.sh"

    {
        echo '#!/usr/bin/env bash'
        echo 'printf "Content-Type: text/plain\r\n\r\n"'
        echo 'printf "method=%s query=%s length=%s\n" "$REQUEST_METHOD" "$QUERY_STRING" "$CONTENT_LENGTH"'
        echo 'dd bs=1 count="${CONTENT_LENGTH:-0}" 2>/dev/null || true'
    } >"$run_dir/cgi-bin/echo.cgi"
    chmod 0755 "$run_dir/cgi-bin/echo.cgi"

    if [ "$BUILD_CONFIG" = 13 ] || [ "$BUILD_CONFIG" = 33 ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$run_dir/conf/server.key" \
            -out "$run_dir/conf/server.crt" \
            -days 3650 -subj /CN=localhost >/dev/null 2>&1
    fi
}

build_software() {
    local run_dir="$directory/run/run_$BUILD_CONFIG"
    local build_dir="$directory/build/build_$BUILD_CONFIG"
    local temp_source_dir="$directory/build/src_$BUILD_CONFIG"
    local port="$((5800 + BUILD_CONFIG))"
    local backend_port="$((6800 + BUILD_CONFIG))"
    local backend2_port="$((7800 + BUILD_CONFIG))"

    echo "############# Building Config: $BUILD_CONFIG Args Used: $* ##################"

    if [ "$BUILD_DIRECTORY" = 1 ]; then
        rm -rf -- "$run_dir"
    fi
    if [ "$REBUILD_DIRECTORY" = 0 ]; then
        rm -rf -- "$build_dir" "$temp_source_dir"
        mkdir -p "$temp_source_dir" "$build_dir"
        cp -a "$source_dir/." "$temp_source_dir/"

        cd "$temp_source_dir" || build_failed
        if [ "$PATCH" = 1 ]; then
            apply_fuzz_patches
            if [ ! -f modules/fuzzer/config.m4 ]; then
                echo "The required fuzzer module patch was not applied." >&2
                build_failed
            fi
            mkdir -p modules/fuzzer
            install -m 0644 "$directory/fuzzer.c" modules/fuzzer/fuzzer.c
            install -m 0644 "$directory/fuzzer.h" modules/fuzzer/fuzzer.h
            install -m 0644 "$directory/covbridge.c" modules/fuzzer/covbridge.c
            install -m 0644 "$directory/covbridge.h" modules/fuzzer/covbridge.h
            sed -i \
                -e "s/int port = 5800;/int port = $port;/" \
                -e "s#/home/admin/software/fuzzing/apachehttp-fuzz#$directory#g" \
                -e "s/testCases1/testCases$BUILD_CONFIG/g" \
                -e "s/currentInput1/currentInput$BUILD_CONFIG/g" \
                -e "s/0x4150465a00000001/0x4150465a000000$(printf '%02x' "$BUILD_CONFIG")/" \
                modules/fuzzer/fuzzer.c
        fi
        ./buildconf

        cd "$build_dir" || build_failed
        cmake \
            -S "$temp_source_dir/srclib/expat/expat" \
            -B "$build_dir/expat-build" \
            -DCMAKE_BUILD_TYPE=Debug \
            -DCMAKE_INSTALL_PREFIX="$build_dir/expat" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DEXPAT_SHARED_LIBS=OFF \
            -DEXPAT_BUILD_DOCS=OFF \
            -DEXPAT_BUILD_EXAMPLES=OFF \
            -DEXPAT_BUILD_TESTS=OFF \
            -DEXPAT_BUILD_TOOLS=OFF \
            -DEXPAT_BUILD_PKGCONFIG=ON
        cmake --build "$build_dir/expat-build" --target install --parallel "$JOBS"

        config_build
        if [ "$PATCH" = 1 ]; then
            FUZZER_LIBS="$FUZZER_NO_MAIN -lstdc++ -pthread \
                -Wl,--wrap=__sanitizer_cov_trace_pc_guard \
                -Wl,--wrap=__sanitizer_cov_trace_pc_guard_init" \
                "$temp_source_dir/configure" \
                "--prefix=$run_dir" \
                "--with-port=$port" \
                "--with-sslport=$port" \
                "${config_flags[@]}"
        else
            "$temp_source_dir/configure" \
                "--prefix=$run_dir" \
                "--with-port=$port" \
                "--with-sslport=$port" \
                "${config_flags[@]}"
        fi
    fi

    cd "$build_dir" || build_failed
    make -j "$JOBS" || build_failed
    make install || build_failed
    install_runtime_config "$run_dir" "$port" "$backend_port" "$backend2_port"
    if [ "$PATCH" = 1 ]; then
        if ! "$NM" "$run_dir/bin/httpd" | grep -E '[[:space:]][BD] fuzzer_module$' >/dev/null; then
            echo "Installed httpd is missing fuzzer_module." >&2
            build_failed
        fi
        if ! "$NM" "$run_dir/bin/httpd" | grep -E '[[:space:]]T LLVMFuzzerRunDriver$' >/dev/null; then
            echo "Installed httpd is missing LLVMFuzzerRunDriver." >&2
            build_failed
        fi
        if ! "$NM" "$run_dir/bin/httpd" | grep -E '[[:space:]]T __wrap___sanitizer_cov_trace_pc_guard$' >/dev/null; then
            echo "Installed httpd is missing the covbridge guard wrapper." >&2
            build_failed
        fi
        if ! readelf -SW "$run_dir/bin/httpd" | grep '__libfuzzer_extra_counters' >/dev/null; then
            echo "Installed httpd is missing LibFuzzer extra counters." >&2
            build_failed
        fi
    fi
    "$run_dir/bin/httpd" -t -f "$run_dir/conf/httpd.conf" -DNO_FUZZ
    cd "$directory" || build_failed
}

mkdir -p \
    "$directory/build" \
    "$directory/run" \
    "$directory/corpus" \
    "$directory/logs/old/build" \
    "$directory/logs/old/error" \
    "$directory/logs/old/asan" \
    "$directory/logs/old/testCases"

sed "s!tacos!$directory!g" "$directory/logrotate.conf" >"$directory/run/logrotate.conf"

if [ "$CONFIG" = a ] || [ "$CONFIG" = all ]; then
    build_pids=()
    for ((BUILD_CONFIG = 1; BUILD_CONFIG <= MAX_CONFIG; BUILD_CONFIG++)); do
        (build_software "$@") \
            > >(tee "$directory/logs/build$BUILD_CONFIG.log") 2>&1 &
        build_pids+=($!)
        sleep 0.1
    done
    result=0
    for build_pid in "${build_pids[@]}"; do
        wait "$build_pid" || result=1
    done
    exit "$result"
else
    BUILD_CONFIG="$CONFIG"
    build_software "$@"
fi
