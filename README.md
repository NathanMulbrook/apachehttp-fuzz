# Apache HTTP Server fuzzing

This is the 389-ds-fuzz layout ported to Apache httpd. It keeps the same
`build/src_N`, `build/build_N`, `run/run_N`, shared `corpus`, and per-config
`logs/errorN`, `logs/asanN.log.*`, and `logs/testCasesN` structure. The build
uses the repository-local LLVM toolchain and the embedded multipacket harness.

## Setup and build

The local LLVM build needs about 80 GiB free. Apache, APR, APR-util, and Expat
are pinned and cloned by `--init`; Expat is built locally so no system Expat
headers are required.

```sh
./build.sh --bootstrap-toolchain
./build.sh --init -c=1 -d -j
./generate-interesting-corpus.py corpus
./run.sh -c=1
```

`-c=a` or `-c=all` selects all 35 builds. `-r` reinstalls an existing build,
`-p` leaves out the fuzz module, and `-j` uses four build jobs. As in the 389
interface, `run.sh --fuzz` runs the server without starting libFuzzer.
Add `--multiprocess` (or `-m`) to start two Apache worker processes. The
single-worker layout remains the default.

Stop `run.sh` with Ctrl-C. Add `--packet` for rotating loopback pcaps and use
`--LOG_OUPTUT` (the original spelling is retained) to show output in the
terminal instead of the error log. Packet capture needs `tcpdump` with scoped
capture privileges such as `cap_net_raw,cap_net_admin`; do not run the Apache
fuzz stack as root to obtain them.

## Input format

Byte zero is a flag byte:

- bit 0 sends a valid keep-alive `HEAD` request before the fuzz data;
- bit 1 enables multipacket framing;
- bit 2 waits for a server response between framed packets.

With bit 1 clear, bytes 1 onward are sent as one packet. With it set, the rest
is a sequence of `uint16` big-endian nonzero length followed by that many raw
bytes. Inputs may contain at most 64 packets. The generated corpus contains 104
deterministic seeds for parser boundaries, pipelining, chunked bodies, request
smuggling boundaries, form auth and sessions, DAV, native proxy protocols,
filters, caches, CGI/SSI, h2c control frames, WebSockets, TLS variants, authz,
translation maps, balancers, PROXY protocol v1/v2, error subrequests, and
character conversion. CGI seeds cover fixed and chunked request bodies, path
information, authorization export, response headers, redirects, conditional
responses, malformed output, NPH responses, and SSI execution. The chunked
seeds bracket the signed `apr_off_t` limit,
cover the separate width
rejection, and retain valid extension and trailer syntax; focused TRACE and
ALPN seeds cover chunked TRACE bodies, header enumeration, `Max-Forwards`
boundaries, the 255-byte ALPN protocol-name boundary, and a valid HTTP/2 DATA
stream crossing the 8 KB socket-bucket boundary.

Replay a corpus or crash input without starting libFuzzer:

```sh
./run.sh --fuzz -c=1
./send-test-case.py corpus/seed-chunk-split --port 5801
./send-test-case.py corpus/seed-chunk-split --packet 2 --port 5801
```

## Configurations

| N | Main coverage target | MPM |
|---:|---|---|
| 1 | strict HTTP/1 method and version parsing | event |
| 2 | lenient methods and `AllowMethods` | worker |
| 3 | unsafe parsing and HTTP/0.9 | prefork |
| 4 | request-line, header, and body limits | event |
| 5 | rewrite, headers, expressions, remote IP | event |
| 6 | deflate/inflate, Brotli, substitute, and Sed filters | event |
| 7 | Basic/Digest/form auth, auth cache, and cookie sessions | event |
| 8 | WebDAV filesystem and lock handling | event |
| 9 | reverse proxy to a local virtual host | event |
| 10 | loopback-only forward/CONNECT proxy, balancer, WebSocket proxy | event |
| 11 | disk/socache/file cache, expiry, and validators | event |
| 12 | h2c, push, WebSockets, and control frames | event |
| 13 | TLS plus ALPN HTTP/2 | event |
| 14 | negotiation, autoindex, and spelling | event |
| 15 | range and conditional requests | event |
| 16 | CGI, Actions, and server-side includes | event |
| 17 | status, info, and reflector handlers | event |
| 18 | threaded h2c, push, WebSockets, and control frames | worker |
| 19 | prefork CGI, DAV, rewrite, and HTTP/0.9 | prefork |
| 20 | combined h2c, rewrite, cache, filters, HTTP/AJP/FCGI/SCGI/UWSGI proxy | event |
| 21 | anonymous/file authentication and group/file-owner authorization | event |
| 22 | buffered request/response bodies, reflector headers, and rate limiting | event |
| 23 | isolated external input/output filter process lifecycle | prefork |
| 24 | name-based virtual hosts, virtual document roots, and user directories | event |
| 25 | text, SDBM, lowercase, and escaping rewrite maps | event |
| 26 | DBM-driven local dynamic reverse proxying | event |
| 27 | by-traffic/by-busyness balancers and isolated balancer management | event |
| 28 | error documents, SSI subrequests, fallback resources, and redirects | event |
| 29 | cache locks, cache-control policy, headers, and query-key handling | event |
| 30 | reverse-proxy Location, cookie, and error-response rewriting | event |
| 31 | data output filtering and imagemap coordinate parsing | event |
| 32 | ISO-8859-1 to UTF-8 reflector input/output conversion | event |
| 33 | full TLS proxy handshakes, HTTPS backend requests, and DBM TLS sessions | event |
| 34 | DBM-backed shared response caching and cache-key handling | event |
| 35 | PROXY protocol v1/v2 parsing and remote client addresses | event |

Config 16 exercises `mod_cgid` under event MPM. Config 19 applies the same CGI
fixtures to in-process `mod_cgi` under prefork MPM.

Each config listens on `[::1]:5800+N`; local proxy backends use
`[::1]:6800+N`. The forward proxy denies every destination except its matching
loopback backend, so mutated inputs cannot make outbound proxy connections.
Config 23 launches one local filter process for each filtered request and may be
substantially slower than the in-process personalities.

## Apache process model

Apache's Unix MPMs are multiprocess. The default configs retain `ServerLimit 1`;
`./run.sh --multiprocess` selects two workers without changing the directory,
log, corpus, or command layout.

The fuzz build uses the guard backend adapted from the supplied covbridge 0.1
examples. A shared anonymous counter map is initialized in the parent before
the MPM forks. Each process contributes through wrapped `trace-pc-guard`
callbacks, and one child holds `logs/fuzzer.lock` while it runs the stock
LibFuzzer driver. Waiting children take over automatically if that controller
exits. Run IDs live in shared memory and remain increasing across controller
replacement. `CB_MAX_EDGES` is 1,048,576, above the current roughly 519,000
registered Apache sites. Counts enter stock LibFuzzer through its
`__libfuzzer_extra_counters` section; comparison operands and value profiles
are not bridged.

Each input still uses the 389 multipacket format and 20 ms packet delay. The
controller now waits for the matching Apache connection to reach the
`pre_close_connection` hook before it snapshots and imports coverage. Only one
input owns the map. Event-MPM suspend/resume hooks move the connection tag with
normal asynchronous processing, and coverage callbacks accept hits only from a
thread carrying that run tag. The `pre_connection` hook admits only primary
connections whose `conn_rec` local port is the main `5800+N` fuzz listener;
HTTP/2 secondary connection records and requests that a proxy configuration
sends to its `6800+N` loopback backend cannot prolong the run. This prevents
parent maintenance and unrelated worker activity from leaking into the next
input.

The boundary covers Apache processing from the fuzzer module's
`pre_connection` hook through `pre_close_connection`. It excludes accept-path
work before that hook, lingering-close work afterward, and work that leaves the
tagged connection thread. Config 16's exec-based `mod_cgid` helper does not
retain the map after exec. Detached module work, including implementation-
specific HTTP/2 helper activity, is not claimed as precisely attributed
feedback. Keep the listener dedicated to this local fuzzer; another loopback
client arriving during an input would join the same measurement.

Sanitizers use recovering mode and write deduplicated logs. ASan retains its
fatal-signal handlers after Apache starts, so a worker crash produces a
sanitizer report while the other configurations continue. Before sending an
input, the controller writes its exact binary form to
`logs/currentInputN-PID`. It removes the file only after coverage is imported;
a worker crash, coverage timeout, or controller failure therefore leaves the
input for replay. `status.sh` reports the number of preserved inputs. A
recovering sanitizer report does not preserve this file after the input
finishes, so independently reproduce it before attributing it to a nearby
`testCasesN` timestamp.

The covbridge-derived files retain their MIT terms in `covbridge-LICENSE`. The
supplied `covbridge-source.zip` was treated as a read-only source artifact.

## Reports and checks

Every run creates a unique `logs/profiles/SESSION/run_N` tree. Generate source
coverage with the parent and each post-fork Apache child writing a distinct
mergeable `.profraw` file:

```sh
./genreport.sh
./genreport.sh logs/profiles/SESSION 1
```

With no arguments, the report script uses the latest completed session and
reports every config, matching the original 389 command style. The two-argument
form selects one session and config.

`./asanProcess.sh` deduplicates sanitizer logs. `./checkObjects.sh` performs the
same read-only static instrumentation scan used by 389-ds-fuzz; its default
config checks every build 1 target-code object and the installed server, then
writes `logs/symbolReport.md`.

Check every configuration or one selected configuration without disturbing the
run:

```sh
./status.sh
./status.sh -c=13
```

The status output shows the Apache parent PID, child count, busiest child CPU,
latest input age, latest LibFuzzer progress, shared corpus activity, sanitizer
report count, crash artifact count, and preserved current-input count. It marks
a fuzzing process `STALE` if its testcase log has not changed for two minutes.
