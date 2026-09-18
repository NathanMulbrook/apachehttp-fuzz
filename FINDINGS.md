# Fuzzing findings

## September 18 impact follow-up

The `mod_remoteip.c:1122` zero-length copy diagnostic does not have a
demonstrated native memory-safety impact. Source review found no path from an
Apache bucket to `ptr == NULL` with a nonzero length, and the accumulated copy
remains bounded by the fixed PROXY-header buffer. Under recovering UBSan,
18,561 empty-FIN triggers over ten seconds caused three one-time diagnostics
but all 1,823 concurrent health requests succeeded and no worker was replaced.
With `UBSAN_OPTIONS=halt_on_error=1`, repeated triggers terminated whole worker
processes: the parent replaced them, concurrent requests failed temporarily,
and steady service returned about two seconds after the trigger stopped. This
is relevant to hardened builds that make UBSan fatal, but it did not terminate
the parent or produce a persistent outage.

The uninstrumented Fedora 42 `httpd-2.4.66-1.fc42` package and an independent
Clang `-O2` Apache 2.4.68 build did not crash or replace workers over more than
150,000 combined empty-FIN connections. The packaged server completed 255/255
health requests during a sustained test. Its observable native effect was one
error-log entry per connection, about 1.11 MiB/s at the local test rate, plus
ordinary load-induced latency. No ASan report, native crash, corruption,
request desynchronization, code execution, or persistent availability effect
was found for the zero-length copy itself.

The source review exposed a separate PROXY v2 length-validation issue. In
Apache 2.4.68 and the current `2.4.x` branch, `remoteip_process_v2_header()`
uses the TCP4 or TCP6 address union without first requiring the declared v2
payload to contain the 12- or 36-byte address structure. A syntactically valid
16-byte v2 header with a declared length of zero is therefore complete to the
parser, while the address fields beyond that header contain stale or
uninitialized pool data.

This behavior affects identity consumers. Against the unmodified Fedora 42
package, valid disallowed PROXY sources received HTTP 403 and valid
`203.0.113.7` sources received HTTP 200 for a location protected by
`Require ip 203.0.113.7`. After allocator warmup, 10/10 zero-length TCP4
records sent immediately after an allowed record inherited that record's IP
and port and also received HTTP 200. TCP6 tests likewise reused the preceding
address and port in 9/9 steady-state pairs; the first three malformed records
instead exposed unrelated allocator contents in the access log. A static
response did not disclose the interpreted address to the client, so remote
disclosure additionally requires an application or handler that reflects the
client identity.

This is a constrained authorization risk rather than a general direct-client
bypass. A client that can send arbitrary complete PROXY records can already
claim an allowed address. The demonstrated bypass matters when a trusted
frontend can be induced to send an undersized backend PROXY record while the
requester cannot choose a complete asserted identity. Apache fixed this on
trunk in [commit `7c6129b51935`](https://github.com/apache/httpd/commit/7c6129b51935d9165241279637915eaf905c58f1)
by rejecting TCP4 payloads shorter than 12 bytes and TCP6 payloads shorter than
36 bytes; that commit closes upstream issue `#683` and is not present in the
fetched `2.4.x` branch. This makes the issue a
known upstream duplicate, although the tested stable releases remain affected.
Two focused corpus inputs now cover the zero-length TCP4 and TCP6 cases.

The overnight 35-config campaign ended at 06:15 after systemd recorded an OOM
kill at a 63.9 GiB peak. Before stopping it reached 278,570 corpus files and 210
recovering UBSan reports at the same four already classified source sites: 99
chunk shifts, 99 TRACE callback mismatches, nine mod_ssl callback mismatches,
and three zero-length `mod_remoteip` copies. It produced no new ASan source site.

The OOM evidence does not show a target memory leak. Most LibFuzzer controllers
reached a stable high-water RSS between about 0.75 and 1.04 GiB after corpus
initialization and reload, then reported the same peak for hundreds of thousands
of further executions. Each process had independently loaded the shared
265,266-file, 449 MB corpus at startup. The kernel's global OOM table attributed
52.49 GiB RSS to 171 campaign `httpd` processes; all 177 `httpd` processes on
the host accounted for 53.84 GiB. Three unrelated Python processes used another
26.98 GiB, and swap was exhausted. The kernel selected a campaign process with
`oom_score_adj=200`. This supports aggregate sanitizer, corpus, and process
overhead under system-wide pressure, not unbounded per-request growth. The
overnight campaign disables LeakSanitizer, but a separate config 35 check ran
10,000 alternating valid and zero-length TCP4 PROXY records with leak detection
enabled. Single-process RSS warmed from 73 MiB to 174 MiB by request 5,000 and
then changed by only 0.6 MiB through request 10,000; Apache exited normally with
no LeakSanitizer or ASan report. This rules out sustained per-request growth in
the targeted path under that bounded test. Multiprocess mode now starts two
workers per configuration instead of three, removing 35 sanitized workers while
preserving cross-process coverage feedback and the existing command interface.

## September 17 campaign follow-up

Config 35 had been starting Apache but had not entered fuzzing because its
health request omitted the PROXY protocol line required by
`RemoteIPProxyProtocol On`. The build now prepends `PROXY UNKNOWN fuzz` only to
config 35's generated health request. After rebuilding and restarting the
unchanged 35-config command, config 35 began fuzzing at about 22 inputs per
second and the full campaign remained active.

The newly active config produced three recovering UBSan diagnostics at
`modules/metadata/mod_remoteip.c:1122`. A fresh single-process replay confirmed
the trigger: connect to a PROXY-protocol listener, send no application bytes,
and close the write side. The input filter reads an EOS bucket as
`ptr == NULL, len == 0` and passes those values to `memcpy`. Nonempty 1-, 14-,
and 15-byte partial headers did not report the issue, including when held past
the request timeout; a valid PROXY header and HTTP request also remained clean.

This is protocol-reachable C undefined behavior, but the copy length is zero
and no memory access or state change was observed. Recovering UBSan left the
server process alive; `halt_on_error=1` made the isolated process exit with
status 1. There was no ASan report, native crash, memory corruption, code
execution, or lasting availability effect. The condition requires
`RemoteIPProxyProtocol On`, and no valid PROXY header or authentication is
needed. Apache 2.4.68 and the locally cached `2.4.x` branch contain the same
unconditional copy. Guarding `memcpy` with `if (len != 0)` removes the invalid
call.

No other new sanitizer source site or crash artifact appeared after the
September 16 finding snapshot.

## September 14 sanitizer follow-up

The expanded logs contain 201 recovering UBSan diagnostics, but still only
three semantic source sites: 98 signed chunk-size shifts at
`modules/http/http_filters.c:270`, 98 TRACE callback type mismatches at
`srclib/apr/tables/apr_tables.c:990`, and five mod_ssl optional-function type
mismatches at `server/ssl.c:192`. A few newer logs symbolize the last two
callbacks as `ap_get_client_block` or `ssl_var_register`. Those names came from
symbolizing still-running processes after their on-disk binaries had been
rebuilt; the source locations, call stacks, and previously verified callback
implementations show that they are not new UBSan sites. The impact assessment
below remains unchanged: the chunk shift is real protocol-reachable undefined
behavior, while the two function-type mismatches are ABI-benign on tested
x86-64 builds but are expected to terminate non-recovering UBSan or
CFI-hardened children. CFI was not tested.

The campaign also found a separate, higher-interest ASan issue in mod_http2.
A reduced 8,001-byte HTTP/2 connection payload causes an invalid indirect call
after a malformed HEADERS block closes its stream. `read_and_feed()` uses
`session->bbtmp` for socket input; the reentrant `ev_stream_closed()` callback
uses and cleans the same brigade for its output EOS bucket. When parsing returns,
`c1_in_feed_brigade()` deletes a stale APR bucket and calls a non-executable
destroy pointer. Thirty-one saved config 12/event and config 18/worker reports
have the same wild-jump shape, including the deliberately repeated reduction
runs.

The reduced trigger reproduced three times in an unmodified Apache 2.4.68
source build without the fuzzer module. A single-process replay exited 134
after ASan reported the SEGV; multiprocess replays killed and replaced workers.
Trace logging captured the input brigade, invalid header, `CLOSED` transition,
and `adding h2_eos to c1 out` immediately before the stale destroy. Inputs no
larger than 8,000 bytes did not reproduce. A valid 8,080-byte HTTP/2 POST/DATA
control returned normal responses four times without a sanitizer report and is
now retained as `seed-h2-large-data`; the crashing input is intentionally not
placed in the shared corpus. The full reproducer and evidence are recorded in
the private finding repository.

The exact long-run coverage report also identified mod_remoteip's PROXY parser
as a clean gap: config 35 now enables `RemoteIPProxyProtocol On`, and eight
deterministic inputs cover PROXY v1 TCP4, TCP6, UNKNOWN, a split detection
boundary, and PROXY v2 TCP4, TCP6, LOCAL, and oversize-length handling. This
adds a distinct connection-level parser without duplicating existing HTTP
personalities. An isolated replay of those eight seeds at the standard notice
log level covered 41.85% of
`mod_remoteip.c` lines, compared with 14.95% in the prior exact long-run
aggregate. The smoke run is a focused path check rather than a new
whole-campaign total.

## September 13-14 coverage follow-up

The exact-provenance multiprocess session
`logs/profiles/20260913T213249Z-3084251` ran for 10h45m and produced 126
nonempty, mergeable profiles. The first 20 configurations reached 27.91% of
regions, 57.59% of functions, 42.70% of lines, and 20.18% of branches when
reported against the config 20 event-MPM binary. Merging all 32 profiles in
that same common/event view reached 29.86% of regions, 60.43% of functions,
45.71% of lines, and 21.69% of branches. Configurations 21-32 therefore added
5,123 covered regions, 163 functions, 4,385 lines, and 2,076 branches beyond
the first 20 in that view. The separate all-profile worker and prefork views
reached 45.50% and 45.36% of lines respectively; no single binary contains all
three MPM implementations.

Compared with the preceding 7h27m union, the longer exact session added roughly
995 regions, 7 functions, 640 lines, and 548 branches. That earlier session
crossed a binary rebuild and emitted three profile-mismatch warnings, so this
is a useful saturation trend rather than an exact provenance-matched delta. The
campaign is still progressing, but slowly enough that targeted runtime states
are more useful than more time on the same matrix. Strong core paths included
`server/protocol.c` at 81.19% line coverage and
`modules/http/http_filters.c` at 79.45%. Meaningful under-covered paths included
`modules/ssl/ssl_engine_kernel.c` at 17.99%,
`modules/ssl/ssl_engine_io.c` at 30.94%, `modules/mappers/mod_rewrite.c` at
35.11%, `modules/dav/main/mod_dav.c` at 36.25%, and
`modules/proxy/mod_proxy.c` at 40.51%.

Two focused, self-contained personalities now address those gaps. Config 33
proxies fuzz requests through a full TLS handshake to a local HTTPS virtual
host and uses a DBM TLS session cache. Config 34 uses DBM-backed response
caching with validators, ranges, and cache-control transitions. Two matching
multipacket seeds exercise repeated and stateful requests. Post-rebuild smoke
profiles confirmed the intended gain: config 33's TLS proxy seed reached 38.98%
of `ssl_engine_io.c` lines, versus 30.94% in the long aggregate, and config 34's
cache seed reached 37.43% of `mod_socache_dbm.c`, versus 1.40%. These narrow
single-seed profiles validate the paths but are not new whole-campaign totals.

The completed session also contained three genuine Apache child SIGSEGVs:
config 12 at 22:33:39 and 00:36:56 local time, and config 20 at 23:24:00.
Apache logged `exit signal Segmentation fault (11)`, but ASan did not emit a
fatal report and no core was retained. Apache had replaced ASan's default
fatal-signal handler, while ASan had limited core dumps. The exact inputs had
already rotated out of the ten retained testcase logs, so the crashes are
confirmed findings without an attributable reproducer or demonstrated impact.

The runtime now sets ASan's fatal-signal options to mode 2, which prevents
Apache from replacing those handlers, while keeping sanitizer recovery enabled
for nonfatal findings. The fuzzer also preserves each exact binary input before
starting its coverage run and removes it only after successful coverage import.
A worker death causes the controller to time out and exit, leaving the input as
`logs/currentInputN-PID` for replay; `status.sh` counts these artifacts.

This snapshot covers the completed 20-configuration multiprocess run started
at `20260912T225603Z`. It ran for 10h28m and completed at least 17,196,297
inputs. The raw sanitizer logs contain 123 recovering UBSan reports at three
distinct upstream source sites:

- 57 signed-left-shift overflow reports in Apache
  `modules/http/http_filters.c:270`, while parsing oversized hexadecimal chunk
  sizes;
- 57 incorrect-function-type calls to Apache's `form_header_field` through
  APR `tables/apr_tables.c:990`; and
- 9 incorrect-function-type calls to `ssl_var_lookup` at Apache
  `server/ssl.c:192`, where the core optional-function declaration returns
  `const char *` and the loaded mod_ssl declaration returns `char *`.

These are repeatable undefined-behavior reports. None produced an
AddressSanitizer memory error or LibFuzzer crash artifact during this run. The
function-type reports also appeared once per relevant Apache child, so the raw
occurrence count is not a count of separate bugs.

## UBSan impact triage

The chunk-size report is the only finding with plausible protocol impact beyond
terminating a hardened worker. `apr_off_t` is a signed 64-bit type on this build,
and a 16-significant-digit chunk size beginning with `8` through `f` shifts into
its sign bit before Apache tests whether the result is negative. This path is
unauthenticated and is used for both client request bodies and chunked responses
received from proxied backends.

An isolated replay of `8000000000000000` on the pinned Clang 23.1.1 `-O0` build
reported the shift and returned HTTP 413. Focused Clang 23.1.1 and GCC 15.2.1
`-O2` probes retained the following negative-value check, so no optimized-build
bypass, memory error, request desynchronization, or worker hang has been
demonstrated. A compiler is still allowed to exploit the undefined shift; if the
guard were transformed, the resulting negative remaining length could cause
empty reads, a worker loop, or bytes being interpreted at the wrong request
boundary. Those are latent risks rather than observed impact.

Apache's current [`2.4.x` branch](https://github.com/apache/httpd/blob/2.4.x/modules/http/http_filters.c)
still initializes the chunk bit budget to `sizeof(apr_off_t) * 8`.
[Trunk](https://github.com/apache/httpd/blob/trunk/modules/http/http_filters.c)
uses `sizeof(apr_off_t) * 8 - 4` and explicitly says the reduction avoids
undefined left-shift behavior. Backporting that small change is the direct fix.

The two incorrect-function-type reports have matching pointer representations
and calling conventions on the tested x86-64 ABI:

- `form_header_field` takes `header_struct *` where APR's callback type takes
  `void *`; the object passed by TRACE really is a `header_struct`.
- The stable mod_ssl optional function returns `char *` and takes `char *`, while
  the core compatibility bridge calls it through a type using `const char *`.

Neither mismatch has a credible direct memory-corruption effect on this ABI, and
ordinary builds execute the calls as intended. They remain C undefined behavior:
non-recovering `-fsanitize=function` or LTO `-fsanitize=cfi-icall` builds can
terminate a request-processing child when a remote TRACE request, deflate lookup,
or TLS ALPN negotiation reaches the call. The parent can replace a child, but a
sustained trigger can churn hardened workers. Trunk still has the TRACE callback
cast; its mod_ssl declaration is now const-correct.

Eight deterministic inputs now target these paths: maximum signed, sign-bit,
and width-rejected chunk sizes; valid chunk extensions and trailers; TRACE
header boundaries and a chunked extended-TRACE body; and h2-only plus 255-byte
ALPN ClientHellos. Isolated replays reproduced all three UBSan sites, produced no
ASan report, and left both test servers healthy.

The best single configuration, config 20, covered 25.37% of Apache lines,
16.53% of regions, 38.71% of functions, and 11.21% of branches. Merging all 20
configurations covered 36.81% of lines, 23.61% of regions, 51.49% of functions,
and 16.87% of branches. Throughput averaged 22-23 inputs per second per
configuration and about 456 per second in aggregate.

## Sanitizer scope

The default config 1 artifact scan inspected 332 target-code build objects plus
the final `httpd` binary with no policy failures or inspection errors. Every
inspected object had strong ASan instrumentation evidence. An exhaustive
ASan-only audit also found ASan evidence in all 13 generated-data and inactive
platform-stub objects omitted by the default scan. This covers the static
Apache modules, APR, APR-util, and the locally built static Expat library.

The server still dynamically links the system OpenSSL, nghttp2, PCRE2, zlib,
and Brotli libraries, which do not contain ASan instrumentation. ASan can catch
an invalid access when instrumented Apache code touches memory associated with
these libraries, but it cannot check accesses performed entirely inside an
uninstrumented library. This does not block the Apache-focused campaign: local
dependency builds primarily expand the target to bugs inside those projects.
If that scope is wanted, use a separate static, coverage-instrumented profile
and start with nghttp2 and zlib. OpenSSL needs a TLS strategy that progresses
beyond ClientHello parsing to justify its cost; PCRE2 only receives fixed
patterns here, and this build links the Brotli encoder rather than a request-side
decoder.

ASan alone is also insufficient for the multiprocess feedback path. A local
dependency must be built with coverage instrumentation and linked so its guards
flow through covbridge. The existing one-million-counter bridge is already
about half occupied by Apache, APR, APR-util, and Expat, so the dependency
profile must measure guard use before adding a large library such as libcrypto.

The runtime already enables strict string checks, stack-use-after-return, and
initialization-order checks. Leak detection is disabled for the persistent
multiprocess fuzz run, and sanitizer errors recover so overnight fuzzing can
continue. A bounded leak-check run and a non-recovering reproduction mode would
cover those separate use cases.
