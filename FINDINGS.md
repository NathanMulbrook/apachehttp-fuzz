# Fuzzing findings

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
