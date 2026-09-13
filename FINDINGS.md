# Fuzzing findings

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
uninstrumented library. Building these parser-heavy dependencies locally with
the same Clang sanitizer flags is the largest remaining instrumentation
expansion.

The runtime already enables strict string checks, stack-use-after-return, and
initialization-order checks. Leak detection is disabled for the persistent
multiprocess fuzz run, and sanitizer errors recover so overnight fuzzing can
continue. A bounded leak-check run and a non-recovering reproduction mode would
cover those separate use cases.
