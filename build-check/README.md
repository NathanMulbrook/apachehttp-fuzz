# Build artifact checker

This is the read-only ELF/archive instrumentation checker carried over from
389-ds-fuzz. It uses Python 3 and GNU `readelf`; it never executes a scanned
target.

```sh
./checkObjects.sh
./checkObjects.sh /path/to/check-build.ini
python3 -m unittest discover -s build-check -p 'test_*.py' -v
```

The default config scans every config 1 target-code object plus the installed
server and writes `logs/symbolReport.md`. Generated data objects and inactive
platform stubs are excluded. Add `build/build_N` under `object_dirs` and
installed `run/run_N/bin/httpd` paths under `binary_paths` after building other
personalities.

Each check accepts `present`, `absent`, or `ignore`. Later
`[checks:PATH_GLOB]` sections override the baseline per option. A report records
static evidence for sanitizers, SanitizerCoverage, LLVM source coverage, stack
protection, Fortify, and the libFuzzer driver. Missing evidence is useful for
review but cannot prove which compiler flags were used.

Exit code 0 means the configured expectations passed, 1 means an expectation
failed, and 2 means configuration, discovery, inspection, or output failed.
