#!/usr/bin/env python3

import ctypes
import gzip
import importlib.util
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_script("apache_corpus_generator", "generate-interesting-corpus.py")
NORMALIZER = load_script("apache_corpus_normalizer", "normalize-corpus-flags.py")
REPLAY = load_script("apache_replay", "send-test-case.py")


class CorpusTests(unittest.TestCase):
    def test_seed_set_is_deterministic_and_well_framed(self):
        first = GENERATOR.corpus_seeds()
        second = GENERATOR.corpus_seeds()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 86)
        self.assertTrue({
            "seed-keepalive-wait", "seed-chunk-split", "seed-expect-continue",
            "seed-chunk-offt-max", "seed-chunk-offt-overflow",
            "seed-chunk-width-rejected", "seed-chunk-extensions-trailers",
            "seed-trace-max-forwards", "seed-trace-chunked-body",
            "seed-range-conditional", "seed-auth-schemes", "seed-proxy-forms",
            "seed-webdav-stateful", "seed-h2c-upgrade", "seed-tls-clienthello",
            "seed-tls-alpn-h2-only", "seed-tls-alpn-name-boundary",
            "seed-deflate-input-stream", "seed-auth-cache-form-session",
            "seed-cache-socache", "seed-h2-control-matrix",
            "seed-proxy-connect-tunnel", "seed-proxy-fcgi",
            "seed-authz-providers", "seed-buffer-filter-pipeline",
            "seed-ext-filter-lifecycle", "seed-vhost-userdir",
            "seed-rewrite-map-matrix", "seed-proxy-express-hosts",
            "seed-balancer-methods", "seed-balancer-manager",
            "seed-error-subrequests", "seed-cache-policy-lock",
            "seed-proxy-response-rewrite", "seed-data-filter-lengths",
            "seed-imagemap-coordinates", "seed-charset-translate",
            "seed-tls-backend-proxy", "seed-cache-socache-dbm",
        }.issubset(first))
        for data in first.values():
            decoded = REPLAY.parse_fuzzer_input(data)
            self.assertLessEqual(len(decoded.packets), 64)

        self.assertEqual(first["seed-h2c-prior-knowledge"][1:25],
                         b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.assertEqual(first["seed-tls-clienthello"][1], 0x16)
        max_chunk = REPLAY.parse_fuzzer_input(first["seed-chunk-offt-max"])
        self.assertIn(b"00000000000000007fffffffffffffff;edge=max\r\n",
                      b"".join(max_chunk.packets))
        overflow_chunk = REPLAY.parse_fuzzer_input(first["seed-chunk-offt-overflow"])
        self.assertIn(b"00000000000000008000000000000000;edge=overflow\r\n",
                      b"".join(overflow_chunk.packets))
        width_chunk = REPLAY.parse_fuzzer_input(first["seed-chunk-width-rejected"])
        self.assertIn(b"10000000000000000;edge=width\r\n",
                      b"".join(width_chunk.packets))
        trailers = REPLAY.parse_fuzzer_input(first["seed-chunk-extensions-trailers"])
        trailer_wire = b"".join(trailers.packets)
        self.assertIn(b'000000000000000a;token=value;quoted="a\\"b"\r\n',
                      trailer_wire)
        self.assertTrue(trailer_wire.endswith(
            b"X-Fuzz-Duplicate: one\r\nX-Fuzz-Duplicate: two\r\n\r\n"))
        trace = REPLAY.parse_fuzzer_input(first["seed-trace-max-forwards"])
        self.assertEqual(trace.flags, 0x07)
        self.assertEqual(len(trace.packets), 3)
        self.assertTrue(all(packet.startswith(b"TRACE ") for packet in trace.packets))
        self.assertIn(b"Max-Forwards: 0\r\n", trace.packets[0])
        self.assertIn(b"TRACE http://[::1]:6810/trace ", trace.packets[1])
        self.assertIn(b"Max-Forwards: 9223372036854775807\r\n", trace.packets[2])
        trace_body = REPLAY.parse_fuzzer_input(first["seed-trace-chunked-body"])
        self.assertEqual(trace_body.flags, 0x02)
        self.assertIn(b"TRACE /trace/body HTTP/1.1\r\n", trace_body.packets[0])
        self.assertEqual(b"".join(trace_body.packets[1:]),
                         b"4;trace=yes\r\nbody\r\n5;part=two\r\nfuzz!\r\n"
                         b"0\r\nX-Trace-Trailer: complete\r\n\r\n")
        self.assertEqual(GENERATOR.tls_alpn((b"h2",)), b"\x00\x03\x02h2")
        longest_alpn = b"fuzz-" + b"a" * 250
        boundary_alpn = b"\x01\x03\xff" + longest_alpn + b"\x02h2"
        self.assertIn(GENERATOR.tls_extension(0x0010, boundary_alpn),
                      first["seed-tls-alpn-name-boundary"])
        for name in ("seed-tls-alpn-h2-only", "seed-tls-alpn-name-boundary"):
            record = first[name][1:]
            self.assertEqual(int.from_bytes(record[3:5], "big"), len(record) - 5)
            self.assertEqual(int.from_bytes(record[6:9], "big"), len(record) - 9)
        expect = REPLAY.parse_fuzzer_input(first["seed-expect-continue"])
        self.assertEqual(expect.flags, 0x07)
        self.assertEqual(len(expect.packets), 2)
        upgrade = REPLAY.parse_fuzzer_input(first["seed-h2c-upgrade"])
        self.assertEqual(upgrade.packets[2][5:9], b"\x00\x00\x00\x03")
        compressed = REPLAY.parse_fuzzer_input(first["seed-deflate-input-stream"])
        self.assertEqual(gzip.decompress(b"".join(compressed.packets[1:])),
                         b"fuzz input filter\n" * 4)
        continuation = first["seed-h2-continuation"][25:]
        frame_types = []
        while continuation:
            frame_length = int.from_bytes(continuation[:3], "big")
            frame_types.append(continuation[3])
            continuation = continuation[9 + frame_length:]
        self.assertEqual(frame_types, [0x04, 0x01, 0x09])

        buffer_seed = REPLAY.parse_fuzzer_input(
            first["seed-buffer-filter-pipeline"])
        self.assertEqual([len(packet) for packet in buffer_seed.packets[1:]],
                         [31, 2, 32])
        self.assertIn(b"Content-Length: 65\r\n", buffer_seed.packets[0])
        charset_seed = REPLAY.parse_fuzzer_input(first["seed-charset-translate"])
        self.assertEqual(charset_seed.flags, 0x07)
        self.assertIn(b"fuzz\xc2\xa3\xc3\xa9", charset_seed.packets[0])
        self.assertIn(b"1\r\n\xc2\r\n1\r\n\xa3\r\n", charset_seed.packets[1])
        self.assertIn(b"1\r\n\xff\r\n", charset_seed.packets[2])
        data_seed = REPLAY.parse_fuzzer_input(first["seed-data-filter-lengths"])
        self.assertEqual(len(data_seed.packets), 7)
        for packet, length in zip(
                data_seed.packets, (0, 1, 2, 3, 5999, 6000, 6001)):
            self.assertIn(f"/data/length-{length}.".encode(),
                          packet)
        manager_seed = REPLAY.parse_fuzzer_input(first["seed-balancer-manager"])
        self.assertIn(b"nonce=fuzz", manager_seed.packets[2])
        self.assertIn(b"w_lf=1.25", manager_seed.packets[2])
        self.assertIn(b"b_lbm=byrequests", manager_seed.packets[2])
        error_seed = REPLAY.parse_fuzzer_input(first["seed-error-subrequests"])
        self.assertIn(b"GET /fallback-zone/subdir HTTP/1.1", error_seed.packets[3])
        self.assertIn(b"GET /fallback-zone/subdir/ HTTP/1.1", error_seed.packets[4])
        vhost_seed = REPLAY.parse_fuzzer_input(first["seed-vhost-userdir"])
        self.assertEqual(vhost_seed.packets[0].count(b"Host:"), 1)
        self.assertIn(b"Host: blue.vhost.fuzz.test\r\n", vhost_seed.packets[0])

    def test_generator_writes_named_seeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(ROOT / "generate-interesting-corpus.py"), temporary],
                check=True, text=True, capture_output=True)
            self.assertIn("seed-h2c-upgrade", result.stdout)
            self.assertEqual(
                (Path(temporary) / "seed-tls-clienthello").read_bytes(),
                GENERATOR.corpus_seeds()["seed-tls-clienthello"])

    def test_normalizer_is_idempotent_and_adds_flag_variants(self):
        framed = NORMALIZER.multipacket_seed(0xFE)
        self.assertEqual(NORMALIZER.normalize(framed)[0], 0x06)
        self.assertEqual(NORMALIZER.normalize(b"\x02\x00"), b"\x00\x00")

        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary)
            (corpus / "legacy").write_bytes(b"\xffGET / HTTP/1.0\r\n\r\n")
            first = subprocess.run(
                [sys.executable, str(ROOT / "normalize-corpus-flags.py"), temporary],
                check=True, text=True, capture_output=True)
            snapshot = {path.name: path.read_bytes() for path in corpus.iterdir()}
            second = subprocess.run(
                [sys.executable, str(ROOT / "normalize-corpus-flags.py"), temporary],
                check=True, text=True, capture_output=True)
            self.assertIn("added 6 seed inputs", first.stdout)
            self.assertIn("normalized 0 files; added 0 seed inputs", second.stdout)
            self.assertEqual(snapshot,
                             {path.name: path.read_bytes() for path in corpus.iterdir()})


class ConfigMatrixTests(unittest.TestCase):
    def test_all_config_personalities_are_present_once(self):
        text = (ROOT / "fuzz-configs.conf.in").read_text()
        identifiers = [int(value) for value in re.findall(
            r"^<IfDefine FUZZ_CONFIG_(\d+)>", text, re.MULTILINE)]
        self.assertEqual(identifiers, list(range(1, 35)))

    def test_expansion_exercises_distinct_module_paths(self):
        text = (ROOT / "fuzz-configs.conf.in").read_text()
        blocks = {
            int(number): body for number, body in re.findall(
                r"<IfDefine FUZZ_CONFIG_(\d+)>(.*?)</IfDefine>", text, re.DOTALL)
        }
        expected = {
            21: ("AuthBasicProvider anon", "Require group fuzzers"),
            22: ("SetInputFilter BUFFER", "SetOutputFilter RATE_LIMIT"),
            23: ("ExtFilterDefine fuzz-in", "Onfail=remove"),
            24: ("VirtualDocumentRoot", "UserDir"),
            25: ("dbm=sdbm:", "int:tolower", "int:escape"),
            26: ("ProxyExpressEnable On", "ProxyExpressDBMType sdbm"),
            27: ("lbmethod=bytraffic", "lbmethod=bybusyness", "balancer-manager"),
            28: ("ErrorDocument 404", "FallbackResource", "DirectoryIndexRedirect"),
            29: ("CacheLock On", "CacheStoreNoStore On", "CacheIgnoreQueryString On"),
            30: ("ProxyPassReverseCookieDomain", "ProxyErrorOverride On 404 500 503"),
            31: ("SetOutputFilter DATA", "AddHandler imap-file .map"),
            32: ("CharsetSourceEnc ISO-8859-1", "CharsetDefault UTF-8"),
            33: ("SSLProxyEngine On", "https://[::1]:@BACKEND_PORT@/",
                 "SSLSessionCache \"dbm:"),
            34: ("CacheSocache \"dbm:", "CacheEnable socache /socache/"),
        }
        for config, directives in expected.items():
            for directive in directives:
                self.assertIn(directive, blocks[config],
                              f"config {config} is missing {directive}")

    def test_proxy_targets_remain_loopback_only(self):
        text = (ROOT / "fuzz-configs.conf.in").read_text()
        targets = re.findall(r"(?:https?|ws)://[^/\s\"]+", text)
        self.assertTrue(targets)
        self.assertTrue(all(
            "[::1]" in target or "[[]::1[]]" in target for target in targets),
            targets)

    def test_build_installs_expansion_modules_maps_and_boundaries(self):
        text = (ROOT / "build.sh").read_text()
        for token in (
                '3 | 19 | 23)', '"--enable-data=static"',
                '"--enable-imagemap=static"', '"--enable-charset-lite=static"',
                's#@PORT@#$port#g', 's#@BACKEND2_PORT@#$backend2_port#g',
                'rewrite-map.dbm', 'express-map.dbm', 'conf/filter.sh',
                'htdocs/shapes.map', 'length-0.txt', 'length-1.bin',
                'length-2.txt', 'length-3.bin', 'length-5999.txt',
                'length-6000.txt', 'length-6001.bin'):
            self.assertIn(token, text, f"build.sh is missing {token}")
        self.assertIn('[ "$BUILD_CONFIG" = 13 ] || [ "$BUILD_CONFIG" = 33 ]',
                      text)

    def test_command_scripts_accept_the_complete_matrix(self):
        for name in ("build.sh", "run.sh", "status.sh", "genreport.sh"):
            text = (ROOT / name).read_text()
            self.assertRegex(text, r"(?m)^MAX_CONFIG=34$")

        run_source = (ROOT / "run.sh").read_text()
        self.assertIn("handle_segv=2", run_source)
        self.assertIn("handle_sigbus=2", run_source)
        self.assertIn("halt_on_error=0", run_source)


class ReplayTests(unittest.TestCase):
    def test_parser_rejects_malformed_and_packet_overflow(self):
        malformed = (b"\x02", b"\x02\x00", b"\x02\x00\x00", b"\x02\x00\x02x")
        for data in malformed:
            with self.assertRaises(ValueError):
                REPLAY.parse_fuzzer_input(data)
        too_many = b"\x02" + (b"\x00\x01x" * 65)
        with self.assertRaises(ValueError):
            REPLAY.parse_fuzzer_input(too_many)

    def test_dry_run_selects_framed_packet_and_raw_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            framed = Path(temporary) / "framed"
            framed.write_bytes(NORMALIZER.multipacket_seed(0x06))
            result = subprocess.run(
                [sys.executable, str(ROOT / "send-test-case.py"), str(framed),
                 "--packet", "2", "--dry-run"], check=True, text=True,
                capture_output=True)
            self.assertIn("multipacket=1", result.stdout)
            self.assertIn("selected=1", result.stdout)

            raw = Path(temporary) / "raw"
            raw.write_bytes(b"GET / HTTP/1.0\r\n\r\n")
            result = subprocess.run(
                [sys.executable, str(ROOT / "send-test-case.py"), str(raw),
                 "--raw", "--dry-run"], check=True, text=True,
                capture_output=True)
            self.assertIn("sizes=18", result.stdout)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which("clang") or shutil.which("cc")
        if cls.compiler is None:
            raise unittest.SkipTest("no C compiler")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.executable = Path(cls.temporary.name) / "test-harness"
        cls.library = Path(cls.temporary.name) / "libharness.so"
        common = ["-std=c11", "-D_DEFAULT_SOURCE", "-DAPACHE_FUZZ_NO_APACHE",
                  "-DAPACHE_FUZZ_NO_LOG", "-I", str(ROOT)]
        subprocess.run(
            [cls.compiler, *common, "-Wall", "-Wextra", "-Werror",
             str(ROOT / "fuzzer.c"), str(ROOT / "tests/test_harness.c"),
             "-pthread", "-o", str(cls.executable)], check=True)
        subprocess.run(
            [cls.compiler, *common, "-shared", "-fPIC", str(ROOT / "fuzzer.c"),
             "-pthread", "-o", str(cls.library)], check=True)
        cls.harness = ctypes.CDLL(str(cls.library))
        cls.harness.fuzzServer.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
        cls.harness.fuzzServer.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def call_harness(self, data):
        value = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        return self.harness.fuzzServer(value, len(data))

    def capture(self, data, prelude=False, gate=False):
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0))
        except OSError as error:
            self.skipTest(f"IPv6 loopback unavailable: {error}")
        listener.listen(1)
        ctypes.c_int.in_dll(self.harness, "port").value = listener.getsockname()[1]
        captured = bytearray()
        error = []

        def server():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    if prelude:
                        while b"\r\n\r\n" not in captured:
                            captured.extend(connection.recv(4096))
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                            b"Connection: keep-alive\r\n\r\n")
                    if gate:
                        first = bytearray()
                        while b"\r\n\r\n" not in first:
                            first.extend(connection.recv(4096))
                        captured.extend(first)
                        connection.sendall(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        captured.extend(chunk)
            except BaseException as exception:
                error.append(exception)
            finally:
                listener.close()

        thread = threading.Thread(target=server)
        thread.start()
        result = self.call_harness(data)
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(error)
        return result, bytes(captured)

    def test_c_framing_unit(self):
        result = subprocess.run([str(self.executable)], check=True, text=True,
                                capture_output=True)
        self.assertIn("PASS harness framing", result.stdout)

    def test_multipacket_and_response_gate_reach_loopback_in_order(self):
        one = b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n"
        two = b"GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n"
        result, captured = self.capture(
            GENERATOR.multipacket(one, two, flags=0x06), gate=True)
        self.assertEqual(result, 0)
        self.assertEqual(captured, one + two)

    def test_keepalive_prelude_is_completed_before_payload(self):
        payload = b"GET /after-prelude HTTP/1.1\r\nHost: localhost\r\n\r\n"
        result, captured = self.capture(GENERATOR.raw(payload, 0x01), prelude=True)
        self.assertEqual(result, 0)
        self.assertEqual(captured, REPLAY.KEEPALIVE_PRELUDE + payload)

    def test_module_contract_uses_child_init_and_opt_in_directive(self):
        source = (ROOT / "fuzzer.c").read_text()
        self.assertIn('AP_INIT_FLAG("ApacheFuzzer"', source)
        self.assertIn("ap_hook_child_init(fuzzerChildInit", source)
        self.assertIn("ap_hook_child_stopping(fuzzerChildStopping", source)
        self.assertIn("atexit(fuzzerExitAfterApacheCleanup)", source)
        self.assertIn("launchedProcess == process", source)
        self.assertIn("writeCurrentInput(data, size)", source)
        self.assertIn("O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC", source)
        self.assertIn("removeCurrentInput()", source)
        self.assertIn("AP_DECLARE_MODULE(fuzzer)", source)


class CovbridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which("clang-20") or shutil.which("clang")
        if cls.compiler is None:
            raise unittest.SkipTest("clang is required for SanitizerCoverage")
        cls.temporary = tempfile.TemporaryDirectory()
        temporary = Path(cls.temporary.name)
        runtime = temporary / "covbridge.o"
        controller = temporary / "controller.o"
        workload = temporary / "workload.o"
        cls.executable = temporary / "test-covbridge"
        common = ["-std=c11", "-D_DEFAULT_SOURCE", "-I", str(ROOT),
                  "-Wall", "-Wextra", "-Werror"]
        subprocess.run(
            [cls.compiler, *common, "-O2", "-DCB_TESTING", "-c",
             str(ROOT / "covbridge.c"),
             "-o", str(runtime)], check=True)
        subprocess.run(
            [cls.compiler, *common, "-O2", "-c",
             str(ROOT / "tests/test_covbridge.c"), "-o", str(controller)],
            check=True)
        subprocess.run(
            [cls.compiler, *common, "-O1",
             "-fsanitize-coverage=trace-pc-guard", "-c",
             str(ROOT / "tests/covbridge_workload.c"), "-o", str(workload)],
            check=True)
        subprocess.run(
            [cls.compiler, str(controller), str(workload), str(runtime),
             "-Wl,--wrap=__sanitizer_cov_trace_pc_guard",
             "-Wl,--wrap=__sanitizer_cov_trace_pc_guard_init", "-pthread",
             "-o", str(cls.executable)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_shared_feedback_and_stale_controller_recovery(self):
        result = subprocess.run([str(self.executable)], check=True, text=True,
                                capture_output=True, timeout=5)
        self.assertIn("PASS covbridge shared feedback", result.stdout)

    def test_apache_integration_contract(self):
        source = (ROOT / "fuzzer.c").read_text()
        self.assertIn("ap_hook_pre_mpm(fuzzerPreMpm", source)
        self.assertIn("ap_hook_pre_close_connection(fuzzerPreCloseConnection",
                      source)
        self.assertIn("ap_hook_suspend_connection(fuzzerSuspendConnection",
                      source)
        self.assertIn("connection->local_addr->port == (apr_port_t)port",
                      source)
        self.assertIn("connection->master == NULL", source)
        self.assertIn("resetChildProfileFilename(pool)", source)
        self.assertIn("profileProcess != process", source)
        self.assertIn("cb_libfuzzer_import(&coverageSnapshot, 0)", source)
        self.assertIn("F_SETLKW", source)


class ProfileForkTests(unittest.TestCase):
    def test_children_write_distinct_mergeable_raw_profiles(self):
        compiler = shutil.which("clang-20") or shutil.which("clang")
        profdata = shutil.which("llvm-profdata-20") or shutil.which("llvm-profdata")
        if compiler is None or profdata is None:
            self.skipTest("matching Clang profiling tools are required")

        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            executable = temporary / "profile-fork"
            profile_dir = temporary / "profiles" / "run_1"
            profile_dir.mkdir(parents=True)
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fprofile-instr-generate",
                 str(ROOT / "tests/test_profile_fork.c"), "-o", str(executable)],
                check=True)
            environment = os.environ.copy()
            environment["LLVM_PROFILE_FILE"] = str(
                profile_dir / "default-%m-%p.profraw")
            subprocess.run([str(executable)], check=True, env=environment)

            profiles = sorted(profile_dir.glob("*.profraw"))
            child_profiles = [path for path in profiles if ".child-" in path.name]
            self.assertEqual(len(child_profiles), 3)
            for number, profile in enumerate(profiles):
                subprocess.run(
                    [profdata, "merge", "-sparse", str(profile), "-o",
                     str(temporary / f"single-{number}.profdata")], check=True)
            subprocess.run(
                [profdata, "merge", "-sparse", *map(str, profiles), "-o",
                 str(temporary / "combined.profdata")], check=True)


if __name__ == "__main__":
    unittest.main()
