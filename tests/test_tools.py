#!/usr/bin/env python3

import ctypes
import gzip
import importlib.util
import os
from pathlib import Path
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
        self.assertEqual(len(first), 61)
        self.assertTrue({
            "seed-keepalive-wait", "seed-chunk-split", "seed-expect-continue",
            "seed-range-conditional", "seed-auth-schemes", "seed-proxy-forms",
            "seed-webdav-stateful", "seed-h2c-upgrade", "seed-tls-clienthello",
            "seed-deflate-input-stream", "seed-auth-cache-form-session",
            "seed-cache-socache", "seed-h2-control-matrix",
            "seed-proxy-connect-tunnel", "seed-proxy-fcgi",
        }.issubset(first))
        for data in first.values():
            decoded = REPLAY.parse_fuzzer_input(data)
            self.assertLessEqual(len(decoded.packets), 64)

        self.assertEqual(first["seed-h2c-prior-knowledge"][1:25],
                         b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.assertEqual(first["seed-tls-clienthello"][1], 0x16)
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
