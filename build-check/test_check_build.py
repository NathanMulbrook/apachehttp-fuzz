"""Compile small fixtures and inspect them. No fixture binaries are executed."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import check_build as checker


SCRIPT = Path(checker.__file__).resolve()
SOURCE = """
#include <string.h>
int sample(char *output, const char *input, int number) {
    char buffer[64];
    strcpy(buffer, input);
    strcpy(output, buffer);
    return number == 7 ? number : number + 1;
}
int main(int argc, char **argv) {
    char output[64];
    return sample(output, "hello", argc);
}
"""


@unittest.skipUnless(all(shutil.which(tool) for tool in ("clang", "readelf", "ar", "strip")),
                     "compiled fixtures need clang and GNU binutils")
class BuildCheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="build-check-tests-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / "sample.c"
        cls.source.write_text(SOURCE)
        cls.plain = cls.compile("plain.o")
        cls.protected = cls.compile("protected.o", "-fstack-protector-all")
        cls.fortified = cls.compile("fortified.o", "-O2", "-D_FORTIFY_SOURCE=2")
        cls.asan = cls.compile("asan.o", "-fsanitize=address,undefined")
        cls.coverage = cls.compile("coverage.o", "-fsanitize=fuzzer-no-link")
        cls.profile = cls.compile("profile.o", "-fprofile-instr-generate", "-fcoverage-mapping")
        cls.binary = cls.compile("program", "-fstack-protector-all", link=True)
        cls.runtime = cls.root / "runtime-only"
        cls.command("clang", str(cls.plain), "-fsanitize=address", "-o", str(cls.runtime))

    @classmethod
    def command(cls, *args):
        return subprocess.run(args, check=True, capture_output=True, text=True,
                              env={**os.environ, "CCACHE_DISABLE": "1"}, timeout=60)

    @classmethod
    def compile(cls, name, *flags, link=False, source=None):
        output = cls.root / name
        cls.command("clang", "-O1", "-g", "-fno-stack-protector", "-U_FORTIFY_SOURCE",
                    *flags, *([] if link else ["-c"]), str(source or cls.source), "-o", str(output))
        return output

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.root, prefix="case-")
        self.addCleanup(self.case.cleanup)
        self.work = Path(self.case.name)

    def evidence(self, path):
        units = checker.inspect(path)
        self.assertEqual(len(units), 1)
        self.assertFalse(units[0].error)
        self.assertFalse(units[0].skipped)
        self.assertIsNotNone(units[0].evidence)
        return units[0].evidence

    def state(self, path, check):
        return checker.detect(check, self.evidence(path))[0]

    def split_report(self, report):
        summary, details = report.split("\n## Evidence key\n", 1)
        return summary, "## Evidence key\n" + details

    def run_config(self, scan, checks="", report="report.txt", expected=0,
                   overrides="", output_extra=""):
        config = self.work / "config.ini"
        output = "" if report is None else f"report = {report}\n"
        output += output_extra
        config.write_text(f"[scan]\n{scan}\n[checks]\n{checks}\n{overrides}\n[output]\n{output}")
        result = subprocess.run([sys.executable, str(SCRIPT), str(config)], cwd="/tmp",
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result, self.work / (report or "build-report.md")

    def test_plain_code_has_no_instrumentation(self):
        evidence = self.evidence(self.plain)
        for check in checker.CHECKS:
            with self.subTest(check=check):
                self.assertEqual(checker.detect(check, evidence)[0], "NOT-SEEN")

    def test_stack_protection_and_fortify_are_distinct(self):
        self.assertEqual(self.state(self.protected, "stack_protector"), "FOUND")
        self.assertEqual(self.state(self.protected, "fortify"), "NOT-SEEN")
        self.assertEqual(self.state(self.fortified, "fortify"), "FOUND")
        self.assertEqual(self.state(self.fortified, "stack_protector"), "NOT-SEEN")

    def test_sanitizer_objects(self):
        for check in ("asan", "ubsan"):
            self.assertEqual(self.state(self.asan, check), "FOUND")
        for check, sanitizer in (("tsan", "thread"), ("msan", "memory")):
            with self.subTest(check=check):
                obj = self.compile(f"{check}.o", f"-fsanitize={sanitizer}")
                self.assertEqual(self.state(obj, check), "FOUND")

    def test_source_coverage_is_not_fuzzer_guidance(self):
        self.assertEqual(self.state(self.profile, "llvm_profile"), "FOUND")
        self.assertEqual(self.state(self.profile, "source_coverage"), "FOUND")
        self.assertEqual(self.state(self.profile, "sancov"), "NOT-SEEN")
        for check in ("sancov", "sancov_cmp", "sancov_pc_table"):
            self.assertEqual(self.state(self.coverage, check), "FOUND")
        self.assertEqual(self.state(self.coverage, "source_coverage"), "NOT-SEEN")
        profile_only = self.compile("profile-only.o", "-fprofile-instr-generate")
        self.assertEqual(self.state(profile_only, "source_coverage"), "NOT-SEEN")

    def test_alternative_sanitizer_coverage(self):
        for mode in ("trace-pc-guard", "trace-pc", "inline-8bit-counters", "inline-bool-flag"):
            with self.subTest(mode=mode):
                obj = self.compile(f"{mode}.o", f"-fsanitize-coverage={mode}")
                self.assertEqual(self.state(obj, "sancov"), "FOUND")

    def test_runtime_definitions_do_not_prove_instrumentation(self):
        self.assertEqual(self.state(self.runtime, "asan"), "SYMBOL-ONLY")
        self.assertEqual(self.state(self.runtime, "sancov"), "SYMBOL-ONLY")
        self.assertEqual(self.state(self.runtime, "sancov_cmp"), "SYMBOL-ONLY")
        self.assertEqual(self.state(self.runtime, "libfuzzer"), "NOT-SEEN")

    def test_optional_weak_hooks_do_not_prove_instrumentation(self):
        source = self.work / "optional.c"
        source.write_text("""
extern void __msan_init(void) __attribute__((weak));
extern void __sanitizer_cov_trace_pc(void) __attribute__((weak));
void optional(void) {
    if (__msan_init) __msan_init();
    if (__sanitizer_cov_trace_pc) __sanitizer_cov_trace_pc();
}
""")
        obj = self.compile("optional.o", source=source)
        for check in ("msan", "sancov"):
            state, reason = checker.detect(check, self.evidence(obj))
            self.assertEqual(state, "SYMBOL-ONLY")
            self.assertIn("weak reference", reason)
            self.assertTrue(checker.policy_failed("present", state))

    def test_libfuzzer_callback_is_not_runtime(self):
        source = self.work / "callback.c"
        source.write_text("#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *p, size_t n) { return 0; }\n")
        callback = self.compile("callback.o", source=source)
        self.assertEqual(self.state(callback, "libfuzzer"), "NOT-SEEN")
        binary = self.compile("fuzzer", "-fsanitize=fuzzer", link=True, source=source)
        self.assertEqual(self.state(binary, "libfuzzer"), "FOUND")
        self.assertEqual(self.state(binary, "sancov"), "FOUND")

    def test_stripped_binary_uses_dynamic_symbols_and_sections(self):
        binary = self.work / "stripped"
        shutil.copyfile(self.binary, binary)
        self.command("strip", "--strip-all", str(binary))
        self.assertEqual(self.state(binary, "stack_protector"), "FOUND")
        self.assertEqual(self.state(binary, "fortify"), "UNKNOWN")
        covered = self.compile("covered-program", "-fsanitize=fuzzer-no-link,address", link=True)
        self.command("strip", "--strip-all", str(covered))
        self.assertEqual(self.state(covered, "sancov"), "FOUND")

    @unittest.skipUnless(shutil.which("objcopy"), "sectionless fixture needs objcopy")
    def test_sectionless_binary_remains_inconclusive_instead_of_being_skipped(self):
        if "--strip-section-headers" not in self.command("objcopy", "--help").stdout:
            self.skipTest("objcopy does not support --strip-section-headers")
        binary = self.work / "sectionless"
        self.command("objcopy", "--strip-section-headers", str(self.binary), str(binary))
        self.assertEqual(self.state(binary, "asan"), "UNKNOWN")
        for mode in ("present", "absent"):
            with self.subTest(mode=mode):
                _, report = self.run_config("binary_paths = sectionless", f"asan = {mode}",
                                            expected=1)
                summary = self.split_report(report.read_text())[0]
                self.assertIn(f"### asan\n\nExpected {mode}: 1 failure", summary)
                self.assertIn("sectionless: inconclusive:", summary)
                self.assertNotIn("\n  SKIPPED:", report.read_text())

    def test_global_data_objects_are_checked_for_asan(self):
        source = self.work / "global.c"
        source.write_text("int shared_array[16];\n")
        for name, flags, expected in (("plain-data.o", (), "NOT-SEEN"),
                                      ("asan-data.o", ("-fsanitize=address",), "FOUND")):
            fixture = self.compile(name, *flags, source=source)
            shutil.copyfile(fixture, self.work / name)
            self.assertEqual(self.state(fixture, "asan"), expected)
        _, report = self.run_config("object_dirs = .", "asan = present", expected=1)
        summary = self.split_report(report.read_text())[0]
        section = summary.split("### asan\n\nExpected present: 1 failure\n", 1)[1].split("\n## ", 1)[0]
        self.assertIn("plain-data.o: not seen", section)
        self.assertNotIn("asan-data.o", section)
        self.assertNotIn("\n  SKIPPED:", report.read_text())

    def test_archives_check_every_code_member_including_thin_archives(self):
        for mode in ("rcs", "rcsT"):
            with self.subTest(mode=mode):
                archive = self.work / f"{mode}.a"
                self.command("ar", mode, str(archive), str(self.plain), str(self.asan))
                units = checker.inspect(archive, "archive")
                self.assertEqual([Path(unit.member).name for unit in units],
                                 [self.plain.name, self.asan.name])
                self.assertEqual([checker.detect("asan", unit.evidence)[0] for unit in units],
                                 ["NOT-SEEN", "FOUND"])
                errors = []
                report, failures = checker.make_report(
                    [(archive, "archive")], errors, {"asan": "present"},
                    self.work / "example.ini")
                summary, detailed = self.split_report(report)
                self.assertEqual(errors, [])
                self.assertEqual(failures, 1)
                self.assertIn("Failed items", summary)
                self.assertIn("### asan\n\nExpected present: 1 failure", summary)
                self.assertIn(f"{archive.name}({units[0].member}): not seen", summary)
                self.assertNotIn(f"{archive.name}({units[1].member}):", summary)
                self.assertIn("__asan_init", detailed)

    def test_duplicate_archive_member_names_remain_separate(self):
        paths = []
        for directory, fixture in (("first", self.plain), ("second", self.asan)):
            parent = self.work / directory
            parent.mkdir()
            path = parent / "same.o"
            shutil.copyfile(fixture, path)
            paths.append(path)
        archive = self.work / "duplicates.a"
        self.command("ar", "qc", str(archive), *map(str, paths))
        units = checker.inspect(archive, "archive")
        self.assertEqual(len(units), 2)
        self.assertEqual([checker.detect("asan", unit.evidence)[0] for unit in units],
                         ["NOT-SEEN", "FOUND"])
        report, failures = checker.make_report(
            [(archive, "archive")], [], {"asan": "present", "stack_protector": "present"},
            self.work / "config.ini")
        summary, detailed = self.split_report(report)
        self.assertEqual(failures, 1)
        self.assertIn("### asan\n\nExpected present: 1 failure", summary)
        self.assertIn("### stack_protector\n\nExpected present: 2 failures", summary)
        self.assertIn("duplicates.a(same.o): not seen", summary)
        stack_section = summary.split("### stack_protector\n", 1)[1]
        entries = stack_section.split("```text\n", 1)[1].split("\n```", 1)[0].splitlines()
        self.assertEqual(entries, ["duplicates.a: 2 member failures; see File details"])
        counts = re.search(r"\| stack_protector\s+\| present\s+\| \[(\d+)\]\(#stack_protector\)\s+\|\s+(\d+)\s+\|",
                           summary)
        self.assertIsNotNone(counts)
        self.assertEqual(counts.groups(), ("1", "2"))
        self.assertEqual(len(entries), int(counts[1]))
        self.assertRegex(summary, r"\| asan\s+\| present\s+\| \[1\]\(#asan\)\s+\|\s+1\s+\|")
        first = detailed.split("#### `same.o`\n", 1)[1].split("\n#### ", 1)[0]
        second = detailed.split("#### `same.o` [occurrence 2]\n", 1)[1]
        self.assertRegex(first, r"asan\s+NOT-SEEN\s+.*FAIL \(expected present\)")
        self.assertRegex(second, r"asan\s+FOUND\s+__asan_")
        for member in (first, second):
            self.assertRegex(member, r"stack_protector\s+NOT-SEEN\s+.*FAIL \(expected present\)")
        self.assertRegex(summary, r"\| archive member\s+\|\s+2\s+\|\s+2\s+\|\s+0 \|")

    def test_discovery_paths_spaces_excludes_symlinks_and_fifos(self):
        objects = self.work / "object files"
        objects.mkdir()
        shutil.copyfile(self.plain, objects / "plain.o")
        skipped = objects / "skip"
        skipped.mkdir()
        (skipped / "invalid.o").write_text("invalid")
        binaries = self.work / "binaries"
        binaries.mkdir()
        shutil.copyfile(self.binary, binaries / "no-extension")
        (binaries / "alias.so").symlink_to("no-extension")
        (binaries / "script").write_text("#!/bin/sh\nexit 0\n")
        (binaries / "directory-link").symlink_to(objects, target_is_directory=True)
        os.mkfifo(binaries / "pipe")
        result, report = self.run_config("object_dirs = object files\nbinary_paths = binaries\nexclude = skip")
        self.assertIn("2 artifacts", result.stdout)
        self.assertRegex(report.read_text(), r"stack_protector\s+FOUND\s+__stack_chk_fail")
        self.assertNotIn("invalid.o", report.read_text())
        # Re-running with the same inputs gives the same report.
        before = report.read_text()
        self.run_config("object_dirs = object files\nbinary_paths = binaries\nexclude = skip")
        self.assertEqual(report.read_text(), before)

    def test_discovery_uses_content_and_retains_known_invalid_candidates(self):
        for name in ("plain.obj", "module", "native.lo", "native.ko", "unusual.payload"):
            shutil.copyfile(self.plain, self.work / name)
        archive = self.work / "library.payload"
        self.command("ar", "rcs", str(archive), str(self.plain))
        rust_archive = self.work / "library.rlib"
        shutil.copyfile(archive, rust_archive)
        bitcode = self.compile("bitcode.payload", "-flto")
        shutil.copyfile(bitcode, self.work / bitcode.name)
        (self.work / "libtool.lo").write_text("# libtool object file\npic_object='.libs/plain.o'\n")
        (self.work / "notes.txt").write_text("ordinary text")
        for name in ("bad.o", "bad.obj", "bad.a", "bad.rlib", "bad.bc"):
            (self.work / name).write_text("invalid object")
        artifacts, errors = checker.discover([self.work], [], [], self.work)
        self.assertEqual(errors, [])
        found = {path.name: kind for path, kind in artifacts}
        self.assertEqual(found, {
            "plain.obj": "object", "module": "object", "native.lo": "object",
            "native.ko": "object", "unusual.payload": "object",
            "library.payload": "archive", "library.rlib": "archive",
            "bitcode.payload": "object", "bad.o": "object", "bad.obj": "object",
            "bad.a": "archive", "bad.rlib": "archive", "bad.bc": "object",
        })
        _, report = self.run_config("object_dirs = .", expected=2)
        _, detailed = self.split_report(report.read_text())
        for name in ("bad.o", "bad.obj", "bad.a", "bad.rlib", "bad.bc", "bitcode.payload"):
            self.assertIn(name, detailed)
        self.assertNotIn("libtool.lo", detailed)

    def test_no_code_metadata_members_are_skipped_without_hiding_code_failures(self):
        members = []
        for index, section in enumerate((".rmeta", ".rmeta-link")):
            source = self.work / f"metadata-{index}.s"
            source.write_text(f'.section {section},"",@progbits\n.byte 1\n')
            member = self.work / f"metadata-{index}.o"
            self.command("clang", "-c", str(source), "-o", str(member))
            members.append(member)
        archive = self.work / "metadata.rlib"
        self.command("ar", "rcs", str(archive), *map(str, members), str(self.plain))
        units = checker.inspect(archive, "archive")
        self.assertEqual(len(units), 3)
        for unit in units[:2]:
            self.assertTrue(unit.skipped)
            self.assertFalse(unit.error)
            self.assertIsNone(unit.evidence)
        self.assertEqual(checker.detect("asan", units[2].evidence)[0], "NOT-SEEN")
        errors = []
        report, failures = checker.make_report(
            [(archive, "archive")], errors, {"asan": "present"}, self.work / "config.ini")
        summary, detailed = self.split_report(report)
        self.assertEqual(errors, [])
        self.assertEqual(failures, 1)
        self.assertIn("SKIPPED", detailed)
        self.assertIn("### asan\n\nExpected present: 1 failure", summary)
        failures_section = summary.split("### asan\n", 1)[1].split("\n## ", 1)[0]
        self.assertIn("metadata.rlib(plain.o): not seen", failures_section)
        self.assertNotIn("metadata-0.o", failures_section)
        self.assertNotIn("metadata-1.o", failures_section)

    def test_native_code_with_embedded_llvm_bitcode_is_inspected(self):
        obj = self.compile("embedded-bitcode.o", "-fembed-bitcode", "-fstack-protector-all")
        evidence = self.evidence(obj)
        self.assertIn(".llvmbc", evidence[2])
        self.assertEqual(checker.detect("stack_protector", evidence)[0], "FOUND")

    def test_installed_rust_compiler_rlib_metadata_and_code(self):
        rustup_home = Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")))
        candidates = [Path(shutil.which("rustc") or "/nonexistent/rustc")]
        candidates += sorted(rustup_home.glob("toolchains/*/bin/rustc"))
        rustc = next((path for path in candidates
                      if path.is_file() and path.resolve().name != "rustup"), None)
        if rustc is None:
            self.skipTest("no directly installed Rust compiler; do not invoke rustup")
        source = self.work / "fixture.rs"
        source.write_text('#[no_mangle]\npub extern "C" fn sample(number: u32) -> u32 { number + 1 }\n')
        archive = self.work / "fixture.rlib"
        self.command(str(rustc), "--crate-type=rlib", "--crate-name=fixture", "-Copt-level=1",
                     str(source), "-o", str(archive))
        units = checker.inspect(archive, "archive")
        self.assertTrue(any(unit.skipped and "rmeta" in unit.member for unit in units))
        code = [unit for unit in units if unit.evidence is not None]
        self.assertTrue(code)
        self.assertFalse(any(unit.error for unit in units))
        for unit in code:
            self.assertEqual(checker.detect("asan", unit.evidence)[0], "NOT-SEEN")
        self.run_config("object_dirs = .", "asan = absent")

    def test_parent_and_member_overrides_apply_independently(self):
        shutil.copyfile(self.plain, self.work / "plain.o")
        shutil.copyfile(self.asan, self.work / "asan.o")
        archive = self.work / "mixed.rlib"
        self.command("ar", "rcs", str(archive), str(self.plain), str(self.asan))
        result, report = self.run_config("object_dirs = .", "asan = present", overrides="""
[checks:plain.o]
asan = ignore
[checks:mixed.rlib]
asan = absent
[checks:mixed.rlib(asan.o)]
asan = present
""")
        self.assertIn("3 artifacts, 0 policy failures", result.stdout)
        summary = self.split_report(report.read_text())[0]
        self.assertIn("### asan\n", summary)
        self.assertNotIn("FAIL (expected", report.read_text())

    def test_last_matching_override_changes_only_its_explicit_checks(self):
        shutil.copyfile(self.plain, self.work / "plain.o")
        self.run_config("object_dirs = .", "asan = present\nstack_protector = present",
                        overrides="""
[checks:*.o]
asan = absent
stack_protector = absent
[checks:plain.o]
stack_protector = ignore
""")

    def test_member_only_override_does_not_match_a_standalone_object(self):
        self.assertEqual(checker.effective_modes(
            "plain.o", "", {"asan": "present"}, [("*(*)", {"asan": "ignore"})]),
            {"asan": "present"})
        shutil.copyfile(self.plain, self.work / "plain.o")
        self.run_config("object_dirs = .", "asan = present",
                        overrides="[checks:*(*)]\nasan = ignore", expected=1)

    def test_object_evidence_does_not_make_a_linked_runtime_conclusive(self):
        shutil.copyfile(self.asan, self.work / "asan.o")
        shutil.copyfile(self.runtime, self.work / "runtime-only")
        _, report = self.run_config("object_dirs = .\nbinary_paths = runtime-only",
                                    "asan = present", expected=1)
        summary = self.split_report(report.read_text())[0]
        section = summary.split("### asan\n\nExpected present: 1 failure\n", 1)[1].split("\n## ", 1)[0]
        self.assertIn("runtime-only: inconclusive:", section)
        self.assertNotIn("asan.o", section)
        _, report = self.run_config("object_dirs = .\nbinary_paths = runtime-only",
                                    "asan = present", overrides="[checks:runtime-only]\nasan = ignore")
        self.assertRegex(report.read_text(), r"asan\s+SYMBOL-ONLY")

    def test_policy_modes_and_exit_codes(self):
        _, report = self.run_config(f"binary_paths = {self.binary}",
                                    "stack_protector = present\nfortify = absent\nmsan = ignore")
        summary, detailed = self.split_report(report.read_text())
        self.assertNotIn("### msan", summary)
        self.assertIn("msan", detailed)
        _, report = self.run_config(f"binary_paths = {self.binary}", "stack_protector = absent", expected=1)
        self.assertIn("FAIL (expected absent)", report.read_text())
        self.run_config(f"binary_paths = {self.binary}", "asan = present", expected=1)
        for mode in ("present", "absent"):
            _, report = self.run_config(f"binary_paths = {self.runtime}", f"asan = {mode}", expected=1)
            self.assertIn("inconclusive:", self.split_report(report.read_text())[0])

    def test_legacy_modes_keep_their_expectations(self):
        self.run_config(f"binary_paths = {self.binary}", "stack_protector = require\nfortify = forbid")
        self.run_config(f"binary_paths = {self.binary}", "stack_protector = forbid", expected=1)
        _, report = self.run_config(f"binary_paths = {self.binary}", "asan = report")
        summary, detailed = self.split_report(report.read_text())
        self.assertIn("No expectations configured", summary)
        self.assertIn("asan", detailed)

    def test_summary_groups_failures_and_file_details_keep_all_results(self):
        artifacts = []
        for fixture in (self.plain, self.protected, self.fortified):
            path = self.work / fixture.name
            shutil.copyfile(fixture, path)
            artifacts.append((path, "object"))
        with mock.patch.object(checker, "inspect", wraps=checker.inspect) as inspection:
            report, failures = checker.make_report(
                artifacts, [], {"stack_protector": "present", "fortify": "absent"},
                self.work / "config.ini")
        summary, detailed = self.split_report(report)
        self.assertEqual(inspection.call_count, len(artifacts))
        self.assertEqual(failures, 2)  # fortified.o fails two checks, but counts once.
        file_list = summary.split("## Objects (3)\n\n```text\n", 1)[1].split("\n```", 1)[0]
        self.assertEqual(file_list.splitlines(), [str(path) for path, _ in artifacts])
        self.assertLess(summary.index("## Failures\n"), summary.index("## Objects (3)"))
        stack_failures = summary.split("### stack_protector\n\nExpected present: 2 failures\n", 1)[1].split("\n### ", 1)[0]
        self.assertIn("plain.o: not seen", stack_failures)
        self.assertIn("fortified.o: not seen", stack_failures)
        self.assertNotIn("protected.o", stack_failures)
        fortify_failures = summary.split("### fortify\n\nExpected absent: 1 failure\n", 1)[1].split("\n## ", 1)[0]
        self.assertIn("fortified.o: found:", fortify_failures)
        self.assertNotIn("plain.o", fortify_failures)
        self.assertNotIn("protected.o", fortify_failures)
        self.assertNotIn("__stack_chk_fail", summary)
        self.assertIn("__stack_chk_fail (reference)", detailed)
        self.assertIn("libfuzzer", detailed)  # Ignored checks still have detailed evidence.

    def test_summary_counts_and_bare_inventories_cover_each_file_type(self):
        object_path = self.work / "object with spaces.o"
        binary_path = self.work / "binary with spaces"
        archive_path = self.work / "empty.a"
        shutil.copyfile(self.plain, object_path)
        shutil.copyfile(self.binary, binary_path)
        self.command("ar", "rcs", str(archive_path))
        artifacts = [(object_path, "object"), (binary_path, "binary"), (archive_path, "archive")]
        errors = []
        report, failures = checker.make_report(
            artifacts, errors, {"stack_protector": "present", "fortify": "absent"},
            self.work / "config.ini")
        summary, detailed = self.split_report(report)
        self.assertEqual(failures, 1)
        self.assertEqual(len(errors), 1)
        self.assertRegex(summary, r"\| stack_protector\s+\| present\s+\| \[1\]\(#stack_protector\)\s+\|\s+1\s+\|")
        self.assertRegex(summary, r"\| fortify\s+\| absent\s+\| \[0\]\(#fortify\)\s+\|\s+0\s+\|")
        self.assertRegex(summary, r"\| libfuzzer\s+\| ignore\s+\|\s+-\s+\|\s+-\s+\|")
        self.assertIn("\n### stack_protector\n\nExpected present: 1 failure\n", summary)
        self.assertIn("\n### fortify\n\nExpected absent: 0 failures\n\nNone\n", summary)
        self.assertNotIn("(#libfuzzer)", summary)
        for kind in ("object", "binary"):
            self.assertRegex(summary, rf"\| {kind}\s+\|\s+1\s+\|\s+1\s+\|\s+0 \|")
        self.assertRegex(summary, r"\| archive\s+\|\s+1\s+\|\s+0\s+\|\s+1 \|")
        for title, path in (("Objects", object_path), ("Binaries", binary_path), ("Archives", archive_path)):
            section = summary.split(f"## {title} (1)\n\n```text\n", 1)[1].split("\n```", 1)[0]
            self.assertEqual(section, str(path))  # No indentation, bullets, labels, or error annotations.
        self.assertLess(summary.index("## Failure counts"), summary.index("## Failures\n"))
        self.assertLess(summary.index("## File counts"), summary.index("## Failures\n"))
        self.assertLess(summary.index("## Inspection errors"), summary.index("## Objects"))
        self.assertIn("\n### `empty.a` [archive]\n\n```text\n  ERROR:", detailed)
        self.assertTrue(report.startswith("# Build artifact report\n"))
        sections = ("Failure counts", "File counts", "Failures", "Inspection errors (1)",
                    "Objects (1)", "Binaries (1)", "Archives (1)",
                    "Evidence key", "Check summary", "File details")
        positions = []
        for title in sections:
            heading = f"\n## {title}\n"
            self.assertEqual(report.count(heading), 1)
            positions.append(report.index(heading))
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(report.count("# Build artifact report\n"), 1)
        self.assertEqual(report.count("Files checked:"), 1)
        self.assertEqual(report.count("\n## Inspection errors"), 1)
        self.assertNotIn("Build artifact summary", report)
        self.assertNotIn("## Inspection errors", detailed)
        self.assertNotIn("### `", summary)
        self.assertIn("\n### `object with spaces.o` [object]\n\n```text\n", detailed)

    def test_custom_and_default_report_paths_write_one_combined_file(self):
        expected_files = {self.work / "config.ini"}
        for name in ("reports/results.md", None):
            with self.subTest(report=name):
                result, report = self.run_config(f"binary_paths = {self.binary}", "asan = absent",
                                                report=name)
                expected_files.add(report)
                summary, detailed = self.split_report(report.read_text())
                self.assertIn("### asan\n\nExpected absent: 0 failures", summary)
                self.assertIn("## File details\n", detailed)
                self.assertRegex(detailed, r"stack_protector\s+FOUND\s+__stack_chk_fail")
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertTrue(result.stdout.startswith(f"Report: {report}"))
                self.assertEqual({path for path in self.work.rglob("*") if path.is_file()},
                                 expected_files)

    def test_removed_summary_option_is_rejected_without_changing_report(self):
        report = self.work / "report.txt"
        report.write_text("previous report")
        result, _ = self.run_config(f"binary_paths = {self.binary}",
                                    output_extra="summary = obsolete-summary.md\n", expected=2)
        self.assertIn("unknown config option: [output] summary", result.stderr)
        self.assertEqual(report.read_text(), "previous report")
        self.assertFalse((self.work / "obsolete-summary.md").exists())

    def test_invalid_report_parent_or_directory_preserves_existing_files(self):
        report = self.work / "report.txt"
        blocker = self.work / "not-a-directory"
        report.write_text("previous report")
        blocker.write_text("existing file")
        for output in ("report.txt/nested.md", "not-a-directory/nested.md", "."):
            with self.subTest(report=output):
                self.run_config(f"binary_paths = {self.binary}", report=output, expected=2)
                self.assertEqual(report.read_text(), "previous report")
                self.assertEqual(blocker.read_text(), "existing file")

    def test_report_hardlink_cannot_overwrite_an_unrelated_file(self):
        original = self.work / "unrelated.txt"
        original.write_text("unrelated content")
        os.link(original, self.work / "report.txt")
        self.run_config(f"binary_paths = {self.binary}", expected=2)
        self.assertEqual(original.read_text(), "unrelated content")

    def test_outputs_cannot_overwrite_excluded_unsupported_objects_or_hardlinks(self):
        artifact = self.work / "unsupported.o"
        artifact.write_text("unrecognized object format")
        alias = self.work / "alias.txt"
        os.link(artifact, alias)
        for output in ("unsupported.o", "alias.txt"):
            with self.subTest(output=output):
                self.run_config(f"binary_paths = {self.binary}\nexclude = unsupported.o",
                                report=output, expected=2)
                self.assertEqual(artifact.read_text(), "unrecognized object format")

    def test_artifact_named_output_symlinks_cannot_overwrite_their_targets(self):
        target = self.work / "payload.txt"
        target.write_text("unrecognized object format")
        artifact = self.work / "excluded.o"
        artifact.symlink_to(target.name)
        shutil.copyfile(self.plain, self.work / "valid.o")
        self.run_config("object_dirs = .\nexclude = excluded.o", report="excluded.o", expected=2)
        self.assertEqual(target.read_text(), "unrecognized object format")

    def test_missing_empty_and_invalid_inputs_are_errors(self):
        for scan in ("object_dirs = missing", "object_dirs = ."):
            with self.subTest(scan=scan):
                _, report = self.run_config(scan, expected=2)
                self.assertIn("no matching artifacts", report.read_text())
        self.run_config(f"object_dirs = .\nbinary_paths = {self.binary}", expected=2)
        (self.work / "bad.o").write_text("not an object")
        shutil.copyfile(self.plain, self.work / "valid.o")
        _, report = self.run_config("object_dirs = .", "asan = present", expected=2)
        self.assertIn("ERROR:", report.read_text())
        self.assertIn("### `valid.o` [object]", report.read_text())
        summary = self.split_report(report.read_text())[0]
        self.assertIn(str(self.work / "bad.o"), summary)
        failures = summary.split("### asan\n\nExpected present: 1 failure\n", 1)[1].split("\n## ", 1)[0]
        self.assertNotIn("bad.o", failures)
        self.assertIn("valid.o", failures)

    def test_overlapping_scan_roots_are_not_empty(self):
        shutil.copyfile(self.plain, self.work / "plain.o")
        result, _ = self.run_config(f"object_dirs = .\n    {self.work}")
        self.assertIn("1 artifacts", result.stdout)

    def test_invalid_config_leaves_previous_report_untouched(self):
        report = self.work / "report.txt"
        report.write_text("previous report")
        for checks in ("aasn = require", "asan = required"):
            with self.subTest(checks=checks):
                self.run_config(f"binary_paths = {self.binary}", checks, expected=2)
                self.assertEqual(report.read_text(), "previous report")
        for overrides in ("[checks:*.o]\naasn = present", "[checks:*.o]\nasan = required",
                          "[checks:]\nasan = present"):
            with self.subTest(overrides=overrides):
                self.run_config(f"binary_paths = {self.binary}", overrides=overrides, expected=2)
                self.assertEqual(report.read_text(), "previous report")

    def test_report_cannot_overwrite_its_config_or_checker(self):
        script = self.work / "check_build.py"
        shutil.copyfile(SCRIPT, script)
        original_script = script.read_bytes()
        config = self.work / "config.ini"
        for output in (config.name, script.name):
            with self.subTest(report=output):
                content = f"[scan]\nbinary_paths = {self.binary}\n[output]\nreport = {output}\n"
                config.write_text(content)
                result = subprocess.run([sys.executable, str(script), str(config)], cwd="/tmp",
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("must not overwrite", result.stderr)
                self.assertEqual(config.read_text(), content)
                self.assertEqual(script.read_bytes(), original_script)

    def test_report_cannot_overwrite_inputs_even_when_excluded(self):
        artifact = self.work / "protected.o"
        shutil.copyfile(self.protected, artifact)
        original = artifact.read_bytes()
        self.run_config("object_dirs = .\nexclude = protected.o", report="protected.o", expected=2)
        self.assertEqual(artifact.read_bytes(), original)
        alias = self.work / "alias.txt"
        os.link(artifact, alias)
        self.run_config("object_dirs = .", report="alias.txt", expected=2)
        self.assertEqual(artifact.read_bytes(), original)
        script = self.work / "input.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        self.run_config("binary_paths = input.sh", report="input.sh", expected=2)
        self.assertEqual(script.read_text(), "#!/bin/sh\nexit 0\n")

    def test_empty_archives_and_bitcode_are_errors(self):
        empty = self.work / "empty.a"
        self.command("ar", "rcs", str(empty))
        bitcode = self.compile("bitcode.o", "-flto")
        for path, kind in ((empty, "archive"), (bitcode, "object")):
            with self.subTest(path=path):
                units = checker.inspect(path, kind)
                self.assertTrue(any(unit.error for unit in units))
                self.assertFalse(any(unit.evidence is not None for unit in units))

    def test_archive_errors_preserve_valid_members_before_and_after_the_error(self):
        text = self.work / "text.txt"
        text.write_text("not ELF")
        mixed = self.work / "mixed.a"
        self.command("ar", "rcs", str(mixed), str(self.plain), str(text), str(self.asan))
        units = checker.inspect(mixed, "archive")
        code = [unit for unit in units if unit.evidence is not None]
        self.assertEqual([unit.member for unit in code], ["plain.o", "asan.o"])
        self.assertEqual([checker.detect("asan", unit.evidence)[0] for unit in code],
                         ["NOT-SEEN", "FOUND"])
        self.assertTrue(any(unit.member == "text.txt" and unit.error for unit in units))
        self.assertTrue(any(not unit.member and unit.error for unit in units))
        _, report = self.run_config("object_dirs = .", "asan = present", expected=2)
        summary, detailed = self.split_report(report.read_text())
        self.assertIn("#### `plain.o`", detailed)
        self.assertIn("#### `asan.o`", detailed)
        self.assertIn("ERROR:", detailed)
        self.assertIn("### asan\n\nExpected present: 1 failure", summary)
        self.assertIn("mixed.a(plain.o): not seen", summary)
        self.assertRegex(summary, r"\| archive\s+\|\s+1\s+\|\s+0\s+\|\s+1 \|")
        self.assertRegex(summary, r"\| archive member\s+\|\s+3\s+\|\s+2\s+\|\s+1 \|")


if __name__ == "__main__":
    unittest.main()
