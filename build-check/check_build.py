#!/usr/bin/env python3
"""Inspect Linux ELF build artifacts with readelf; never execute them."""

import argparse
import configparser
from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Optional


# Match whole names, not substrings in filenames or debug information.
# Each check has a symbol pattern and a section pattern.
FORTIFY_FUNCTIONS = (
    "asprintf|confstr|dprintf|explicit_bzero|fdelt|fgets|fgets_unlocked|"
    "fgetws|fgetws_unlocked|fprintf|fread|fread_unlocked|fwprintf|getcwd|"
    "getdomainname|getgroups|gethostname|getlogin_r|gets|getwd|longjmp|"
    "mbsnrtowcs|mbsrtowcs|mbstowcs|memcpy|memmove|mempcpy|memset|obstack_printf|"
    "obstack_vprintf|poll|ppoll|pread|pread64|printf|read|readlink|readlinkat|"
    "realpath|recv|recvfrom|snprintf|sprintf|stpcpy|stpncpy|strcat|strcpy|"
    "strncat|strncpy|swprintf|syslog|ttyname_r|vasprintf|vdprintf|vfprintf|"
    "vfwprintf|vprintf|vsnprintf|vsprintf|vswprintf|vsyslog|vwprintf|wcrtomb|"
    "wcpcpy|wcpncpy|wcsnrtombs|wcsrtombs|wcstombs|wcscat|wcscpy|wcsncat|"
    "wcsncpy|wctomb|wmemcpy|wmemmove|wmempcpy|wmemset|wprintf"
)
CHECKS = {
    "stack_protector": (r"__stack_chk_(?:fail(?:_local)?|guard)", None),
    "fortify": (rf"(?:__(?:nldbl___)?(?:{FORTIFY_FUNCTIONS})_chk(?:ieee128)?|"
                r"__open(?:64|at|at64)?_2)", None),
    "asan": (r"__asan_(?:init|report_.*|load.*|store.*|stack_.*|register_.*|"
             r"unregister_.*|memcpy|memmove|memset)", r"asan_globals"),
    "ubsan": (r"__ubsan_handle_.*", None),
    "tsan": (r"__tsan_(?:init|read.*|write.*|atomic.*|func_entry|func_exit|vptr_.*)", None),
    "msan": (r"__msan_.*", None),
    "sancov": (r"__sanitizer_cov_(?:trace_pc(?:_guard)?|trace_pc_guard_init|"
               r"8bit_counters_init|bool_flag_init)", r"__sancov_(?:cntrs|guards|bools)"),
    "sancov_cmp": (r"__sanitizer_cov_trace_(?:(?:const_)?cmp[1248]|switch)", None),
    "sancov_pc_table": (r"__sanitizer_cov_pcs_init", r"__sancov_pcs"),
    "llvm_profile": (None, r"__llvm_prf_(?:cnts|bits)"),
    "source_coverage": (None, r"__llvm_covmap"),
    "libfuzzer": (r"LLVMFuzzerRunDriver", None),
}
MODES = {"present", "absent", "ignore"}
LEGACY_MODES = {"require": "present", "forbid": "absent", "report": "ignore"}
STATES = ("FOUND", "SYMBOL-ONLY", "NOT-SEEN", "UNKNOWN")


def lines(value):
    return [line.strip() for line in value.splitlines() if line.strip()]


def load_config(path):
    config = configparser.ConfigParser(interpolation=None)
    with path.open(encoding="utf-8") as source:
        config.read_file(source)
    allowed = {
        "scan": {"object_dirs", "binary_paths", "exclude"},
        "checks": set(CHECKS),
        "output": {"report"},
    }
    if config.defaults():
        raise ValueError("[DEFAULT] is not supported")
    for section in config.sections():
        if section.startswith("checks:"):
            if not section[len("checks:"):].strip():
                raise ValueError("[checks:PATH_GLOB] requires a nonempty path pattern")
            keys = set(CHECKS)
        elif section in allowed:
            keys = allowed[section]
        else:
            raise ValueError(f"unknown config section: [{section}]")
        for key in config[section]:
            if key not in keys:
                raise ValueError(f"unknown config option: [{section}] {key}")
    objects = lines(config.get("scan", "object_dirs", fallback=""))
    binaries = lines(config.get("scan", "binary_paths", fallback=""))
    if not objects and not binaries:
        raise ValueError("configure at least one object_dirs or binary_paths entry")
    modes = {}
    overrides = []
    for section in config.sections():
        if section != "checks" and not section.startswith("checks:"):
            continue
        section_modes = {}
        for check, value in config[section].items():
            mode = LEGACY_MODES.get(value.strip(), value.strip())
            if mode not in MODES:
                raise ValueError(f"invalid mode for {check}: {mode!r}; use {', '.join(sorted(MODES))}")
            if mode != "ignore" or section != "checks":
                section_modes[check] = mode
        if section == "checks":
            modes = section_modes
        else:
            overrides.append((section[len("checks:"):].strip(), section_modes))
    report = config.get("output", "report", fallback="build-report.md").strip()
    if not report:
        raise ValueError("[output] report must not be empty")
    base = path.parent
    report = base / report
    return ([base / name for name in objects], [base / name for name in binaries],
            lines(config.get("scan", "exclude", fallback="")), modes, overrides, report)


def effective_modes(name, member, modes, overrides):
    effective = modes.copy()
    for pattern, changes in overrides:
        if (fnmatch.fnmatchcase(name, pattern) or
                (member and fnmatch.fnmatchcase(f"{name}({member})", pattern))):
            effective.update(changes)
    return effective


def discover(objects, binaries, excludes, base):
    artifacts = {}
    errors = []

    def excluded(path):
        relative = Path(os.path.relpath(path, base)).as_posix()
        return any(fnmatch.fnmatchcase(relative, pattern) or
                   fnmatch.fnmatchcase(path.name, pattern) for pattern in excludes)

    def add(path, kind, explicit=False):
        if excluded(path):
            return
        try:
            if not stat.S_ISREG(path.stat().st_mode):
                if explicit:
                    errors.append(f"{path}: expected a regular file")
                return
            with path.open("rb") as source:
                header = source.read(18)
            elf_type = None
            if header[:4] == b"\x7fELF" and len(header) == 18 and header[5] in (1, 2):
                elf_type = int.from_bytes(header[16:18], "little" if header[5] == 1 else "big")
            if kind == "object":
                if header.startswith((b"!<arch>\n", b"!<thin>\n")):
                    artifact_kind = "archive"
                elif elf_type == 1 or header.startswith((b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
                    artifact_kind = "object"
                elif path.suffix in {".o", ".obj", ".a", ".rlib", ".bc"}:
                    # Keep malformed known artifacts visible as inspection errors.
                    # Text libtool .lo wrappers are intentionally not candidates.
                    artifact_kind = "archive" if path.suffix in {".a", ".rlib"} else "object"
                else:
                    return
            else:
                if elf_type not in (2, 3):
                    if explicit:
                        errors.append(f"{path}: expected an ELF executable or shared library")
                    return
                artifact_kind = "binary"
            artifacts[path.resolve(strict=True)] = artifact_kind
            return True
        except OSError as error:
            errors.append(f"{path}: {error}")

    for roots, kind in ((objects, "object"), (binaries, "binary")):
        for root in roots:
            if excluded(root):
                continue
            matched = 0
            previous_errors = len(errors)
            if root.is_file() and kind == "binary":
                matched += bool(add(root, kind, explicit=True))
            elif root.is_dir():
                for directory, dirs, files in os.walk(root, onerror=lambda e: errors.append(str(e))):
                    dirs[:] = sorted(name for name in dirs if not excluded(Path(directory) / name))
                    for name in sorted(files):
                        matched += bool(add(Path(directory) / name, kind))
            else:
                errors.append(f"{root}: missing or not a {'directory' if kind == 'object' else 'file/directory'}")
            if not matched and len(errors) == previous_errors:
                errors.append(f"{root}: no matching artifacts found")
    if not artifacts:
        errors.append("no matching artifacts found")
    return sorted(artifacts.items()), errors


@dataclass
class Unit:
    member: str = ""
    evidence: Optional[tuple] = None
    error: str = ""
    skipped: str = ""


def parse_elf(output, member=""):
    """Read one ELF file or archive member; never combine members' evidence."""
    references, other_symbols, sections = set(), {}, set()
    headers = symtabs = 0
    has_runtime_sections = False
    relocatable = False
    for line in output.splitlines():
        if line == "ELF Header:":
            headers += 1
        if re.match(r"\s*Type:\s+REL\b", line):
            relocatable = True
        section = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+"
                           r"\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)\s+"
                           r"[0-9a-fA-F]+\s+([A-Za-z]*)\s+\d+", line)
        if section:
            name, size, flags = section.groups()
            if name == ".symtab":
                symtabs += 1
            if int(size, 16):
                sections.add(name)
                has_runtime_sections |= bool(set(flags) & {"A", "X"})
        fields = line.split()
        if len(fields) >= 8 and re.fullmatch(r"\d+:", fields[0]):
            if fields[3] in {"FILE", "SECTION"}:
                continue
            name = fields[7].split("@", 1)[0]
            if fields[6] != "UND":
                other_symbols[name] = "definition"
            elif fields[4] == "WEAK":
                # Runtimes probe optional sanitizers through weak references.
                other_symbols.setdefault(name, "weak reference")
            else:
                references.add(name)
    if headers != 1:
        raise ValueError("expected one ELF file (non-ELF members and LLVM bitcode are unsupported)")
    if any(name.startswith(".gnu.lto_") for name in sections):
        raise ValueError("GCC LTO objects are unsupported; inspect the final linked binary")
    # Global data can need ASan, and missing sections do not mean missing code.
    # Only positively identified metadata-only Rust objects are skipped.
    if relocatable and not has_runtime_sections and sections & {".rmeta", ".rmeta-link"}:
        return Unit(member=member, skipped="Rust metadata (no runtime code or data)")
    return Unit(member=member, evidence=(references, other_symbols, sections, bool(symtabs)))


def inspect(path, kind="object"):
    result = subprocess.run(
        ["readelf", "--wide", "--file-header", "--section-headers", "--symbols", "--", str(path)],
        capture_output=True, text=True, errors="replace", timeout=60,
        env={**os.environ, "LC_ALL": "C"},
    )
    diagnostic = ""
    if result.returncode or result.stderr.strip():
        detail = " ".join(result.stderr.split()) or f"exit status {result.returncode}"
        diagnostic = f"readelf: {detail[:500]}"
    if kind != "archive":
        if diagnostic:
            return [Unit(error=diagnostic)]
        try:
            return [parse_elf(result.stdout)]
        except ValueError as error:
            return [Unit(error=str(error))]

    # GNU readelf uses (...) for regular archives and [...] for thin archives.
    # Keep the ordered chunks: archives may contain duplicate member names.
    pattern = rf"^File: {re.escape(str(path))}(?:\((.*)\)|\[(.*)\])$"
    headings = list(re.finditer(pattern, result.stdout, re.MULTILINE))
    units = []
    for index, heading in enumerate(headings):
        member = heading[1] if heading[1] is not None else heading[2]
        end = headings[index + 1].start() if index + 1 < len(headings) else len(result.stdout)
        try:
            units.append(parse_elf(result.stdout[heading.end():end], member))
        except ValueError as error:
            units.append(Unit(member=member, error=str(error)))
    # Stderr cannot reliably be assigned to a member. It can also indicate that
    # readelf stopped before visiting later members, so retain a file-level error.
    if diagnostic:
        units.append(Unit(error=f"archive inspection incomplete: {diagnostic}"))
    elif not units:
        units.append(Unit(error="no archive members found (empty archive)"))
    return units


def detect(check, evidence):
    references, other_symbols, sections, symbols_present = evidence
    symbol_pattern, section_pattern = CHECKS[check]
    for names, pattern, description in ((sections, section_pattern, "section"),
                                         (references, symbol_pattern, "reference")):
        matches = sorted(name for name in names if pattern and re.fullmatch(pattern, name))
        if matches:
            return "FOUND", f"{matches[0]} ({description})"
    matches = sorted(name for name in other_symbols if symbol_pattern and re.fullmatch(symbol_pattern, name))
    if matches:
        # The driver definition proves libFuzzer is linked. Other runtime
        # definitions alone do not prove that callers were instrumented.
        reason = other_symbols[matches[0]]
        state = "FOUND" if check == "libfuzzer" and reason == "definition" else "SYMBOL-ONLY"
        return state, f"{matches[0]} ({reason})"
    if not symbols_present:
        return "UNKNOWN", "symbol table unavailable"
    return "NOT-SEEN", "no matching evidence"


def policy_failed(mode, state):
    # Unknown or definition-only evidence cannot satisfy an enforced policy.
    return ((mode == "present" and state != "FOUND") or
            (mode == "absent" and state != "NOT-SEEN"))


def make_report(artifacts, errors, modes, config_path, overrides=()):
    # Inspect each file once. Archive members are independent check items.
    files = {"object": [], "binary": [], "archive": []}
    inspected_by_kind = dict.fromkeys(files, 0)
    member_counts = {"checked": 0, "inspected": 0, "errors": 0}
    details = []
    counts = {check: dict.fromkeys(STATES, 0) for check in CHECKS}
    failures_by_check = {check: {} for check in CHECKS}
    used_modes = {check: set() for check in CHECKS}
    failures = checked = code_items = failed_items = skipped = 0
    for path, kind in artifacts:
        name = Path(os.path.relpath(path, config_path.parent)).as_posix()
        files[kind].append(str(path.resolve()))
        details.extend(["", f"### `{name}` [{kind}]"])
        try:
            units = inspect(path, kind)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            units = [Unit(error=str(error))]
        if not any(unit.error for unit in units):
            checked += 1
            inspected_by_kind[kind] += 1
        file_failed = False
        occurrences = {}
        for unit in units:
            item = name
            if unit.member:
                member_counts["checked"] += 1
                member_counts["errors" if unit.error else "inspected"] += 1
                occurrences[unit.member] = occurrences.get(unit.member, 0) + 1
                occurrence = occurrences[unit.member]
                suffix = f" [occurrence {occurrence}]" if occurrence > 1 else ""
                item = f"{name}({unit.member}){suffix}"
                details.extend(["", f"#### `{unit.member}`{suffix}"])
            details.extend(["", "```text"])
            if unit.error:
                errors.append(f"{item}: {unit.error}")
                details.extend([f"  ERROR: {unit.error}", "```"])
                continue
            if unit.skipped:
                skipped += 1
                details.extend([f"  SKIPPED: {unit.skipped}", "```"])
                continue
            code_items += 1
            item_modes = effective_modes(name, unit.member, modes, overrides)
            item_failed = False
            for check in CHECKS:
                mode = item_modes.get(check, "ignore")
                used_modes[check].add(mode)
                state, reason = detect(check, unit.evidence)
                counts[check][state] += 1
                mismatch = policy_failed(mode, state)
                suffix = f"; FAIL (expected {mode})" if mismatch else ""
                details.append(f"  {check:18} {state:11} {reason}{suffix}")
                if not mismatch:
                    continue
                item_failed = True
                if state == "NOT-SEEN":
                    detail = "not seen"
                elif state == "FOUND":
                    detail = f"found: {reason}"
                else:
                    detail = f"inconclusive: {reason}"
                entries = failures_by_check[check]
                if name in entries:
                    count, first = entries[name]
                    entries[name] = count + 1, first
                else:
                    entries[name] = 1, f"{item}: {detail}; expected {mode}"
            details.append("```")
            failed_items += item_failed
            file_failed |= item_failed
        failures += file_failed
    expectations = {}
    enforced = []
    for check in CHECKS:
        values = used_modes[check] or {modes.get(check, "ignore")}
        expectations[check] = next(iter(values)) if len(values) == 1 else "varies"
        if values != {"ignore"}:
            enforced.append(check)
    report = [
        "# Build artifact report", "",
        f"Config: {config_path}",
        f"Paths relative to: {config_path.parent}",
        f"Files checked: {len(artifacts)}; inspected: {checked}; files failing expectations: {failures}; errors: {len(errors)}",
        f"Check items: {code_items}; failing expectations: {failed_items}; metadata items skipped: {skipped}",
        "Evidence checks only; inconclusive results fail either expectation.",
        "Archive members are checked separately; Rust metadata-only items are listed as skipped.",
        "Inventory paths are absolute.",
        "", "## Failure counts", "",
        "| Check              | Expected | Failed files                     | Failed items |",
        "| ------------------ | -------- | -------------------------------- | ------------ |",
    ]
    for check in CHECKS:
        total = f"[{len(failures_by_check[check])}](#{check})" if check in enforced else "-"
        items = str(sum(count for count, _ in failures_by_check[check].values())) if check in enforced else "-"
        report.append(f"| {check:18} | {expectations[check]:8} | {total:32} | {items:>12} |")
    report.extend(["", "An item is an object, binary, or individual archive member, excluding Rust metadata-only items.",
                   "Archives with multiple failures have one summary line; every member result appears under File details.",
                    "Ignored checks have no failure count. 'varies' means path rules set different expectations.",
                    "", "## File counts", "",
                    "| Type           | Checked | Inspected | Errors |",
                    "| -------------- | ------- | --------- | ------ |"])
    for kind, paths in files.items():
        inspected = inspected_by_kind[kind]
        report.append(f"| {kind:14} | {len(paths):7} | {inspected:9} | {len(paths) - inspected:6} |")
    report.append(f"| archive member | {member_counts['checked']:7} | {member_counts['inspected']:9} | {member_counts['errors']:6} |")
    report.extend(["", "The archive member row counts members read within archives; it is not an additional file total.",
                    "", "## Failures", ""])
    if not enforced:
        report.append("No expectations configured for the checked items.")
    for check in enforced:
        groups = failures_by_check[check]
        total = sum(count for count, _ in groups.values())
        entries = [first if count == 1 else f"{name}: {count} member failures; see File details"
                   for name, (count, first) in groups.items()]
        noun = "failure" if total == 1 else "failures"
        # Keep heading links stable when expectations or failure counts change.
        report.extend(["", f"### {check}", "",
                        f"Expected {expectations[check]}: {total} {noun}", ""])
        report.extend(["```text", *entries, "```"] if entries else ["None"])
    report.extend(["", f"## Inspection errors ({len(errors)})", ""])
    report.extend(["```text", *errors, "```"] if errors else ["None"])
    for kind, title in (("object", "Objects"), ("binary", "Binaries"), ("archive", "Archives")):
        report.extend(["", f"## {title} ({len(files[kind])})", "",
                        "```text", *files[kind], "```"])
    report.extend(["", "## Evidence key", "", "```text",
                "FOUND = strong reference or nonempty instrumentation section (libfuzzer: driver symbol).",
                "SYMBOL-ONLY = definition or optional weak reference; instrumentation use is unproven.",
                "NOT-SEEN = no evidence in available tables; compiler options and symbol completeness are unproven.",
                "UNKNOWN = symbol table unavailable, usually due to stripping.",
                "SKIPPED = identified Rust metadata with no runtime code or data.",
                "```", "", "## Check summary", "", "```text"])
    for check in CHECKS:
        totals = ", ".join(f"{state}={counts[check][state]}" for state in STATES)
        report.append(f"  {check} (expectation: {expectations[check]}): {totals}")
    report.extend(["```", "", "## File details"] + details)
    return "\n".join(report) + "\n", failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", nargs="?", type=Path,
                        default=Path(__file__).with_name("check-build.ini"),
                        help="INI config (default: check-build.ini beside this script)")
    args = parser.parse_args()
    try:
        config_path = args.config.resolve()
        objects, binaries, excludes, modes, overrides, report_path = load_config(config_path)
        if not shutil.which("readelf"):
            raise ValueError("readelf is required (install GNU binutils)")
        artifacts, errors = discover(objects, binaries, excludes, config_path.parent)
        configured_report = report_path
        report_path = report_path.resolve()
        inputs = ({path for path, _ in artifacts} | {path.resolve() for path in binaries} |
                  {config_path, Path(__file__).resolve()})
        # An artifact name remains protected even when it is a symlink.
        for output_path in (configured_report, report_path):
            if output_path.suffix in {".o", ".obj", ".lo", ".ko", ".a", ".rlib", ".bc"} or re.search(r"\.so(?:\..*)?$", output_path.name):
                raise ValueError("output paths must not use object, archive, or shared-library filenames")
        if report_path in inputs or any(report_path.exists() and path.exists() and
                                       report_path.samefile(path) for path in inputs):
            raise ValueError("output path must not overwrite an input artifact, config, or checker")
        if report_path.exists():
            output_stat = report_path.stat()
            if not stat.S_ISREG(output_stat.st_mode):
                raise ValueError("output path must be a regular file")
            if output_stat.st_nlink > 1:
                raise ValueError("output path must not be hardlinked to another file")
            with report_path.open("rb") as source:
                magic = source.read(8)
            if magic.startswith((b"\x7fELF", b"!<arch>\n", b"!<thin>\n", b"BC\xc0\xde", b"\xde\xc0\x17\x0b")):
                raise ValueError("output path must not overwrite an artifact, even if excluded")
        report, failures = make_report(artifacts, errors, modes, config_path, overrides)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report, encoding="utf-8")
        print(f"Report: {report_path} ({len(artifacts)} artifacts, {failures} policy failures, {len(errors)} errors)")
        return 2 if errors else 1 if failures else 0
    except (OSError, ValueError, configparser.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
