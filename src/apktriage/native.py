"""Stage 3: native ARM ``.so`` triage with LIEF.

For each ``lib/<abi>/*.so`` we parse the ELF, record the architecture (arm64-v8a
/ armeabi-v7a are the common Android targets), and flag imported symbols that
are classic tells of anti-analysis or shell-out behaviour. We also sweep the
library's printable strings so the secret/indicator scanners see native data,
not just DEX strings, since packed apps hide their logic in native code.
"""

from __future__ import annotations

import re

import lief

from apktriage.logging import get_logger
from apktriage.models import Finding, Severity

log = get_logger(__name__)

# Imported libc/syscall symbols that warrant a closer look in a mobile binary.
SUSPICIOUS_IMPORTS: dict[str, tuple[str, Severity]] = {
    "ptrace": ("anti-debug (ptrace)", Severity.MEDIUM),
    "system": ("shell command execution (system)", Severity.HIGH),
    "exec": ("process execution (exec*)", Severity.MEDIUM),
    "execve": ("process execution (execve)", Severity.HIGH),
    "popen": ("shell pipe (popen)", Severity.HIGH),
    "dlopen": ("dynamic library loading (dlopen)", Severity.MEDIUM),
    "fork": ("process fork", Severity.LOW),
    "inotify_init": ("filesystem watching (inotify)", Severity.LOW),
}

_STRINGS_RE = re.compile(rb"[\x20-\x7e]{5,}")


def _strings(data: bytes, limit: int = 50000) -> list[str]:
    return [m.decode("ascii", "ignore") for m in _STRINGS_RE.findall(data)[:limit]]


def analyze_lib(name: str, data: bytes) -> tuple[list[Finding], list[str]]:
    """Return (findings, extracted_strings) for one native library."""
    findings: list[Finding] = []
    binary = lief.ELF.parse(list(data))
    if binary is None:
        log.warning("could not parse ELF", lib=name)
        return findings, _strings(data)

    arch = str(getattr(binary.header, "machine_type", "unknown")).split(".")[-1]
    findings.append(
        Finding(
            category="native_lib",
            title=f"Native library: {name.rsplit('/', 1)[-1]} ({arch})",
            severity=Severity.INFO,
            location=name,
            evidence=arch,
        )
    )

    imported = {sym.name for sym in binary.imported_functions}
    for symbol, (why, severity) in SUSPICIOUS_IMPORTS.items():
        if symbol in imported:
            findings.append(
                Finding(
                    category="native_import",
                    title=f"Native import: {symbol}",
                    severity=severity,
                    detail=why,
                    location=name,
                    evidence=symbol,
                )
            )

    return findings, _strings(data)


def run(libs: dict[str, bytes]) -> tuple[list[Finding], dict[str, list[str]]]:
    """Analyze every native lib; return findings and per-lib extracted strings."""
    findings: list[Finding] = []
    strings_by_lib: dict[str, list[str]] = {}
    for name, data in libs.items():
        lib_findings, lib_strings = analyze_lib(name, data)
        findings.extend(lib_findings)
        strings_by_lib[name] = lib_strings
    return findings, strings_by_lib
