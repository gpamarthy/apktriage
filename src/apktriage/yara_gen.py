"""Stage 7: synthesize a YARA rule from the high-confidence findings.

We turn the strongest, most distinctive observations (hardcoded secrets, C2
URLs/IPs, packer names) into YARA string conditions so the sample can be hunted
across a corpus. The generated rule is compiled with yara-python before it is
returned; if it does not compile we raise, because shipping a broken signature
is worse than shipping none.
"""

from __future__ import annotations

import re

import yara

from apktriage.logging import get_logger
from apktriage.models import Indicator, Report

log = get_logger(__name__)

_MAX_STRINGS = 20


def _ident(value: str) -> str:
    """A safe YARA rule identifier derived from the package name."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value) or "sample"
    if cleaned[0].isdigit():
        cleaned = f"r_{cleaned}"
    return f"apktriage_{cleaned}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _collect_strings(report: Report) -> list[tuple[str, str]]:
    """Return (yara_var, literal) pairs from the most distinctive evidence."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(prefix: str, value: str) -> None:
        value = value.strip()
        if len(value) < 6 or value in seen or len(out) >= _MAX_STRINGS:
            return
        seen.add(value)
        out.append((f"${prefix}{len(out)}", value))

    for ind in report.indicators:
        if ind.kind in {"url", "ipv4"}:
            add("net", ind.value)
    for f in report.findings:
        if f.category == "secret" and "..." not in f.evidence:
            add("sec", f.evidence)
    for p in report.packers:
        if p.category in {"packer", "obfuscator"}:
            add("pkr", p.name)
    return out


def build(report: Report, indicators: list[Indicator] | None = None) -> str:
    if indicators is not None:
        report.indicators = indicators
    strings = _collect_strings(report)
    rule_name = _ident(report.package or report.sha256[:12])

    if strings:
        string_lines = "\n".join(f'        {var} = "{_escape(lit)}"' for var, lit in strings)
        strings_block = f"    strings:\n{string_lines}\n"
        # Anchor on the ZIP/APK magic plus a couple of distinctive strings.
        condition = f"        uint32(0) == 0x04034b50 and {min(2, len(strings))} of them"
    else:
        strings_block = ""
        condition = "        uint32(0) == 0x04034b50  // PK zip magic; no distinctive strings found"

    rule = (
        f"rule {rule_name}\n"
        "{\n"
        "    meta:\n"
        '        author = "apktriage"\n'
        '        description = "Auto-generated triage signature"\n'
        f'        sha256 = "{report.sha256}"\n'
        f'        package = "{_escape(report.package)}"\n'
        f"{strings_block}"
        "    condition:\n"
        f"{condition}\n"
        "}\n"
    )

    # Fail loudly on a broken signature rather than writing it out.
    yara.compile(source=rule)
    log.info("generated yara rule", name=rule_name, strings=len(strings))
    return rule
