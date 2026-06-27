"""Stage 5: hardcoded-secret extraction.

A curated set of well-known credential regexes (the same families MobSF,
trufflehog and gitleaks ship) is applied across every text source we have:
decompiled smali/Java, the DEX string pool, and native-library strings. For the
loose generic patterns we add a Shannon-entropy gate so ``api_key="REPLACE_ME"``
placeholders do not drown out real keys.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

from apktriage.models import Finding, Severity

_ENTROPY_MIN = 3.2  # bits/char; random base64/hex sits ~4.5+, English prose ~2.5


@dataclass
class Pattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    entropy: bool


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@lru_cache(maxsize=1)
def load_patterns() -> tuple[Pattern, ...]:
    raw = resources.files("apktriage.data").joinpath("secret_patterns.yml").read_text()
    out: list[Pattern] = []
    for entry in yaml.safe_load(raw):
        out.append(
            Pattern(
                name=entry["name"],
                regex=re.compile(entry["regex"]),
                severity=Severity(entry["severity"]),
                entropy=bool(entry.get("entropy", False)),
            )
        )
    return tuple(out)


def scan_text(text: str, location: str, patterns: tuple[Pattern, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for pat in patterns:
        for match in pat.regex.finditer(text):
            value = match.group(0)
            if pat.entropy and shannon_entropy(value) < _ENTROPY_MIN:
                continue
            findings.append(
                Finding(
                    category="secret",
                    title=f"Hardcoded secret: {pat.name}",
                    severity=pat.severity,
                    location=location,
                    evidence=_redact(value),
                )
            )
    return findings


def _redact(value: str) -> str:
    """Keep enough to recognize the secret without printing it in full."""
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]} (len={len(value)})"


def run(sources: dict[str, list[str]]) -> list[Finding]:
    """``sources`` maps a location label to its lines/strings to scan."""
    patterns = load_patterns()
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for location, lines in sources.items():
        for finding in scan_text("\n".join(lines), location, patterns):
            key = (finding.title, finding.evidence)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return findings
