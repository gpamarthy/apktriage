"""Typed, JSON-serializable result objects shared by every pipeline stage.

Keeping these as plain dataclasses (not pydantic) makes the data flow obvious
in an interview walk-through: every stage takes the APK context and returns a
list of ``Finding`` / ``Indicator`` objects that the report renderer consumes.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Coarse triage severity. ``StrEnum`` makes it JSON-serializable as-is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 3, "high": 6, "critical": 10}[self.value]


@dataclass
class Finding:
    """A single observation produced by a stage (secret, suspicious API, etc.)."""

    category: str  # e.g. "secret", "permission", "native_import", "dynamic_code"
    title: str
    severity: Severity
    detail: str = ""
    location: str = ""  # file / class / lib the evidence came from
    evidence: str = ""  # the matched string or symbol (redacted-safe excerpt)
    attack_ids: list[str] = field(default_factory=list)  # MITRE ATT&CK Mobile technique ids


@dataclass
class Indicator:
    """A network / crypto IOC suitable for a YARA string or a threat-intel feed."""

    kind: str  # "url", "ipv4", "domain", "base64_blob", "crypto"
    value: str
    location: str = ""


@dataclass
class PackerVerdict:
    """One APKiD detection (packer, obfuscator, anti-debug, compiler, ...)."""

    category: str
    name: str


@dataclass
class AttackTechnique:
    """A mapped MITRE ATT&CK Mobile technique plus the evidence that triggered it."""

    technique_id: str
    name: str
    tactic: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Report:
    """The full triage result for one APK. Serialized verbatim to report.json."""

    apk_path: str
    sha256: str
    package: str = ""
    version_name: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    tools_used: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    packers: list[PackerVerdict] = field(default_factory=list)
    techniques: list[AttackTechnique] = field(default_factory=list)
    yara_rule: str = ""

    @property
    def risk_score(self) -> int:
        """Sum of finding severity weights, clamped to 0-100 for a quick gauge."""
        return min(100, sum(f.severity.weight for f in self.findings))

    def to_dict(self) -> dict[str, Any]:
        # asdict() omits properties; surface risk_score so JSON consumers get it.
        data = dataclasses.asdict(self)
        data["risk_score"] = self.risk_score
        return data
