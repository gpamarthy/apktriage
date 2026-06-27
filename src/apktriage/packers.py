"""Stage 4: packer / obfuscator / compiler detection via APKiD.

APKiD is "PEiD for Android": a YARA-backed identifier for packers, obfuscators,
anti-debug tricks and the compiler that built the DEX. We invoke its CLI in JSON
mode (read-only, never executing the sample) and normalize the matches into
``PackerVerdict`` rows. The dependency is optional, so a missing APKiD degrades
to an empty list rather than failing the run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from apktriage.logging import get_logger
from apktriage.models import Finding, PackerVerdict, Severity

log = get_logger(__name__)

_TIMEOUT_S = 180


def _find_apkid() -> str | None:
    """APKiD installs a console script next to the interpreter; check there too
    so detection works when apktriage is imported as a library, not just when
    the venv's bin is on ``PATH``."""
    found = shutil.which("apkid")
    if found:
        return found
    candidate = Path(sys.executable).parent / "apkid"
    return str(candidate) if candidate.exists() else None


# APKiD match categories that should raise a finding (compiler is informational).
_INTERESTING = {"packer", "obfuscator", "anti_vm", "anti_debug", "anti_disassembly", "manipulator"}


def _severity_for(category: str) -> Severity:
    return Severity.HIGH if category in {"packer", "anti_debug", "anti_vm"} else Severity.MEDIUM


def scan(apk_path: str) -> tuple[list[PackerVerdict], list[Finding]]:
    apkid = _find_apkid()
    if not apkid:
        log.debug("apkid not installed, skipping packer detection")
        return [], []

    try:
        proc = subprocess.run(
            [apkid, "-j", apk_path],
            timeout=_TIMEOUT_S,
            capture_output=True,
            text=True,
            check=False,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError) as exc:
        log.warning("apkid failed", error=str(exc))
        return [], []

    verdicts: list[PackerVerdict] = []
    findings: list[Finding] = []
    for file_entry in data.get("files", []):
        for category, names in file_entry.get("matches", {}).items():
            for name in names:
                verdicts.append(PackerVerdict(category=category, name=name))
                if category in _INTERESTING:
                    findings.append(
                        Finding(
                            category="packer" if category == "packer" else "obfuscation",
                            title=f"{category.replace('_', ' ').title()}: {name}",
                            severity=_severity_for(category),
                            location=file_entry.get("filename", apk_path),
                            evidence=name,
                        )
                    )
    return verdicts, findings
