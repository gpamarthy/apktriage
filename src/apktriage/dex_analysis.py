"""Stage 2: DEX-level triage via androguard cross-references.

We never regex the bytecode for behaviour. Instead we ask androguard's
``Analysis`` for methods matching well-known sensitive APIs and keep only the
ones the app actually *calls* (non-empty xref-from). That distinguishes "the
SMS class exists in the framework" from "this app invokes sendTextMessage",
which is the difference that matters in triage.
"""

from __future__ import annotations

from typing import Any

from apktriage.logging import get_logger
from apktriage.models import Finding, Severity

log = get_logger(__name__)

# Android "dangerous" permission protection level (the ones worth flagging).
DANGEROUS_PERMISSIONS = {
    "READ_SMS",
    "RECEIVE_SMS",
    "SEND_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
    "READ_PHONE_STATE",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "CALL_PHONE",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE",
    "GET_ACCOUNTS",
}

# Permission pairs whose combination is a classic exfil / spyware tell.
SUSPICIOUS_COMBOS: list[tuple[str, str, str]] = [
    ("READ_SMS", "INTERNET", "Reads SMS and has network access (SMS exfiltration)"),
    ("RECORD_AUDIO", "INTERNET", "Records audio and has network access (surveillance)"),
    ("READ_CONTACTS", "INTERNET", "Harvests contacts and has network access"),
    ("ACCESS_FINE_LOCATION", "INTERNET", "Tracks location and has network access"),
    ("BIND_ACCESSIBILITY_SERVICE", "INTERNET", "Accessibility abuse with network access"),
]

# Sensitive API surface: (class regex, method regex, category, title, severity).
SUSPICIOUS_APIS: list[tuple[str, str, str, str, Severity]] = [
    (
        r".*DexClassLoader.*",
        "<init>",
        "dynamic_code",
        "DexClassLoader (loads external DEX)",
        Severity.HIGH,
    ),
    (
        r".*PathClassLoader.*",
        "<init>",
        "dynamic_code",
        "PathClassLoader (loads code paths)",
        Severity.MEDIUM,
    ),
    (
        r"Ljava/lang/System;",
        "load(Library)?",
        "dynamic_code",
        "Loads a native library",
        Severity.LOW,
    ),
    (r"Ljava/lang/Runtime;", "exec", "dynamic_code", "Runtime.exec (shell command)", Severity.HIGH),
    (
        r".*ProcessBuilder.*",
        "start",
        "dynamic_code",
        "ProcessBuilder.start (spawns process)",
        Severity.MEDIUM,
    ),
    (r"Ljava/lang/reflect/.*", ".*", "reflection", "Java reflection", Severity.LOW),
    (r"Ljavax/crypto/.*", ".*", "crypto", "Uses javax.crypto", Severity.LOW),
    (
        r".*TelephonyManager.*",
        "getDeviceId|getSubscriberId|getSimSerialNumber",
        "discovery",
        "Reads device/SIM identifiers",
        Severity.MEDIUM,
    ),
    (
        r".*SmsManager.*",
        "sendTextMessage|sendMultipartTextMessage",
        "sms",
        "Sends SMS programmatically",
        Severity.HIGH,
    ),
    (
        r".*PackageManager.*",
        "getInstalledPackages|getInstalledApplications",
        "discovery",
        "Enumerates installed apps",
        Severity.LOW,
    ),
]


def _perm_short(perm: str) -> str:
    return perm.rsplit(".", 1)[-1]


def safe_permissions(apk: Any) -> set[str]:
    """Short permission names, or empty set if the manifest was unparseable."""
    if apk is None:
        return set()
    try:
        return {_perm_short(p) for p in apk.get_permissions()}
    except Exception:
        return set()


def analyze_permissions(apk: Any) -> list[Finding]:
    findings: list[Finding] = []
    perms = safe_permissions(apk)
    for perm in sorted(perms & DANGEROUS_PERMISSIONS):
        findings.append(
            Finding(
                category="permission",
                title=f"Dangerous permission: {perm}",
                severity=Severity.LOW,
                location="AndroidManifest.xml",
                evidence=perm,
            )
        )
    for a, b, why in SUSPICIOUS_COMBOS:
        if a in perms and b in perms:
            findings.append(
                Finding(
                    category="permission",
                    title=f"Suspicious permission combo: {a} + {b}",
                    severity=Severity.MEDIUM,
                    detail=why,
                    location="AndroidManifest.xml",
                    evidence=f"{a},{b}",
                )
            )
    return findings


def analyze_components(apk: Any) -> list[Finding]:
    """Flag exported components, a common attack surface for other apps."""
    findings: list[Finding] = []
    if apk is None:
        return findings
    getters = (
        ("activity", apk.get_activities),
        ("service", apk.get_services),
        ("receiver", apk.get_receivers),
        ("provider", apk.get_providers),
    )
    for kind, getter in getters:
        try:
            components = list(getter())
        except Exception:
            continue
        for comp in components:
            try:
                exported = apk.get_element("activity", "exported", name=comp)
            except Exception:
                exported = None
            if str(exported).lower() == "true":
                findings.append(
                    Finding(
                        category="component",
                        title=f"Exported {kind}: {comp.rsplit('.', 1)[-1]}",
                        severity=Severity.LOW,
                        location="AndroidManifest.xml",
                        evidence=comp,
                    )
                )
    return findings


def analyze_apis(analysis: Any) -> list[Finding]:
    findings: list[Finding] = []
    for class_re, method_re, category, title, severity in SUSPICIOUS_APIS:
        try:
            matches = list(analysis.find_methods(classname=class_re, methodname=method_re))
        except Exception:
            continue
        callers: set[str] = set()
        for m in matches:
            for _, caller, _ in m.get_xref_from():
                callers.add(f"{caller.class_name}->{caller.name}")
        if callers:
            findings.append(
                Finding(
                    category=category,
                    title=title,
                    severity=severity,
                    detail=f"Called from {len(callers)} site(s)",
                    location=sorted(callers)[0],
                    evidence=f"{class_re}->{method_re}",
                )
            )
    return findings


def run(apk: Any, analysis: Any) -> list[Finding]:
    return [
        *analyze_permissions(apk),
        *analyze_components(apk),
        *analyze_apis(analysis),
    ]
