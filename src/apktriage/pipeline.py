"""Orchestrates the triage stages into a single ``Report``.

The flow mirrors the documented Android static-analysis methodology:
load -> DEX behaviour -> native libs -> packers -> secrets -> C2 indicators ->
YARA -> ATT&CK. Each stage is a small pure function over the shared context, so
the pipeline reads top-to-bottom like the methodology it implements.
"""

from __future__ import annotations

from pathlib import Path

from apktriage import attack_map, dex_analysis, indicators, native, packers, secrets, yara_gen
from apktriage.logging import get_logger
from apktriage.models import Report
from apktriage.unpack import ApkContext, load

log = get_logger(__name__)

# Cap how much decompiled text we read per file so a huge app cannot blow memory.
_MAX_FILE_BYTES = 2_000_000


def _safe(apk: object, method: str) -> str:
    """Call an androguard manifest getter, tolerating None / parser errors."""
    if apk is None:
        return ""
    try:
        return str(getattr(apk, method)() or "")
    except Exception:
        return ""


def _text_sources(ctx: ApkContext, native_strings: dict[str, list[str]]) -> dict[str, list[str]]:
    """Assemble every text corpus the string scanners should sweep."""
    sources: dict[str, list[str]] = {"dex:strings": ctx.dex_strings()}
    for name, strings in native_strings.items():
        sources[name] = strings
    for path in ctx.source_files():
        if path.suffix.lower() not in {".smali", ".java", ".kt", ".xml", ".json", ".txt"}:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(ctx.outdir)) if ctx.outdir in path.parents else path.name
        sources[rel] = text.splitlines()
    return sources


def run(apk_path: Path, outdir: Path, *, use_external: bool = True) -> Report:
    ctx = load(apk_path, outdir, use_external=use_external)
    apk = ctx.apk

    report = Report(
        apk_path=str(apk_path),
        sha256=ctx.sha256,
        package=_safe(apk, "get_package"),
        version_name=_safe(apk, "get_androidversion_name"),
        min_sdk=_safe(apk, "get_min_sdk_version"),
        target_sdk=_safe(apk, "get_target_sdk_version"),
        tools_used=ctx.tools_used,
    )

    # Stage 2: DEX behaviour.
    report.findings.extend(dex_analysis.run(apk, ctx.analysis))

    # Stage 3: native libraries.
    native_findings, native_strings = native.run(ctx.native_libs())
    report.findings.extend(native_findings)

    # Stage 4: packers / obfuscators (APKiD is an external binary, so it is
    # also skipped under --no-external alongside apktool/jadx).
    if use_external:
        verdicts, packer_findings = packers.scan(str(apk_path))
        report.packers.extend(verdicts)
        if verdicts:
            report.tools_used.append("apkid")
        report.findings.extend(packer_findings)

    # Stages 5-6: secrets and C2 indicators over every text corpus.
    sources = _text_sources(ctx, native_strings)
    report.findings.extend(secrets.run(sources))
    inds, c2_findings = indicators.run(sources)
    report.indicators.extend(inds)
    report.findings.extend(c2_findings)

    # Stage 8: ATT&CK mapping (annotates findings in place).
    permissions = dex_analysis.safe_permissions(apk)
    report.techniques.extend(attack_map.run(permissions, report.findings))

    # Stage 7: YARA from the assembled high-confidence evidence.
    report.yara_rule = yara_gen.build(report)

    log.info(
        "triage complete",
        findings=len(report.findings),
        indicators=len(report.indicators),
        techniques=len(report.techniques),
        risk=report.risk_score,
    )
    return report
