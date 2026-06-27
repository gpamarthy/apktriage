"""Stage 1: load the APK and (optionally) dump decompiled source.

androguard does the heavy lifting in pure Python: it parses the APK container,
the binary manifest, and every DEX into an ``Analysis`` object that exposes
cross-references over classes/methods/strings. apktool and Jadx are *optional*
enhancers, auto-detected on ``PATH``; when present we shell out (read-only, with
a timeout, never executing the sample) to dump smali and Java source that the
secret/indicator string scanners then sweep. When absent, we fall back to the
DEX string pool androguard already gives us, so the tool still works offline.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from apktriage.logging import get_logger

log = get_logger(__name__)

# Hard cap so a malformed / hostile archive can never hang the pipeline.
_TOOL_TIMEOUT_S = 300


@dataclass
class ApkContext:
    """Everything the later stages need, gathered once up front."""

    apk_path: Path
    sha256: str
    outdir: Path
    apk: Any  # androguard.core.apk.APK, or None if the manifest was unparseable
    analysis: Any  # androguard.core.analysis.analysis.Analysis
    dvms: list[Any] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    smali_dir: Path | None = None
    java_dir: Path | None = None

    def source_files(self) -> list[Path]:
        """Decompiled text files (smali + Java) available for string scanning."""
        files: list[Path] = []
        for d in (self.smali_dir, self.java_dir):
            if d and d.is_dir():
                files.extend(p for p in d.rglob("*") if p.is_file())
        return files

    def dex_strings(self) -> list[str]:
        """String pool across every DEX (androguard's native view)."""
        out: list[str] = []
        for dvm in self.dvms:
            try:
                out.extend(str(s) for s in dvm.get_strings())
            except Exception:
                continue
        return out

    def native_libs(self) -> dict[str, bytes]:
        """``lib/<abi>/<name>.so`` entries mapped to their raw bytes.

        Read straight from the APK zip (not via androguard) so this works even
        when the manifest is malformed and the androguard ``APK`` object is None.
        """
        libs: dict[str, bytes] = {}
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                for name in zf.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        try:
                            libs[name] = zf.read(name)
                        except (OSError, zipfile.BadZipFile, KeyError):
                            continue
        except (OSError, zipfile.BadZipFile):
            return {}
        return libs


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_tool(cmd: list[str], cwd: Path | None = None) -> bool:
    try:
        subprocess.run(
            cmd,
            cwd=cwd,
            timeout=_TOOL_TIMEOUT_S,
            capture_output=True,
            check=True,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("optional tool failed", cmd=cmd[0], error=str(exc))
        return False
    return True


def load(apk_path: Path, outdir: Path, *, use_external: bool = True) -> ApkContext:
    """Parse ``apk_path`` with androguard and optionally dump smali/Java.

    Real-world (often malicious) APKs ship deliberately malformed manifests that
    crash androguard's binary-XML parser. We try the convenient full load first,
    then fall back to a DEX-only load read straight from the zip so the rest of
    the pipeline still runs (we just lose manifest-derived data like permissions).
    """
    outdir.mkdir(parents=True, exist_ok=True)
    sha = _sha256(apk_path)
    log.info("loading apk", path=str(apk_path), sha256=sha[:16])

    apk, dvms, analysis = _load_androguard(apk_path)
    ctx = ApkContext(
        apk_path=apk_path,
        sha256=sha,
        outdir=outdir,
        apk=apk,
        analysis=analysis,
        dvms=list(dvms),
        tools_used=["androguard"],
    )

    if use_external:
        _dump_smali(ctx)
        _dump_java(ctx)
    return ctx


def _load_androguard(apk_path: Path) -> tuple[Any, list[Any], Any]:
    from androguard.misc import AnalyzeAPK

    try:
        apk, dvms, analysis = AnalyzeAPK(str(apk_path))
        return apk, list(dvms), analysis
    except Exception as exc:
        log.warning("AnalyzeAPK failed; falling back to dex-only load", error=str(exc))
        return _load_dex_only(apk_path)


def _load_dex_only(apk_path: Path) -> tuple[Any, list[Any], Any]:
    """Build the DEX Analysis directly from the zip, tolerating a bad manifest."""
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    apk: Any = None
    try:  # the manifest may still be unparseable; that is fine, perms just go empty
        apk = APK(str(apk_path))
    except Exception:
        apk = None

    analysis = Analysis()
    dvms: list[Any] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_names = sorted(
                n for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex")
            )
            for name in dex_names:
                try:
                    dvm = DEX(zf.read(name))
                    dvms.append(dvm)
                    analysis.add(dvm)
                except Exception:
                    continue
    except (OSError, zipfile.BadZipFile) as exc:
        log.warning("could not read APK as zip", error=str(exc))

    if dvms:
        try:
            analysis.create_xref()
        except Exception:
            log.warning("xref build failed; api detection may be reduced")
    return apk, dvms, analysis


def _dump_smali(ctx: ApkContext) -> None:
    apktool = shutil.which("apktool")
    if not apktool:
        log.debug("apktool not found, skipping smali dump")
        return
    dest = ctx.outdir / "apktool"
    if _run_tool([apktool, "d", "-f", "-o", str(dest), str(ctx.apk_path)]):
        ctx.smali_dir = dest
        ctx.tools_used.append("apktool")


def _dump_java(ctx: ApkContext) -> None:
    jadx = shutil.which("jadx")
    if not jadx:
        log.debug("jadx not found, skipping java dump")
        return
    dest = ctx.outdir / "jadx"
    if _run_tool([jadx, "-d", str(dest), "--no-res", str(ctx.apk_path)]):
        ctx.java_dir = dest / "sources"
        ctx.tools_used.append("jadx")
