"""Validation against real APKs (benign F-Droid + real malware).

Opt-in and network-fetched: marked ``corpus`` so the default suite stays offline
and deterministic. Run with ``make corpus`` (fetch + ``pytest -m corpus``). A
sample whose file has not been downloaded is skipped, so the suite never fails
just because the corpus is absent.

Each sample is scanned in its **own subprocess** via the real ``apktriage`` CLI.
That mirrors production (one process per APK) and isolates the samples: a native
crash in a C dependency (lief/yara/androguard) on one hostile input fails only
that sample instead of taking down the whole run. It also exercises the actual
CLI entrypoint end-to-end.

Two layers:
  A. invariants  - every sample: the scan exits cleanly and emits a coherent,
                   JSON-serializable report whose YARA rule compiles.
  B. ground truth - per-sample manifest expectations hold (benign apps parse
                   their native libs; malware trips behavioural/ATT&CK signals).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yara
from conftest import corpus_sample_path, load_corpus_samples

from apktriage import packers

pytestmark = pytest.mark.corpus

_SAMPLES = load_corpus_samples()
_IDS = [s["name"] for s in _SAMPLES]
_SCAN_TIMEOUT = 300


def _scan(name: str, out_dir: Path) -> dict[str, Any]:
    """Run the real CLI on one sample in a subprocess; return the JSON report."""
    apk = corpus_sample_path(name)
    if not apk.exists():
        pytest.skip(f"{name} not fetched; run `python tests/corpus/fetch.py`")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "apktriage.cli",
            "scan",
            str(apk),
            "-o",
            str(out_dir / name),
            "--no-external",
            "-f",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=_SCAN_TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, (
        f"{name}: scan exited {proc.returncode} (negative = native crash)\n{proc.stderr[-1500:]}"
    )
    return dict(json.loads(proc.stdout))


@pytest.fixture(scope="module")
def reports(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    """Scan each present sample once (isolated subprocess) and cache the report."""
    base = tmp_path_factory.mktemp("corpus_out")
    cache: dict[str, dict[str, Any]] = {}
    for sample in _SAMPLES:
        if corpus_sample_path(sample["name"]).exists():
            cache[sample["name"]] = _scan(sample["name"], base)
    return cache


@pytest.mark.parametrize("sample", _SAMPLES, ids=_IDS)
def test_invariants(sample: dict, reports: dict[str, dict[str, Any]]) -> None:
    name = sample["name"]
    if name not in reports:
        pytest.skip(f"{name} not fetched")
    report = reports[name]

    assert 0 <= report["risk_score"] <= 100
    json.dumps(report)  # already parsed from JSON, but assert round-trips
    assert yara.compile(source=report["yara_rule"]) is not None
    for f in report["findings"]:
        assert f["title"]
        assert f["category"]
        assert f["severity"]


@pytest.mark.parametrize("sample", _SAMPLES, ids=_IDS)
def test_expectations(sample: dict, reports: dict[str, dict[str, Any]]) -> None:
    name = sample["name"]
    if name not in reports:
        pytest.skip(f"{name} not fetched")
    report = reports[name]
    expect = sample.get("expect", {})
    cats = {f["category"] for f in report["findings"]}

    if "min_findings" in expect:
        assert len(report["findings"]) >= expect["min_findings"], f"{name}: too few findings"
    for cat in expect.get("require_categories", []):
        assert cat in cats, f"{name}: expected a '{cat}' finding, got {sorted(cats)}"
    any_cats = expect.get("any_categories")
    if any_cats:
        assert cats & set(any_cats), f"{name}: none of {any_cats} present, got {sorted(cats)}"
    if "min_attack" in expect:
        assert len(report["techniques"]) >= expect["min_attack"], f"{name}: too few techniques"
    if "max_risk" in expect:
        assert report["risk_score"] <= expect["max_risk"], f"{name}: risk too high"


_APKID_SAMPLES = [s for s in _SAMPLES if s.get("expect", {}).get("apkid")]
_APKID_IDS = [s["name"] for s in _APKID_SAMPLES]


@pytest.mark.parametrize("sample", _APKID_SAMPLES, ids=_APKID_IDS)
def test_packer_detection(sample: dict) -> None:
    """APKiD detects the real packer/obfuscator/anti-vm on known-protected malware.

    Runs the packer stage directly (APKiD shells out per-process) so it works
    regardless of the --no-external pipeline path used elsewhere.
    """
    if packers._find_apkid() is None:
        pytest.skip("apkid not installed (install the [packers] extra)")
    apk = corpus_sample_path(sample["name"])
    if not apk.exists():
        pytest.skip(f"{sample['name']} not fetched")

    verdicts, _findings = packers.scan(str(apk))
    seen = {(v.category, v.name) for v in verdicts}
    for want in sample["expect"]["apkid"]:
        assert (want["category"], want["name"]) in seen, (
            f"{sample['name']}: expected APKiD {want}, got {sorted(seen)}"
        )


def test_corpus_manifest_is_loaded() -> None:
    # Guards against a corpus run silently doing nothing (e.g. manifest moved).
    assert _SAMPLES, "corpus manifest is empty or missing"
