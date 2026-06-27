from pathlib import Path

import pytest

from apktriage import packers


def test_scan_fixture_or_skip(fixture_apk: Path):
    if packers._find_apkid() is None:
        pytest.skip("apkid not installed")
    verdicts, _findings = packers.scan(str(fixture_apk))
    # apktool builds the DEX with dexlib, which APKiD identifies as a compiler.
    assert any(v.category == "compiler" for v in verdicts)


def test_scan_missing_apkid_is_graceful(monkeypatch):
    monkeypatch.setattr(packers, "_find_apkid", lambda: None)
    assert packers.scan("whatever.apk") == ([], [])
