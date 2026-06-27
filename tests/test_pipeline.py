from pathlib import Path

import pytest
import yara

from apktriage import pipeline, report


@pytest.mark.integration
def test_end_to_end_on_fixture(fixture_apk: Path, tmp_path: Path):
    result = pipeline.run(fixture_apk, tmp_path / "out", use_external=True)

    assert result.package == "com.example.triagedemo"
    assert "androguard" in result.tools_used

    titles = " ".join(f"{f.title} {f.evidence}" for f in result.findings)
    cats = {f.category for f in result.findings}

    # Planted secret + C2 indicator are recovered.
    assert "Google API Key" in titles
    assert any(i.value == "198.51.100.23" for i in result.indicators)

    # Behavioural detections fired.
    assert "dynamic_code" in cats  # DexClassLoader / Runtime.exec
    assert "secret" in cats
    assert "c2_indicator" in cats

    # A compilable YARA rule and at least one ATT&CK technique were produced.
    assert yara.compile(source=result.yara_rule) is not None
    ids = {t.technique_id for t in result.techniques}
    assert {"T1407", "T1437"}.issubset(ids)


@pytest.mark.integration
def test_writes_three_outputs(fixture_apk: Path, tmp_path: Path):
    out = tmp_path / "out"
    result = pipeline.run(fixture_apk, out, use_external=False)
    paths = report.write_outputs(result, out)
    for key in ("json", "markdown", "yara"):
        assert paths[key].exists()
        assert paths[key].read_text().strip()


@pytest.mark.integration
def test_works_without_external_tools(fixture_apk: Path, tmp_path: Path):
    # androguard-only path: still recovers DEX-string secrets and indicators.
    result = pipeline.run(fixture_apk, tmp_path / "out", use_external=False)
    assert result.tools_used == ["androguard"]
    assert any(f.category == "secret" for f in result.findings)
