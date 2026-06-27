from pathlib import Path

import pytest
import yaml

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = Path(__file__).parent / "corpus"
CORPUS_SAMPLES = CORPUS / "samples"


def load_corpus_samples() -> list[dict]:
    """Manifest entries for the real-APK corpus (empty if manifest is absent)."""
    manifest = CORPUS / "manifest.yml"
    if not manifest.exists():
        return []
    return list(yaml.safe_load(manifest.read_text())["samples"])


def corpus_sample_path(name: str) -> Path:
    return CORPUS_SAMPLES / f"{name}.apk"


@pytest.fixture
def fixture_apk() -> Path:
    apk = FIXTURES / "benign_sample.apk"
    if not apk.exists():
        pytest.skip("benign_sample.apk not built; run tests/fixtures/build_fixture.sh")
    return apk


@pytest.fixture
def fixture_so() -> Path:
    so = FIXTURES / "src" / "lib" / "arm64-v8a" / "libdemo.so"
    if not so.exists():
        pytest.skip("libdemo.so not built; run tests/fixtures/build_fixture.sh")
    return so
