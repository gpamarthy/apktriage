from pathlib import Path

from apktriage import native


def test_parses_so_and_flags_system_import(fixture_so: Path):
    data = fixture_so.read_bytes()
    findings, _strings = native.analyze_lib("lib/arm64-v8a/libdemo.so", data)
    categories = {f.category for f in findings}
    assert "native_lib" in categories  # arch line emitted
    assert any(f.evidence == "system" for f in findings)  # suspicious import flagged


def test_native_strings_include_planted_values(fixture_so: Path):
    data = fixture_so.read_bytes()
    _, strings = native.analyze_lib("x", data)
    joined = "\n".join(strings)
    assert "203.0.113.45" in joined
    assert "AKIAIOSFODNN7EXAMPLE" in joined


def test_run_handles_empty():
    findings, by_lib = native.run({})
    assert findings == []
    assert by_lib == {}
