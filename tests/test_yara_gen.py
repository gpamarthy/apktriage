import yara

from apktriage import yara_gen
from apktriage.models import Indicator, PackerVerdict, Report


def _report() -> Report:
    r = Report(apk_path="x.apk", sha256="a" * 64, package="com.example.app")
    r.indicators = [
        Indicator(kind="url", value="http://203.0.113.45/gate"),
        Indicator(kind="ipv4", value="203.0.113.45"),
    ]
    r.packers = [PackerVerdict(category="packer", name="Jiagu")]
    return r


def test_generated_rule_compiles():
    rule = yara_gen.build(_report())
    compiled = yara.compile(source=rule)  # raises on bad syntax
    assert compiled is not None
    assert "apktriage_com_example_app" in rule


def test_rule_matches_a_zip_with_the_indicator(tmp_path):
    rule_text = yara_gen.build(_report())
    rules = yara.compile(source=rule_text)
    # A minimal ZIP (PK magic) carrying one of the indicator strings should hit.
    blob = b"PK\x03\x04" + b"....http://203.0.113.45/gate....203.0.113.45...."
    sample = tmp_path / "s.bin"
    sample.write_bytes(blob)
    assert rules.match(str(sample))


def test_handles_no_distinctive_strings():
    r = Report(apk_path="x.apk", sha256="b" * 64, package="com.empty")
    rule = yara_gen.build(r)
    assert yara.compile(source=rule) is not None
