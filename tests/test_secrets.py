from apktriage import secrets
from apktriage.models import Severity


def test_detects_google_api_key():
    text = 'String k = "AIzaSyB1cD3fG5hJ7kL9mN1pQ3rS5tU7vW9xY0z";'
    findings = secrets.scan_text(text, "X.java", secrets.load_patterns())
    titles = [f.title for f in findings]
    assert any("Google API Key" in t for t in titles)


def test_detects_aws_and_pem():
    text = "AKIAIOSFODNN7EXAMPLE\n-----BEGIN RSA PRIVATE KEY-----"
    findings = secrets.scan_text(text, "native", secrets.load_patterns())
    titles = {f.title for f in findings}
    assert any("AWS Access Key" in t for t in titles)
    pem = next(f for f in findings if "PEM" in f.title)
    assert pem.severity is Severity.CRITICAL


def test_entropy_gate_rejects_placeholder():
    # Generic assignment pattern, but the value is low-entropy filler.
    text = 'api_key="aaaaaaaaaaaaaaaa"'
    findings = secrets.scan_text(text, "x", secrets.load_patterns())
    assert not any(f.title.startswith("Hardcoded secret: Generic") for f in findings)


def test_entropy_gate_keeps_random_value():
    text = 'api_key="9bX2kQ7zV4mN8pR1tL6w"'
    findings = secrets.scan_text(text, "x", secrets.load_patterns())
    assert any("Generic API Key" in f.title for f in findings)


def test_redaction_hides_full_secret():
    text = "AIzaSyB1cD3fG5hJ7kL9mN1pQ3rS5tU7vW9xY0z"
    findings = secrets.scan_text(text, "x", secrets.load_patterns())
    assert "..." in findings[0].evidence
    assert text not in findings[0].evidence


def test_shannon_entropy_ordering():
    assert secrets.shannon_entropy("aaaa") < secrets.shannon_entropy("9bX2kQ7z")


def test_run_dedupes_across_sources():
    src = {
        "a": ["AKIAIOSFODNN7EXAMPLE"],
        "b": ["AKIAIOSFODNN7EXAMPLE"],
    }
    findings = secrets.run(src)
    aws = [f for f in findings if "AWS" in f.title]
    assert len(aws) == 1
