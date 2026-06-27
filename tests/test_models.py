import json

from apktriage.models import Finding, Report, Severity


def test_severity_weight_ordering():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight > Severity.LOW.weight


def test_risk_score_sums_and_clamps():
    r = Report(apk_path="x", sha256="y")
    r.findings = [Finding(category="c", title="t", severity=Severity.CRITICAL) for _ in range(20)]
    assert r.risk_score == 100  # 20*10 clamped to 100


def test_to_dict_is_json_safe():
    r = Report(apk_path="x", sha256="y")
    r.findings.append(Finding(category="c", title="t", severity=Severity.HIGH))
    json.dumps(r.to_dict())  # must not raise
