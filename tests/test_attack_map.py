from apktriage import attack_map
from apktriage.models import Finding, Severity


def test_permission_maps_to_location_tracking():
    techs = attack_map.run({"ACCESS_FINE_LOCATION"}, [])
    ids = {t.technique_id for t in techs}
    assert "T1430" in ids


def test_finding_category_maps_and_stamps():
    findings = [Finding(category="c2_indicator", title="Embedded URL", severity=Severity.MEDIUM)]
    techs = attack_map.run(set(), findings)
    assert any(t.technique_id == "T1437" for t in techs)
    assert "T1437" in findings[0].attack_ids  # stamped back onto the finding


def test_api_substring_maps_to_exec():
    findings = [
        Finding(
            category="dynamic_code", title="Runtime.exec (shell command)", severity=Severity.HIGH
        )
    ]
    techs = attack_map.run(set(), findings)
    assert any(t.technique_id == "T1623" for t in techs)


def test_no_signal_no_techniques():
    assert attack_map.run(set(), []) == []
