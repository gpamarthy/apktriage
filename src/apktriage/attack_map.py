"""Stage 8: map static signals to MITRE ATT&CK Mobile techniques.

Driven entirely by ``data/attack_mobile.yml`` so the mapping is auditable and
editable without touching code. A technique fires when any of its declared
signals is present: a requested permission, a suspicious API seen in the
findings, or a finding category emitted by an earlier stage. We also stamp the
matched technique ids back onto the contributing findings for traceability.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

import yaml

from apktriage.models import AttackTechnique, Finding


@dataclass
class TechniqueRule:
    technique_id: str
    name: str
    tactic: str
    permissions: frozenset[str]
    apis: tuple[str, ...]
    finding_cats: frozenset[str]


@lru_cache(maxsize=1)
def load_rules() -> tuple[TechniqueRule, ...]:
    raw = resources.files("apktriage.data").joinpath("attack_mobile.yml").read_text()
    rules: list[TechniqueRule] = []
    for e in yaml.safe_load(raw):
        rules.append(
            TechniqueRule(
                technique_id=e["id"],
                name=e["name"],
                tactic=e["tactic"],
                permissions=frozenset(e.get("permissions", [])),
                apis=tuple(e.get("apis", [])),
                finding_cats=frozenset(e.get("finding_cats", [])),
            )
        )
    return tuple(rules)


def run(permissions: set[str], findings: list[Finding]) -> list[AttackTechnique]:
    """Return matched techniques and annotate findings with their technique ids."""
    haystack = " ".join(f"{f.title} {f.evidence} {f.detail}" for f in findings)
    present_cats = {f.category for f in findings}
    techniques: list[AttackTechnique] = []

    for rule in load_rules():
        evidence: list[str] = []
        evidence.extend(sorted(rule.permissions & permissions))
        evidence.extend(api for api in rule.apis if api in haystack)
        evidence.extend(sorted(rule.finding_cats & present_cats))
        if not evidence:
            continue
        techniques.append(
            AttackTechnique(
                technique_id=rule.technique_id,
                name=rule.name,
                tactic=rule.tactic,
                evidence=sorted(set(evidence)),
            )
        )
        for f in findings:
            if f.category in rule.finding_cats and rule.technique_id not in f.attack_ids:
                f.attack_ids.append(rule.technique_id)

    return techniques
