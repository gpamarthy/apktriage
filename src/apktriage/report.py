"""Renders a ``Report`` to the terminal, JSON, and Markdown.

The three formats serve three audiences: rich terminal for a live demo, JSON for
piping into other tooling, and Markdown for pasting into a ticket or interview
write-up. All three read from the same ``Report`` dataclass.
"""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apktriage.models import Finding, Report, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def to_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"# APK Triage Report: `{report.package or report.sha256[:16]}`")
    lines.append("")
    lines.append(f"- **File:** `{report.apk_path}`")
    lines.append(f"- **SHA-256:** `{report.sha256}`")
    lines.append(
        f"- **Version:** {report.version_name}  (minSdk {report.min_sdk}, targetSdk {report.target_sdk})"
    )
    lines.append(f"- **Tools used:** {', '.join(report.tools_used)}")
    lines.append(f"- **Risk score:** {report.risk_score}/100")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if report.findings:
        lines.append("| Severity | Category | Title | Evidence | ATT&CK |")
        lines.append("|---|---|---|---|---|")
        for f in _sorted_findings(report):
            attack = ", ".join(f.attack_ids)
            lines.append(
                f"| {f.severity.value} | {f.category} | {f.title} | `{f.evidence}` | {attack} |"
            )
    else:
        lines.append("_No findings._")
    lines.append("")

    if report.indicators:
        lines.append("## Indicators")
        lines.append("")
        for ind in report.indicators:
            lines.append(f"- **{ind.kind}**: `{ind.value}`")
        lines.append("")

    if report.techniques:
        lines.append("## MITRE ATT&CK Mobile")
        lines.append("")
        lines.append("| Technique | ID | Tactic | Evidence |")
        lines.append("|---|---|---|---|")
        for t in report.techniques:
            lines.append(f"| {t.name} | {t.technique_id} | {t.tactic} | {', '.join(t.evidence)} |")
        lines.append("")

    lines.append("## Generated YARA Rule")
    lines.append("")
    lines.append("```yara")
    lines.append(report.yara_rule.rstrip())
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _sorted_findings(report: Report) -> list[Finding]:
    order = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(report.findings, key=lambda f: order[f.severity])


def render_terminal(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    risk_style = (
        "bold red" if report.risk_score >= 30 else "yellow" if report.risk_score >= 10 else "green"
    )
    console.print(
        Panel(
            f"[bold]{report.package or '(unknown package)'}[/bold]\n"
            f"sha256: {report.sha256}\n"
            f"tools:  {', '.join(report.tools_used)}\n"
            f"risk:   [{risk_style}]{report.risk_score}/100[/{risk_style}]",
            title="apktriage",
            expand=False,
        )
    )

    if report.findings:
        table = Table(title="Findings", show_lines=False)
        table.add_column("Sev")
        table.add_column("Category")
        table.add_column("Title")
        table.add_column("ATT&CK")
        for f in _sorted_findings(report):
            style = _SEVERITY_STYLE[f.severity]
            table.add_row(
                f"[{style}]{f.severity.value}[/{style}]",
                f.category,
                f.title,
                ", ".join(f.attack_ids),
            )
        console.print(table)

    if report.techniques:
        ttable = Table(title="MITRE ATT&CK Mobile")
        ttable.add_column("ID")
        ttable.add_column("Technique")
        ttable.add_column("Tactic")
        for t in report.techniques:
            ttable.add_row(t.technique_id, t.name, t.tactic)
        console.print(ttable)


def write_outputs(report: Report, outdir: Path) -> dict[str, Path]:
    """Write report.json, report.md and the .yar rule; return their paths."""
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": outdir / "report.json",
        "markdown": outdir / "report.md",
        "yara": outdir / f"{report.package or 'sample'}.yar",
    }
    paths["json"].write_text(to_json(report))
    paths["markdown"].write_text(to_markdown(report))
    paths["yara"].write_text(report.yara_rule)
    return paths
