"""Command-line entry point for apktriage."""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(
    add_completion=False,
    help="Static APK reverse-engineering and triage toolkit.",
)


@app.callback()
def _root() -> None:
    """Group callback: keeps ``scan`` an explicit subcommand."""


@app.command()
def scan(
    apk: Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True, help="Path to the .apk"
    ),
    outdir: Path | None = typer.Option(
        None, "--out", "-o", help="Output directory (default: <apk>.out)"
    ),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal | json | markdown"),
    no_external: bool = typer.Option(
        False, "--no-external", help="Skip apktool/jadx even if installed"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging to stderr"),
) -> None:
    """Triage APK and write report.json, report.md and a generated YARA rule."""
    from rich.console import Console

    from apktriage import pipeline, report
    from apktriage.logging import configure

    configure(verbose=verbose)
    out = outdir or apk.with_suffix(apk.suffix + ".out")

    result = pipeline.run(apk, out, use_external=not no_external)
    paths = report.write_outputs(result, out)

    if fmt == "json":
        print(report.to_json(result))
    elif fmt == "markdown":
        print(report.to_markdown(result))
    else:
        report.render_terminal(result, Console())

    Console(stderr=True).print(
        f"[green]wrote[/green] {paths['json']}  {paths['markdown']}  {paths['yara']}"
    )


def main() -> None:  # console-script shim
    app()


if __name__ == "__main__":
    main()
