"""`atlas` — validate, render, and query the technique knowledge base.

    atlas validate         schema + cross-reference + Sigma syntax checks (CI gate)
    atlas render [--check] regenerate technique READMEs from technique.yaml
    atlas list              table of all techniques
    atlas attack-layer       emit a MITRE ATT&CK Navigator layer of covered techniques
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from atlas.loader import DEFAULT_ROOT, load_all
from atlas.models import DetectionType, Technique
from atlas.render import render_all
from atlas.sigma_lint import lint_sigma_file

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()
err_console = Console(stderr=True)


@app.command()
def validate(
    root: Path = typer.Option(DEFAULT_ROOT, help="Root directory containing techniques/"),
) -> None:
    """Validate every technique.yaml (schema, cross-references, Sigma syntax)."""
    result = load_all(root)
    failed = False

    for load_error in result.errors:
        err_console.print(f"[red]FAIL[/red] {load_error.path}: {load_error.message}")
        failed = True

    for technique in result.techniques:
        for detection in technique.detections:
            if detection.type is DetectionType.SIGMA:
                lint = lint_sigma_file(technique.source_dir / detection.path)  # type: ignore[operator]
                if not lint.ok:
                    err_console.print(f"[red]FAIL[/red] {lint.path}: {lint.message}")
                    failed = True

    if failed:
        raise typer.Exit(code=1)
    console.print(f"[green]OK[/green] {len(result.techniques)} techniques validated")


@app.command()
def render(
    root: Path = typer.Option(DEFAULT_ROOT, help="Root directory containing techniques/"),
    check: bool = typer.Option(False, help="Fail if a README is out of date instead of writing it"),
) -> None:
    """Regenerate README.md for each technique from technique.yaml."""
    result = load_all(root)
    if not result.ok:
        for e in result.errors:
            err_console.print(f"[red]FAIL[/red] {e.path}: {e.message}")
        raise typer.Exit(code=1)

    diffs = render_all(result.techniques, check=check)
    stale = [d for d in diffs if not d.up_to_date]
    if check and stale:
        for d in stale:
            err_console.print(
                f"[red]STALE[/red] {d.path} does not match technique.yaml — run `atlas render`"
            )
        raise typer.Exit(code=1)

    console.print(f"[green]OK[/green] {len(diffs)} READMEs {'checked' if check else 'rendered'}")


@app.command(name="list")
def list_techniques(
    root: Path = typer.Option(DEFAULT_ROOT, help="Root directory containing techniques/"),
) -> None:
    """Print a table of all techniques."""
    result = load_all(root)
    table = Table()
    for col in ("ID", "Platform", "Severity", "MITRE ATT&CK", "Detections"):
        table.add_column(col)

    for t in sorted(result.techniques, key=lambda t: (t.platform.value, t.id)):
        mitre = ", ".join(m.technique_id for m in t.mitre_attack) or "-"
        detections = str(len(t.detections))
        table.add_row(t.id, t.platform.value, t.severity.value, mitre, detections)

    console.print(table)
    if result.errors:
        for e in result.errors:
            err_console.print(f"[yellow]WARN[/yellow] {e.path}: {e.message}")


@app.command(name="attack-layer")
def attack_layer(
    root: Path = typer.Option(DEFAULT_ROOT, help="Root directory containing techniques/"),
    output: Path = typer.Option(
        Path("attack-navigator-layer.json"), help="Output path for the layer JSON"
    ),
) -> None:
    """Generate a MITRE ATT&CK Navigator layer showing technique coverage."""
    result = load_all(root)
    techniques: list[Technique] = result.techniques

    scores: dict[str, list[str]] = {}
    for t in techniques:
        for m in t.mitre_attack:
            scores.setdefault(m.technique_id, []).append(t.id)

    layer = {
        "name": "Privilege Escalation Atlas Coverage",
        "versions": {"attack": "15", "navigator": "5.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques with a PoC, detection, and mitigation in privesc-atlas.",
        "techniques": [
            {
                "techniqueID": technique_id,
                "score": 50,
                "comment": f"Covered by: {', '.join(ids)}",
            }
            for technique_id, ids in sorted(scores.items())
        ],
        "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 100},
    }
    output.write_text(json.dumps(layer, indent=2))
    console.print(f"[green]OK[/green] wrote {len(scores)} technique(s) to {output}")


if __name__ == "__main__":
    app()
