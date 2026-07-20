"""Render README.md for each technique from technique.yaml + a Jinja2 template.

technique.yaml is the source of truth; README.md is a build artifact. This
module also powers `atlas render --check`, which CI uses to fail a PR whose
committed README has drifted from what the data would generate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from atlas.models import Technique

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render_technique(technique: Technique) -> str:
    template = _environment().get_template("technique.md.j2")
    return template.render(t=technique)


@dataclass
class RenderDiff:
    technique_id: str
    path: Path
    up_to_date: bool


def render_all(techniques: list[Technique], check: bool = False) -> list[RenderDiff]:
    diffs: list[RenderDiff] = []
    for technique in techniques:
        rendered = render_technique(technique)
        path = technique.readme_path
        current = path.read_text() if path.exists() else None
        up_to_date = current == rendered
        diffs.append(RenderDiff(technique_id=technique.id, path=path, up_to_date=up_to_date))
        if not check and not up_to_date:
            path.write_text(rendered)
    return diffs
