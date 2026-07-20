"""Discover and validate technique.yaml files under a techniques/ root."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from atlas.models import Technique

DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "techniques"


@dataclass
class LoadError:
    path: Path
    message: str


@dataclass
class LoadResult:
    techniques: list[Technique]
    errors: list[LoadError]

    @property
    def ok(self) -> bool:
        return not self.errors


def find_technique_files(root: Path = DEFAULT_ROOT) -> list[Path]:
    return sorted(root.rglob("technique.yaml"))


def load_technique(path: Path) -> Technique:
    raw = yaml.safe_load(path.read_text())
    return Technique.model_validate({**raw, "source_dir": path.parent})


def load_all(root: Path = DEFAULT_ROOT) -> LoadResult:
    techniques: list[Technique] = []
    errors: list[LoadError] = []

    for path in find_technique_files(root):
        try:
            technique = load_technique(path)
        except (ValidationError, yaml.YAMLError) as exc:
            errors.append(LoadError(path=path, message=str(exc)))
            continue

        expected_id = path.parent.name
        if technique.id != expected_id:
            errors.append(
                LoadError(
                    path=path,
                    message=f"id '{technique.id}' does not match folder name '{expected_id}'",
                )
            )
            continue

        techniques.append(technique)

    ids = [t.id for t in techniques]
    for dup in {i for i in ids if ids.count(i) > 1}:
        errors.append(LoadError(path=root, message=f"duplicate technique id '{dup}'"))

    return LoadResult(techniques=techniques, errors=errors)
