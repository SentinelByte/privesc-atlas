"""Syntax-validate Sigma detection rules using pySigma.

This catches the class of bug a human reviewer easily misses in a PR diff:
a Sigma rule that "looks right" but has an invalid logsource, a malformed
modifier, or breaks the spec in a way that would make it silently fail to
load in a real SIEM.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError


@dataclass
class SigmaLintResult:
    path: Path
    ok: bool
    message: str = ""


def lint_sigma_file(path: Path) -> SigmaLintResult:
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return SigmaLintResult(path=path, ok=False, message=f"invalid YAML: {exc}")

    try:
        SigmaCollection.from_dicts([raw])
    except SigmaError as exc:
        return SigmaLintResult(path=path, ok=False, message=str(exc))

    return SigmaLintResult(path=path, ok=True)


def lint_all(paths: list[Path]) -> list[SigmaLintResult]:
    return [lint_sigma_file(p) for p in paths]
