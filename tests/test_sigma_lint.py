"""Tests for atlas.sigma_lint — pySigma syntax validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from atlas.sigma_lint import SigmaLintResult, lint_all, lint_sigma_file

VALID_SIGMA = """\
title: Valid Rule
status: experimental
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'sudo vim'
  condition: selection
level: medium
"""

INVALID_SIGMA_BAD_YAML = """\
: : : not valid yaml :
"""

INVALID_SIGMA_BAD_MODIFIER = """\
title: Bad Modifier
status: experimental
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|no_such_modifier: 'test'
  condition: selection
level: medium
"""


@pytest.fixture
def valid_sigma_file(tmp_path: Path) -> Path:
    p = tmp_path / "valid.yml"
    p.write_text(VALID_SIGMA)
    return p


@pytest.fixture
def invalid_yaml_file(tmp_path: Path) -> Path:
    p = tmp_path / "bad_yaml.yml"
    p.write_text(INVALID_SIGMA_BAD_YAML)
    return p


@pytest.fixture
def invalid_modifier_file(tmp_path: Path) -> Path:
    p = tmp_path / "bad_modifier.yml"
    p.write_text(INVALID_SIGMA_BAD_MODIFIER)
    return p


class TestLintSigmaFile:
    def test_valid_rule_passes(self, valid_sigma_file: Path) -> None:
        result = lint_sigma_file(valid_sigma_file)
        assert isinstance(result, SigmaLintResult)
        assert result.ok
        assert result.message == ""

    def test_invalid_yaml_fails(self, invalid_yaml_file: Path) -> None:
        result = lint_sigma_file(invalid_yaml_file)
        assert not result.ok
        assert "invalid YAML" in result.message

    def test_invalid_modifier_fails(self, invalid_modifier_file: Path) -> None:
        result = lint_sigma_file(invalid_modifier_file)
        assert not result.ok

    def test_result_path_preserved(self, valid_sigma_file: Path) -> None:
        result = lint_sigma_file(valid_sigma_file)
        assert result.path == valid_sigma_file


class TestLintAll:
    def test_lint_multiple(
        self, valid_sigma_file: Path, invalid_yaml_file: Path
    ) -> None:
        results = lint_all([valid_sigma_file, invalid_yaml_file])
        assert len(results) == 2
        assert results[0].ok
        assert not results[1].ok

    def test_empty_list(self) -> None:
        assert lint_all([]) == []


class TestRealSigmaRules:
    """Validate all Sigma rules shipped with the repo."""

    def test_all_shipped_sigma_rules_pass(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        sigma_files = list(repo_root.rglob("detections/sigma/*.yml"))
        assert sigma_files, "No Sigma files found — check path"
        results = lint_all(sigma_files)
        failures = [r for r in results if not r.ok]
        assert not failures, "\n".join(f"{r.path}: {r.message}" for r in failures)
