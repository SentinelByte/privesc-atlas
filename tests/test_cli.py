"""Tests for atlas.cli — Typer command integration."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from atlas.cli import app

runner = CliRunner()


@pytest.fixture
def techniques_root() -> Path:
    return Path(__file__).resolve().parents[1] / "techniques"


class TestValidateCommand:
    def test_validate_succeeds_on_real_techniques(self, techniques_root: Path) -> None:
        result = runner.invoke(app, ["validate", "--root", str(techniques_root)])
        assert result.exit_code == 0, result.output
        assert "OK" in result.output

    def test_validate_fails_on_bad_technique(self, tmp_path: Path) -> None:
        bad_dir = tmp_path / "bad-technique"
        bad_dir.mkdir()
        (bad_dir / "technique.yaml").write_text("id: bad\nplatform: linux\n")
        result = runner.invoke(app, ["validate", "--root", str(tmp_path)])
        assert result.exit_code != 0

    def test_validate_empty_root_reports_zero_ok(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["validate", "--root", str(tmp_path)])
        assert result.exit_code == 0
        assert "0 techniques" in result.output


class TestRenderCommand:
    def test_render_check_passes_when_readmes_current(self, techniques_root: Path) -> None:
        result = runner.invoke(app, ["render", "--root", str(techniques_root), "--check"])
        assert result.exit_code == 0, result.output

    def test_render_writes_readme(self, valid_technique_dir: Path) -> None:
        readme = valid_technique_dir / "README.md"
        if readme.exists():
            readme.unlink()
        result = runner.invoke(app, ["render", "--root", str(valid_technique_dir.parent)])
        assert result.exit_code == 0, result.output
        assert readme.exists()

    def test_render_check_fails_when_stale(self, valid_technique_dir: Path) -> None:
        (valid_technique_dir / "README.md").write_text("stale content")
        result = runner.invoke(
            app, ["render", "--root", str(valid_technique_dir.parent), "--check"]
        )
        assert result.exit_code != 0
        assert "STALE" in result.output


class TestListCommand:
    def test_list_outputs_table(self, techniques_root: Path) -> None:
        result = runner.invoke(app, ["list", "--root", str(techniques_root)])
        assert result.exit_code == 0, result.output
        # Rich table output should contain platform and severity columns
        assert "linux" in result.output or "windows" in result.output or "macos" in result.output

    def test_list_shows_all_platforms(self, techniques_root: Path) -> None:
        result = runner.invoke(app, ["list", "--root", str(techniques_root)])
        assert "linux" in result.output
        assert "macos" in result.output
        assert "windows" in result.output
        assert "ai-agent" in result.output


class TestAttackLayerCommand:
    def test_attack_layer_creates_json(self, techniques_root: Path, tmp_path: Path) -> None:
        output = tmp_path / "layer.json"
        result = runner.invoke(
            app,
            ["attack-layer", "--root", str(techniques_root), "--output", str(output)],
        )
        assert result.exit_code == 0, result.output
        assert output.exists()

    def test_attack_layer_valid_json(self, techniques_root: Path, tmp_path: Path) -> None:
        import json

        output = tmp_path / "layer.json"
        runner.invoke(
            app,
            ["attack-layer", "--root", str(techniques_root), "--output", str(output)],
        )
        layer = json.loads(output.read_text())
        assert "techniques" in layer
        assert "domain" in layer
        assert layer["domain"] == "enterprise-attack"
