"""Tests for atlas.render — Jinja2 template rendering."""

from __future__ import annotations

from pathlib import Path

from atlas.models import Platform, Severity, Technique
from atlas.render import RenderDiff, render_all, render_technique


class TestRenderTechnique:
    def test_title_in_output(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "# Test Technique" in out

    def test_platform_in_output(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "linux" in out

    def test_severity_in_output(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "low" in out

    def test_summary_in_output(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "A short summary for unit testing." in out

    def test_mitre_link_rendered(self, full_technique: Technique) -> None:
        out = render_technique(full_technique)
        assert "T1574.009" in out
        assert "https://attack.mitre.org/techniques/T1574/009/" in out

    def test_requirements_rendered(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "One requirement" in out

    def test_exploitation_steps_numbered(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "1. Step one" in out

    def test_disclaimer_rendered(self, full_technique: Technique) -> None:
        out = render_technique(full_technique)
        assert "For authorized testing only." in out

    def test_no_detections_placeholder(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "CONTRIBUTING.md" in out

    def test_poc_links_rendered(self, tmp_path: Path) -> None:
        (tmp_path / "poc.sh").write_text("#!/bin/bash\n")
        t = Technique(
            id="poc-test",
            title="PoC Test",
            platform=Platform.LINUX,
            category="test",
            severity=Severity.LOW,
            summary="ok",
            description="ok",
            requirements=["r"],
            exploitation_steps=["s"],
            mitigations=["m"],
            poc=["poc.sh"],
            source_dir=tmp_path,
        )
        out = render_technique(t)
        assert "[`poc.sh`](./poc.sh)" in out

    def test_generated_header_present(self, minimal_technique: Technique) -> None:
        out = render_technique(minimal_technique)
        assert "GENERATED FILE" in out


class TestRenderAll:
    def test_writes_readme(self, minimal_technique: Technique, tmp_path: Path) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        diffs = render_all([t], check=False)
        assert len(diffs) == 1
        assert (tmp_path / "README.md").exists()

    def test_idempotent(self, minimal_technique: Technique, tmp_path: Path) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        render_all([t], check=False)
        diffs = render_all([t], check=True)
        assert diffs[0].up_to_date

    def test_check_mode_detects_stale(
        self, minimal_technique: Technique, tmp_path: Path
    ) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        (tmp_path / "README.md").write_text("old content")
        diffs = render_all([t], check=True)
        assert not diffs[0].up_to_date
        # check mode must not overwrite
        assert (tmp_path / "README.md").read_text() == "old content"

    def test_check_mode_does_not_write(
        self, minimal_technique: Technique, tmp_path: Path
    ) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        render_all([t], check=True)
        assert not (tmp_path / "README.md").exists()

    def test_render_diff_fields(
        self, minimal_technique: Technique, tmp_path: Path
    ) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        diffs = render_all([t])
        diff = diffs[0]
        assert isinstance(diff, RenderDiff)
        assert diff.technique_id == "test-technique"
        assert diff.path == tmp_path / "README.md"
