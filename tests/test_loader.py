"""Tests for atlas.loader — technique discovery and loading."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atlas.loader import LoadResult, find_technique_files, load_all, load_technique
from atlas.models import Technique


class TestFindTechniqueFiles:
    def test_finds_all_real_techniques(self, techniques_root: Path) -> None:
        paths = find_technique_files(techniques_root)
        assert len(paths) >= 5  # at least the 5 shipped techniques
        assert all(p.name == "technique.yaml" for p in paths)

    def test_returns_sorted(self, techniques_root: Path) -> None:
        paths = find_technique_files(techniques_root)
        assert paths == sorted(paths)

    def test_empty_root(self, tmp_path: Path) -> None:
        assert find_technique_files(tmp_path) == []

    def test_ignores_non_technique_yaml(self, tmp_path: Path) -> None:
        (tmp_path / "not-technique.yaml").write_text("nope: true\n")
        assert find_technique_files(tmp_path) == []


class TestLoadTechnique:
    def test_loads_valid_technique(self, valid_technique_dir: Path) -> None:
        path = valid_technique_dir / "technique.yaml"
        t = load_technique(path)
        assert isinstance(t, Technique)
        assert t.id == "stub-technique"
        assert t.source_dir == valid_technique_dir

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "technique.yaml"
        bad.write_text(": : invalid yaml :::\n")
        import yaml as _yaml
        from pydantic import ValidationError

        with pytest.raises((_yaml.YAMLError, ValidationError, Exception)):
            load_technique(bad)


class TestLoadAll:
    def test_loads_all_real_techniques(self, techniques_root: Path) -> None:
        result = load_all(techniques_root)
        assert result.ok, "\n".join(e.message for e in result.errors)
        assert len(result.techniques) >= 5

    def test_load_result_ok_property(self, valid_technique_dir: Path) -> None:
        result = load_all(valid_technique_dir.parent)
        assert isinstance(result, LoadResult)

    def test_id_mismatch_reported(self, tmp_path: Path) -> None:
        tech_dir = tmp_path / "correct-folder"
        tech_dir.mkdir()
        data = {
            "id": "wrong-id",
            "title": "x",
            "platform": "linux",
            "category": "x",
            "severity": "low",
            "summary": "ok",
            "description": "ok",
            "requirements": ["r"],
            "exploitation_steps": ["s"],
            "mitigations": ["m"],
        }
        (tech_dir / "technique.yaml").write_text(yaml.dump(data))
        result = load_all(tmp_path)
        assert not result.ok
        assert any("wrong-id" in e.message or "correct-folder" in e.message for e in result.errors)

    def test_no_duplicate_ids(self, techniques_root: Path) -> None:
        result = load_all(techniques_root)
        ids = [t.id for t in result.techniques]
        assert len(ids) == len(set(ids))

    def test_each_technique_id_matches_folder(self, techniques_root: Path) -> None:
        result = load_all(techniques_root)
        assert result.ok
        for t in result.techniques:
            assert t.source_dir is not None
            assert t.id == t.source_dir.name


@pytest.fixture
def techniques_root() -> Path:
    return Path(__file__).resolve().parents[1] / "techniques"
