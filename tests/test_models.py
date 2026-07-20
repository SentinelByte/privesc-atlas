"""Tests for atlas.models — Pydantic schema validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from atlas.models import (
    DetectionArtifact,
    DetectionType,
    MitreMapping,
    Platform,
    Severity,
    Technique,
)


class TestMitreMapping:
    def test_valid_id_simple(self) -> None:
        m = MitreMapping(technique_id="T1548", name="Elevation")
        assert m.url == "https://attack.mitre.org/techniques/T1548/"

    def test_valid_id_subtechnique(self) -> None:
        m = MitreMapping(technique_id="T1548.003", name="Sudo")
        assert m.url == "https://attack.mitre.org/techniques/T1548/003/"

    def test_invalid_id_lowercase(self) -> None:
        with pytest.raises(ValidationError, match="MITRE ATT&CK"):
            MitreMapping(technique_id="t1548", name="x")

    def test_invalid_id_no_digits(self) -> None:
        with pytest.raises(ValidationError):
            MitreMapping(technique_id="TABC", name="x")

    def test_invalid_id_wrong_subtechnique_digits(self) -> None:
        with pytest.raises(ValidationError):
            MitreMapping(technique_id="T1548.03", name="x")


class TestTechnique:
    def test_valid_minimal(self, minimal_technique: Technique) -> None:
        assert minimal_technique.id == "test-technique"
        assert minimal_technique.platform == Platform.LINUX
        assert minimal_technique.severity == Severity.LOW

    def test_invalid_id_not_kebab(self) -> None:
        with pytest.raises(ValidationError, match="kebab-case"):
            Technique(
                id="Test_Technique",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=["m"],
            )

    def test_invalid_id_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            Technique(
                id="MyTechnique",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=["m"],
            )

    def test_summary_too_long(self) -> None:
        with pytest.raises(ValidationError):
            Technique(
                id="test",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="x" * 201,
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=["m"],
            )

    def test_summary_exact_max(self) -> None:
        t = Technique(
            id="test",
            title="x",
            platform=Platform.LINUX,
            category="x",
            severity=Severity.LOW,
            summary="x" * 200,
            description="ok",
            requirements=["r"],
            exploitation_steps=["s"],
            mitigations=["m"],
        )
        assert len(t.summary) == 200

    def test_empty_requirements_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Technique(
                id="test",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=[],
                exploitation_steps=["s"],
                mitigations=["m"],
            )

    def test_empty_mitigations_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Technique(
                id="test",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=[],
            )

    def test_poc_path_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="does not exist"):
            Technique(
                id="test",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=["m"],
                poc=["missing.sh"],
                source_dir=tmp_path,
            )

    def test_detection_path_missing_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="does not exist"):
            Technique(
                id="test",
                title="x",
                platform=Platform.LINUX,
                category="x",
                severity=Severity.LOW,
                summary="ok",
                description="ok",
                requirements=["r"],
                exploitation_steps=["s"],
                mitigations=["m"],
                detections=[DetectionArtifact(type=DetectionType.SIGMA, path="nonexistent.yml")],
                source_dir=tmp_path,
            )

    def test_poc_path_exists(self, tmp_path: Path) -> None:
        (tmp_path / "poc.sh").write_text("#!/bin/bash\n")
        t = Technique(
            id="test",
            title="x",
            platform=Platform.LINUX,
            category="x",
            severity=Severity.LOW,
            summary="ok",
            description="ok",
            requirements=["r"],
            exploitation_steps=["s"],
            mitigations=["m"],
            poc=["poc.sh"],
            source_dir=tmp_path,
        )
        assert t.poc == ["poc.sh"]

    def test_readme_path(self, minimal_technique: Technique, tmp_path: Path) -> None:
        t = minimal_technique.model_copy(update={"source_dir": tmp_path})
        assert t.readme_path == tmp_path / "README.md"

    def test_ai_agent_platform(self) -> None:
        t = Technique(
            id="test-ai",
            title="x",
            platform=Platform.AI_AGENT,
            category="prompt-injection",
            severity=Severity.CRITICAL,
            summary="ok",
            description="ok",
            requirements=["r"],
            exploitation_steps=["s"],
            mitigations=["m"],
        )
        assert t.platform == Platform.AI_AGENT
        assert t.platform.value == "ai-agent"
