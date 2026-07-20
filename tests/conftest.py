"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atlas.models import (
    MitreMapping,
    Platform,
    Severity,
    Technique,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
TECHNIQUES_ROOT = REPO_ROOT / "techniques"


@pytest.fixture
def minimal_technique() -> Technique:
    """A valid Technique with no files on disk (source_dir=None skips path checks)."""
    return Technique(
        id="test-technique",
        title="Test Technique",
        platform=Platform.LINUX,
        category="test",
        severity=Severity.LOW,
        summary="A short summary for unit testing.",
        description="Extended description.",
        requirements=["One requirement"],
        exploitation_steps=["Step one"],
        mitigations=["One mitigation"],
    )


@pytest.fixture
def full_technique() -> Technique:
    """A valid Technique with MITRE mapping and references."""
    return Technique(
        id="full-technique",
        title="Full Technique",
        platform=Platform.WINDOWS,
        category="misconfiguration",
        severity=Severity.HIGH,
        summary="A full technique used in render tests.",
        description="This technique has all optional fields populated.",
        mitre_attack=[
            MitreMapping(technique_id="T1574.009", name="Path Interception by Unquoted Path")
        ],
        requirements=["Requirement A", "Requirement B"],
        exploitation_steps=["Step one", "Step two"],
        mitigations=["Mitigation A"],
        disclaimer="For authorized testing only.",
    )


@pytest.fixture
def valid_technique_dir(tmp_path: Path) -> Path:
    """A temporary directory containing a valid technique.yaml and a stub PoC."""
    tech_dir = tmp_path / "stub-technique"
    tech_dir.mkdir()
    (tech_dir / "poc.sh").write_text("#!/bin/bash\necho hi\n")

    detections_dir = tech_dir / "detections" / "sigma"
    detections_dir.mkdir(parents=True)
    sigma_file = detections_dir / "stub.yml"
    sigma_file.write_text(
        "title: Stub\n"
        "status: experimental\n"
        "logsource:\n"
        "  product: linux\n"
        "  category: process_creation\n"
        "detection:\n"
        "  selection:\n"
        "    CommandLine|contains: 'sudo vim'\n"
        "  condition: selection\n"
        "level: medium\n"
    )

    data = {
        "id": "stub-technique",
        "title": "Stub Technique",
        "platform": "linux",
        "category": "test",
        "severity": "low",
        "summary": "A minimal stub technique for loader tests.",
        "description": "Description text.",
        "requirements": ["Requirement one"],
        "exploitation_steps": ["Step one"],
        "poc": ["poc.sh"],
        "detections": [
            {
                "type": "sigma",
                "path": "detections/sigma/stub.yml",
                "description": "Stub sigma rule.",
            }
        ],
        "mitigations": ["Mitigation one"],
    }
    (tech_dir / "technique.yaml").write_text(yaml.dump(data))
    return tech_dir
