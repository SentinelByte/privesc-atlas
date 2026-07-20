"""Typed schema for a privilege escalation technique entry.

Every technique in `techniques/**/technique.yaml` is validated against this
schema before it can be rendered or merged. The schema is the single source
of truth: READMEs are a rendering of it, not the other way around.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Platform(StrEnum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    AI_AGENT = "ai-agent"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionType(StrEnum):
    SIGMA = "sigma"
    OSQUERY = "osquery"
    CUSTOM = "custom"


class MitreMapping(BaseModel):
    technique_id: str
    name: str

    @field_validator("technique_id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _MITRE_ID_RE.match(v):
            raise ValueError(f"'{v}' is not a valid MITRE ATT&CK technique id (e.g. T1548.003)")
        return v

    @property
    def url(self) -> str:
        parts = self.technique_id.split(".")
        path = "/".join(parts)
        return f"https://attack.mitre.org/techniques/{path}/"


class DetectionArtifact(BaseModel):
    type: DetectionType
    path: str
    description: str = ""


class Reference(BaseModel):
    title: str
    url: str


class Technique(BaseModel):
    id: str
    title: str
    platform: Platform
    category: str
    severity: Severity
    summary: str = Field(min_length=1, max_length=200)
    description: str
    mitre_attack: list[MitreMapping] = Field(default_factory=list)
    requirements: list[str] = Field(min_length=1)
    exploitation_steps: list[str] = Field(min_length=1)
    poc: list[str] = Field(default_factory=list)
    detections: list[DetectionArtifact] = Field(default_factory=list)
    mitigations: list[str] = Field(min_length=1)
    references: list[Reference] = Field(default_factory=list)
    disclaimer: str | None = None

    # populated by the loader, not present in technique.yaml itself
    source_dir: Path | None = Field(default=None, exclude=True)

    @field_validator("id")
    @classmethod
    def _valid_slug(cls, v: str) -> str:
        if not _SLUG_RE.match(v):
            raise ValueError(f"id '{v}' must be a lowercase-kebab-case slug")
        return v

    @model_validator(mode="after")
    def _check_paths_exist(self) -> Technique:
        if self.source_dir is None:
            return self
        for rel in [*self.poc, *(d.path for d in self.detections)]:
            if not (self.source_dir / rel).exists():
                raise ValueError(f"referenced path '{rel}' does not exist under {self.source_dir}")
        return self

    @property
    def readme_path(self) -> Path:
        assert self.source_dir is not None
        return self.source_dir / "README.md"
