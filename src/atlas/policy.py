"""A minimal least-privilege policy engine for LLM agent / MCP tool calls.

Classic OS privilege escalation exploits a gap between the permission a
principal is *supposed* to have and the permission the system actually
enforces (sudo NOPASSWD, an unquoted service path, a writable LaunchDaemon).
Agentic AI systems have the same gap, just with a new principal: content the
agent ingests (a fetched page, a returned tool result) can smuggle
instructions that get treated as if they came from the user, and cause a
*low-trust* input to trigger a *high-privilege* tool call. That's a confused
deputy — a privilege escalation — even though no OS boundary is crossed.

This module is the control referenced by
`techniques/ai-agent/mcp-tool-poisoning/`: it gates every tool call by the
trust level of whatever triggered it, independent of what the model
"decided" to do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class TrustLevel(IntEnum):
    """Provenance of whatever immediately triggered a tool call."""

    UNTRUSTED = 0  # content ingested from outside the trust boundary (web page, file, tool result)
    USER = 1  # the human operator, in the current turn
    TRUSTED = 2  # the host application itself (e.g. a hardcoded system action)


@dataclass(frozen=True)
class ToolSpec:
    """A tool an agent may call, and the minimum provenance required to auto-run it."""

    name: str
    min_trust: TrustLevel
    human_confirmable: bool = True
    description: str = ""


class Decision(IntEnum):
    DENY = 0
    REQUIRE_CONFIRMATION = 1
    ALLOW = 2


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str


@dataclass(frozen=True)
class AuditEvent:
    """Structured record of a policy evaluation, meant to be logged as JSON lines.

    This is the artifact the detection rule in
    `detections/agent_toolcall_escalation.yml` matches against.
    """

    session_id: str
    tool_name: str
    provenance: TrustLevel
    decision: Decision
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "provenance": self.provenance.name.lower(),
            "decision": self.decision.name.lower(),
            "reason": self.reason,
        }


@dataclass
class PolicyEngine:
    """Evaluates tool calls against registered ToolSpecs and emits an audit trail."""

    tools: dict[str, ToolSpec] = field(default_factory=dict)
    audit_log: list[AuditEvent] = field(default_factory=list)

    def register(self, tool: ToolSpec) -> None:
        self.tools[tool.name] = tool

    def evaluate(
        self,
        session_id: str,
        tool_name: str,
        provenance: TrustLevel,
        confirmed: bool = False,
    ) -> PolicyDecision:
        tool = self.tools.get(tool_name)
        if tool is None:
            result = PolicyDecision(Decision.DENY, f"unknown tool '{tool_name}'")
        elif provenance >= tool.min_trust:
            result = PolicyDecision(
                Decision.ALLOW,
                f"provenance {provenance.name} meets minimum {tool.min_trust.name}",
            )
        elif tool.human_confirmable and confirmed:
            result = PolicyDecision(
                Decision.ALLOW, "explicit human confirmation overrides provenance"
            )
        elif tool.human_confirmable:
            result = PolicyDecision(
                Decision.REQUIRE_CONFIRMATION,
                f"provenance {provenance.name} below minimum {tool.min_trust.name}; "
                "human confirmation required",
            )
        else:
            result = PolicyDecision(
                Decision.DENY, "tool is not human-confirmable and provenance is insufficient"
            )

        self.audit_log.append(
            AuditEvent(
                session_id=session_id,
                tool_name=tool_name,
                provenance=provenance,
                decision=result.decision,
                reason=result.reason,
            )
        )
        return result

    def audit_registry(self) -> list[str]:
        """Static check: flag tools configured to auto-run for untrusted provenance.

        The agent-security equivalent of the `sudo_nopasswd` osquery check —
        a misconfigured registry is the root cause, not any single exploit attempt.
        """
        findings = []
        for tool in self.tools.values():
            if tool.min_trust == TrustLevel.UNTRUSTED:
                findings.append(
                    f"tool '{tool.name}' auto-runs for UNTRUSTED provenance — "
                    "any ingested content can trigger it without human review"
                )
        return findings
