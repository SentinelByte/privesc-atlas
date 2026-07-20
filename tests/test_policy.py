"""Tests for atlas.policy — least-privilege policy engine."""

from __future__ import annotations

import json

import pytest

from atlas.policy import (
    AuditEvent,
    Decision,
    PolicyDecision,
    PolicyEngine,
    ToolSpec,
    TrustLevel,
)

SESSION = "test-session"


@pytest.fixture
def engine() -> PolicyEngine:
    e = PolicyEngine()
    e.register(ToolSpec(name="web_fetch", min_trust=TrustLevel.UNTRUSTED, human_confirmable=False))
    e.register(ToolSpec(name="send_email", min_trust=TrustLevel.USER, human_confirmable=True))
    e.register(ToolSpec(name="execute_code", min_trust=TrustLevel.TRUSTED, human_confirmable=False))
    return e


class TestTrustLevelOrdering:
    def test_untrusted_lt_user(self) -> None:
        assert TrustLevel.UNTRUSTED < TrustLevel.USER

    def test_user_lt_trusted(self) -> None:
        assert TrustLevel.USER < TrustLevel.TRUSTED


class TestPolicyEngineEvaluate:
    def test_allow_when_provenance_meets_minimum(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "web_fetch", TrustLevel.UNTRUSTED)
        assert result.decision == Decision.ALLOW

    def test_allow_user_provenance_for_user_tool(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "send_email", TrustLevel.USER)
        assert result.decision == Decision.ALLOW

    def test_require_confirmation_for_untrusted_on_user_tool(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "send_email", TrustLevel.UNTRUSTED)
        assert result.decision == Decision.REQUIRE_CONFIRMATION

    def test_allow_with_confirmed_override(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "send_email", TrustLevel.UNTRUSTED, confirmed=True)
        assert result.decision == Decision.ALLOW

    def test_deny_non_confirmable_below_min_trust(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "execute_code", TrustLevel.USER)
        assert result.decision == Decision.DENY

    def test_deny_unknown_tool(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "nonexistent", TrustLevel.TRUSTED)
        assert result.decision == Decision.DENY
        assert "unknown tool" in result.reason

    def test_confirmed_true_does_not_override_non_confirmable(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "execute_code", TrustLevel.UNTRUSTED, confirmed=True)
        assert result.decision == Decision.DENY

    def test_returns_policy_decision(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "web_fetch", TrustLevel.UNTRUSTED)
        assert isinstance(result, PolicyDecision)

    def test_reason_non_empty(self, engine: PolicyEngine) -> None:
        result = engine.evaluate(SESSION, "send_email", TrustLevel.UNTRUSTED)
        assert result.reason != ""


class TestAuditLog:
    def test_audit_log_grows_with_each_call(self, engine: PolicyEngine) -> None:
        engine.evaluate(SESSION, "web_fetch", TrustLevel.UNTRUSTED)
        engine.evaluate(SESSION, "send_email", TrustLevel.USER)
        assert len(engine.audit_log) == 2

    def test_audit_event_fields(self, engine: PolicyEngine) -> None:
        engine.evaluate(SESSION, "send_email", TrustLevel.UNTRUSTED)
        event = engine.audit_log[-1]
        assert isinstance(event, AuditEvent)
        assert event.session_id == SESSION
        assert event.tool_name == "send_email"
        assert event.provenance == TrustLevel.UNTRUSTED
        assert event.decision == Decision.REQUIRE_CONFIRMATION

    def test_audit_event_to_dict_serializable(self, engine: PolicyEngine) -> None:
        engine.evaluate(SESSION, "web_fetch", TrustLevel.USER)
        d = engine.audit_log[-1].to_dict()
        # must round-trip through JSON without error
        assert json.loads(json.dumps(d)) == d

    def test_audit_event_to_dict_keys(self, engine: PolicyEngine) -> None:
        engine.evaluate(SESSION, "web_fetch", TrustLevel.USER)
        d = engine.audit_log[-1].to_dict()
        assert set(d.keys()) == {"session_id", "tool_name", "provenance", "decision", "reason"}

    def test_audit_event_provenance_lowercase(self, engine: PolicyEngine) -> None:
        engine.evaluate(SESSION, "web_fetch", TrustLevel.UNTRUSTED)
        d = engine.audit_log[-1].to_dict()
        assert d["provenance"] == "untrusted"


class TestAuditRegistry:
    def test_clean_registry_returns_empty(self) -> None:
        e = PolicyEngine()
        e.register(ToolSpec(name="send_email", min_trust=TrustLevel.USER, human_confirmable=True))
        e.register(
            ToolSpec(name="execute_code", min_trust=TrustLevel.TRUSTED, human_confirmable=False)
        )
        assert e.audit_registry() == []

    def test_misconfigured_tool_flagged(self) -> None:
        e = PolicyEngine()
        e.register(
            ToolSpec(name="dangerous", min_trust=TrustLevel.UNTRUSTED, human_confirmable=False)
        )
        findings = e.audit_registry()
        assert len(findings) == 1
        assert "dangerous" in findings[0]
        assert "UNTRUSTED" in findings[0]

    def test_user_min_trust_not_flagged(self) -> None:
        e = PolicyEngine()
        e.register(ToolSpec(name="safe", min_trust=TrustLevel.USER, human_confirmable=True))
        assert e.audit_registry() == []

    def test_multiple_misconfigured_tools_all_flagged(self) -> None:
        e = PolicyEngine()
        e.register(ToolSpec(name="a", min_trust=TrustLevel.UNTRUSTED))
        e.register(ToolSpec(name="b", min_trust=TrustLevel.UNTRUSTED))
        findings = e.audit_registry()
        assert len(findings) == 2
