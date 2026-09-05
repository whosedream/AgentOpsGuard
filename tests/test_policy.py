from types import SimpleNamespace

from agentops_guard.backend.schemas import PolicyContext, PolicyDecisionOut
from agentops_guard.backend.services import policy as policy_service
from agentops_guard.backend.services.policy import (
    assess_tool_action_alignment,
    build_user_intent_manifest,
    evaluate_builtin_policy,
    evaluate_policy,
)


def test_policy_denies_dangerous_command():
    decision = evaluate_policy(
        PolicyContext(
            actor={"agent_id": "coding-agent"},
            tool={"name": "shell.execute", "command": "rm -rf /"},
        )
    )
    assert decision.action == "deny"
    assert decision.reason_code == "dangerous_command"


def test_policy_denies_data_exfiltration():
    decision = evaluate_policy(
        PolicyContext(
            tool={"name": "http.post"},
            risk_score=0.95,
            risk_labels=["credential_exfiltration"],
            data={"labels": ["credential_exfiltration"]},
        )
    )
    assert decision.action == "deny"
    assert decision.reason_code == "data_exfiltration"


def test_policy_requires_approval_for_high_risk_tool():
    decision = evaluate_policy(PolicyContext(tool={"name": "filesystem.write"}))
    assert decision.action == "require_approval"


def test_action_alignment_boundary_cannot_be_overridden_by_opa(monkeypatch):
    monkeypatch.setattr(
        policy_service,
        "_evaluate_opa",
        lambda _context: PolicyDecisionOut(action="allow", reason_code="configured_allow"),
    )

    decision = evaluate_policy(
        PolicyContext(
            tool={"name": "mail.send"},
            data={
                "action_alignment": {
                    "required": True,
                    "intent_present": True,
                    "action_aligned": True,
                    "target_aligned": False,
                    "aligned": False,
                }
            },
        )
    )

    assert decision.action == "require_approval"
    assert decision.reason_code == "tool_target_not_authorized"


def test_opa_allow_cannot_lower_builtin_approval(monkeypatch):
    monkeypatch.setattr(
        policy_service,
        "get_settings",
        lambda: SimpleNamespace(opa_url="http://opa.test", policy_fail_mode="closed_for_high_risk"),
    )
    monkeypatch.setattr(
        policy_service,
        "evaluate_opa",
        lambda _input: {"action": "allow", "policy_revision": "test-v1"},
    )

    decision = evaluate_policy(PolicyContext(tool={"name": "filesystem.write"}))

    assert decision.action == "require_approval"
    assert decision.matched_policy == "approval"


def test_opa_deny_overrides_builtin_allow_and_records_provider(monkeypatch):
    monkeypatch.setattr(
        policy_service,
        "get_settings",
        lambda: SimpleNamespace(opa_url="http://opa.test", policy_fail_mode="closed_for_high_risk"),
    )
    monkeypatch.setattr(
        policy_service,
        "evaluate_opa",
        lambda _input: {
            "action": "deny",
            "reason_code": "project_policy",
            "matched_policy": "opa:project_policy",
            "policy_revision": "test-v2",
            "bundle_revision": "bundle-sha256:abc123",
        },
    )

    decision = evaluate_policy(PolicyContext(tool={"name": "records.read"}))

    assert decision.action == "deny"
    assert decision.context["policy_provider"] == "opa"
    assert decision.context["policy_revision"] == "test-v2"
    assert decision.context["opa_bundle_revision"] == "bundle-sha256:abc123"


def test_opa_never_receives_detectable_secrets(monkeypatch):
    canary = "sk-abcdefghijklmnopqrstuvwxyz123456"
    captured: dict = {}
    monkeypatch.setattr(
        policy_service,
        "get_settings",
        lambda: SimpleNamespace(opa_url="http://opa.test", policy_fail_mode="closed_for_high_risk"),
    )

    def fake_opa(input_document):
        captured.update(input_document)
        return {"action": "deny", "reason_code": "project_policy"}

    monkeypatch.setattr(policy_service, "evaluate_opa", fake_opa)

    decision = evaluate_policy(
        PolicyContext(tool={"name": "records.read", "args": {"token": canary}})
    )

    assert canary not in str(captured)
    assert canary not in str(decision.model_dump())


def test_opa_failure_requires_approval_for_risky_context(monkeypatch):
    monkeypatch.setattr(
        policy_service,
        "get_settings",
        lambda: SimpleNamespace(opa_url="http://opa.test", policy_fail_mode="closed_for_high_risk"),
    )
    monkeypatch.setattr(
        policy_service,
        "evaluate_opa",
        lambda _input: (_ for _ in ()).throw(policy_service.OpaUnavailable("offline")),
    )

    decision = evaluate_policy(PolicyContext(tool={"name": "records.read"}, risk_score=0.5))

    assert decision.action == "require_approval"
    assert decision.reason_code == "opa_unavailable"


def test_opa_failure_allows_local_low_risk_policy(monkeypatch):
    monkeypatch.setattr(
        policy_service,
        "get_settings",
        lambda: SimpleNamespace(opa_url="http://opa.test", policy_fail_mode="closed_for_high_risk"),
    )
    monkeypatch.setattr(
        policy_service,
        "evaluate_opa",
        lambda _input: (_ for _ in ()).throw(policy_service.OpaUnavailable("offline")),
    )

    decision = evaluate_policy(PolicyContext(tool={"name": "records.read"}))

    assert decision.action == "allow"


def test_normal_reference_to_email_does_not_authorize_sending():
    manifest = build_user_intent_manifest("Summarize this email from finance@example.com")

    alignment = assess_tool_action_alignment(
        "mail.send",
        {"recipient": "finance@example.com"},
        {},
        manifest,
    )

    assert alignment["action_aligned"] is False
    assert alignment["aligned"] is False


def test_email_categorization_scope_authorizes_requested_batch_mutation():
    manifest = build_user_intent_manifest("Categorize every email in the inbox.")

    alignment = assess_tool_action_alignment(
        "write_action",
        {
            "source_tool": "categorize_email",
            "arguments": {"email_index": 3, "category": "important"},
        },
        {},
        manifest,
    )

    assert manifest["actions"] == ["write"]
    assert manifest["target_scopes"] == ["email"]
    assert alignment["target_scopes"] == ["email"]
    assert alignment["aligned"] is True


def test_risky_untrusted_content_can_only_raise_a_mutation_to_approval():
    decision = evaluate_policy(
        PolicyContext(
            tool={"name": "write_action"},
            data={
                "untrusted_content_risk": True,
                "action_alignment": {
                    "required": True,
                    "intent_present": True,
                    "action_aligned": True,
                    "target_aligned": True,
                    "aligned": True,
                },
            },
        )
    )

    assert decision.action == "require_approval"
    assert decision.reason_code == "untrusted_content_influenced_mutation"


def test_mutating_tool_name_categories_require_trusted_intent():
    cases = {
        "records.update": "write",
        "records.delete": "delete",
        "billing.pay": "payment",
        "access.grant": "permission",
    }

    for tool_name, expected_action in cases.items():
        alignment = assess_tool_action_alignment(tool_name, {}, {}, None)
        decision = evaluate_policy(
            PolicyContext(tool={"name": tool_name}, data={"action_alignment": alignment})
        )

        assert alignment["action"] == expected_action
        assert decision.action == "require_approval"
        assert decision.reason_code == "trusted_user_intent_required"


def test_combined_mutating_tool_requires_every_action_to_be_authorized():
    manifest = build_user_intent_manifest("Delete record customer-17")

    alignment = assess_tool_action_alignment(
        "records.delete_and_send",
        {"record_id": "customer-17"},
        {},
        manifest,
    )

    assert alignment["actions"] == ["delete", "send"]
    assert alignment["action_aligned"] is False
    assert alignment["aligned"] is False


def test_unrecognized_mutating_argument_cannot_bypass_target_alignment():
    manifest = build_user_intent_manifest("Send the report to finance@example.com")

    alignment = assess_tool_action_alignment(
        "mail.send",
        {"x": "attacker@example.com"},
        {},
        manifest,
    )

    assert alignment["target_fields"] == []
    assert alignment["target_aligned"] is False
    assert alignment["aligned"] is False


def test_semantic_signal_can_only_raise_builtin_decision_to_approval():
    decision = evaluate_builtin_policy(
        PolicyContext(
            risk_score=0.8,
            risk_labels=["semantic_prompt_injection"],
            data={"labels": ["semantic_prompt_injection"]},
        )
    )

    assert decision.action == "require_approval"
    assert decision.reason_code == "high_risk_tool_or_content"
