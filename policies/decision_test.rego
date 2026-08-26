package agentops.guard

test_default_allow if {
  decision == {
    "action": "allow",
    "reason_code": "opa_no_policy_violation",
    "severity": "low",
    "matched_policy": "opa:default_allow",
    "policy_revision": "agentops-guard-v1",
  } with input as {"tool": {"name": "records.read"}, "risk_score": 0}
}

test_high_risk_tool_requires_approval if {
  decision == {
    "action": "require_approval",
    "reason_code": "opa_high_risk_action",
    "severity": "high",
    "matched_policy": "opa:high_risk_action",
    "policy_revision": "agentops-guard-v1",
  } with input as {"tool": {"name": "filesystem.write"}, "risk_score": 0}
}

test_dangerous_command_denied if {
  decision == {
    "action": "deny",
    "reason_code": "opa_hard_boundary",
    "severity": "critical",
    "matched_policy": "opa:hard_boundary",
    "policy_revision": "agentops-guard-v1",
  } with input as {
    "tool": {"name": "shell.execute", "command": "rm -rf /"},
    "risk_score": 0,
    "risk_labels": [],
  }
}
