package agentops.guard

default decision := {
  "action": "allow",
  "reason_code": "opa_no_policy_violation",
  "severity": "low",
  "matched_policy": "opa:default_allow",
  "policy_revision": "agentops-guard-v1",
}

high_risk_tools := {
  "shell.execute",
  "terminal.run",
  "filesystem.write",
  "filesystem.delete",
  "database.write",
  "http.post",
  "slack.send",
  "feishu.send",
}

decision := {
  "action": "deny",
  "reason_code": "opa_hard_boundary",
  "severity": "critical",
  "matched_policy": "opa:hard_boundary",
  "policy_revision": "agentops-guard-v1",
} if {
  count(deny) > 0
}

decision := {
  "action": "require_approval",
  "reason_code": "opa_high_risk_action",
  "severity": "high",
  "matched_policy": "opa:high_risk_action",
  "policy_revision": "agentops-guard-v1",
} if {
  count(deny) == 0
  high_risk_tools[input.tool.name]
}

decision := {
  "action": "require_approval",
  "reason_code": "opa_high_risk_content",
  "severity": "high",
  "matched_policy": "opa:high_risk_content",
  "policy_revision": "agentops-guard-v1",
} if {
  count(deny) == 0
  not high_risk_tools[input.tool.name]
  input.risk_score >= 0.7
}
