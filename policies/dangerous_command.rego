package agentops.guard

default allow := true

deny contains "dangerous_command" if {
  input.tool.name == "shell.execute"
  contains(lower(input.tool.command), "rm -rf /")
}

deny contains "data_exfiltration" if {
  some label in input.risk_labels
  label == "credential_exfiltration"
}
