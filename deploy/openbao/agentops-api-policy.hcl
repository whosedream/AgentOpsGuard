path "secret/data/agentops/*" {
  capabilities = ["create", "read", "update"]
}

path "transit/sign/agentops-audit" {
  capabilities = ["update"]
}

path "transit/keys/agentops-audit" {
  capabilities = ["read"]
}
