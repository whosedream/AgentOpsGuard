path "auth/approle/role/agentops-audit-export/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/agentops-audit-export/secret-id" {
  capabilities = ["update"]
}
