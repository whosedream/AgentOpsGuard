path "auth/approle/role/agentops-api/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/agentops-api/secret-id" {
  capabilities = ["update"]
}
