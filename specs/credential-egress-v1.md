# Managed credential egress v1

## Protected value

This contract protects a provider credential submitted through the administrative credential
endpoint. It does not claim that arbitrary strings can be recognized as secrets without first
being registered.

## Required flow

1. Only an operator or active project administrator may submit or rotate the provider credential.
2. Storage contains encrypted ciphertext and an encrypted binding; the API returns only a random
   `credential_ref` that is not derived from the secret.
3. The agent request accepts the reference and model content, but no raw secret, destination,
   header, or caller-supplied identity.
4. Authorization binds the reference to the project, authenticated actor, provider, action, fixed
   origin, status, and version before decryption.
5. Invocation, rotation, and revocation serialize on the credential row.
6. Only the trusted DeepSeek transport decrypts the credential. It rejects the managed secret in
   the model body, sends it only in the final `Authorization` header to the fixed HTTPS endpoint,
   follows no redirect, and rejects a provider response containing the managed secret.
7. Responses, validation errors, audit records, request logs, benchmark artifacts, and model
   messages never contain the managed secret.

## Acceptance evidence

- create, rotate, revoke, wrong scope, wrong actor, cross-project, disabled administrator, unknown
  reference, corrupted vault, tampered metadata, and swapped ciphertext tests;
- one mocked outbound request proving the only plaintext occurrence is its final authentication
  header;
- zero outbound requests for every rejected case;
- migration from revision `0004_identity_rbac` and rendered Helm output proving only the API
  workload receives the encryption key;
- repository search proving the removed MiMo and synthetic-runner paths no longer read provider
  API-key environment variables or call provider SDKs directly.

## Limits

Fernet protects a database-only disclosure and detects partial row tampering. It does not protect
against compromise of the API process, host, encryption-key store, or a complete database rollback.
Use a managed Vault or KMS-backed implementation when those threats are in scope. Local Compose is
development-only. The concurrent revocation guarantee relies on PostgreSQL row locks; SQLite is
only a single-process development and test path.
