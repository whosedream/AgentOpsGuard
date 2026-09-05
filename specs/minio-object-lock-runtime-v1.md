# MinIO Object Lock Runtime Verification v1

## Scope

This local subsystem check runs a real S3-compatible server and exercises the existing
`S3ObjectLockSink` against actual Object Lock and versioning behavior. It proves that the application
contract uses an immutable object version, enforces `COMPLIANCE` retention, rejects duplicate writes
and detects unexpected version history.

It does not claim an external or production storage service. The open-source MinIO repository was
archived in 2026 and its last community binary is no longer maintained, so this runtime is only a
local S3 Object Lock compatibility fixture. Production must use the organization's supported object
storage service or another actively maintained approved implementation.

## Reviewed runtime

- Upstream archive: <https://dl.min.io/server/minio/release/linux-amd64/archive/>
- Release: `RELEASE.2025-09-07T16-13-09Z`
- Binary SHA-256:
  `7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f`
- Minisign file SHA-256:
  `d71cf680e1de21ae4a71d8d6ff2c80d6f8b07cbe8a9e00e157ef40be213fd47f`
- Public key: the key fixed in MinIO's upstream release Dockerfile

`scripts/install_minio_object_lock_runtime.py` validates the exact checksum file, parses the Minisign
format, requires the prehashed `ED` algorithm, matches the key ID and trusted release comment, verifies
both the BLAKE2b-512 payload signature and trusted-comment signature, checks version/platform, and
installs the binary atomically outside Git with mode `0500`.

## Real flow

`scripts/verify_minio_object_lock.py`:

1. repeats the runtime digest, Minisign, version and platform checks;
2. generates temporary administrator credentials only inside the trusted verifier process;
3. starts MinIO as the non-root current user with API and console listeners bound to loopback;
4. creates a bucket with versioning and Object Lock enabled;
5. writes one public audit-checkpoint envelope through the production `S3ObjectLockSink`, using
   SHA-256, `If-None-Match: *`, an immutable version ID and one-day `COMPLIANCE` retention;
6. repeats the write and requires reuse of the original version rather than a second version;
7. reads the exact stored version and checks its bytes and retention;
8. uses the temporary administrator identity to attempt exact-version deletion and retention
   shortening, requiring both operations to fail;
9. lists history and requires exactly one version with no delete marker;
10. stops the server and deletes its temporary data, configuration and credentials.

Credentials are process-local environment values. They do not enter commands, URLs, model/tool
parameters, stdout, stderr, reports or repository files. The aggregate result contains only fixed
version text and booleans.

## Observed result

- binary digest, version, platform and Minisign: pass;
- versioning and Object Lock enabled: pass;
- exact-version read-back and COMPLIANCE retention: pass;
- duplicate conditional write reused the original version: pass;
- administrator exact-version deletion: rejected;
- administrator retention shortening: rejected;
- unexpected versions and delete markers: absent;
- non-root process and loopback listeners: pass.

## Remaining production gate

The external append-only audit checkpoint gate remains open until the same exporter runs against the
target enterprise service with TLS and workload identity, independent account and administrative
boundaries, approved retention policy, multi-node or provider durability, operational alerting, and
a database rollback drill that is caught by the external history.
