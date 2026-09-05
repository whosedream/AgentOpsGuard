from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import BytesIO
import json

import boto3
from botocore.response import StreamingBody
from botocore.exceptions import ClientError
from botocore.stub import Stubber
import pytest

from agentops_guard.backend.config import Settings
from agentops_guard.backend.models import AuditCheckpoint
from agentops_guard.backend.services.audit_anchors import (
    AuditAnchorUnavailable,
    InvalidAuditCheckpoint,
    S3ObjectLockSink,
    export_audit_checkpoints,
    public_checkpoint_bytes,
)
from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    AuditCheckpointIntegrity,
    audit_checkpoint_payload,
)
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json


def _checkpoint() -> AuditCheckpoint:
    issued_at = datetime(2026, 9, 4, 0, 0, tzinfo=UTC)
    payload = audit_checkpoint_payload(
        project_id="enterprise-project",
        entry_id="audit_entry_1",
        entry_hash="a" * 64,
        checked_entries=7,
        issued_at=issued_at,
    )
    return AuditCheckpoint(
        id="checkpoint_1",
        project_id="enterprise-project",
        entry_id="audit_entry_1",
        entry_hash="a" * 64,
        checked_entries=7,
        payload_digest=sha256(canonical_json(payload).encode("utf-8")).hexdigest(),
        signer="openbao-transit-ed25519",
        key_name="agentops-audit",
        key_version=3,
        signature="vault:v3:dGVzdA==",
        public_key="public verification material",
        issued_at=issued_at,
        created_at=issued_at,
    )


def test_s3_anchor_settings_require_signed_checkpoints_and_credential_free_https():
    with pytest.raises(ValueError, match="OpenBao-signed"):
        Settings(
            _env_file=None,
            audit_anchor_backend="s3_object_lock",
            audit_anchor_s3_bucket="audit-lock",
        )

    with pytest.raises(ValueError, match="credential-free base URL"):
        Settings(
            _env_file=None,
            audit_checkpoint_backend="openbao",
            openbao_url="https://openbao.test",
            openbao_token="test-only",
            audit_anchor_backend="s3_object_lock",
            audit_anchor_s3_bucket="audit-lock",
            audit_anchor_s3_endpoint_url="https://user:secret@s3.test?token=value",
        )

    settings = Settings(
        _env_file=None,
        env="prod",
            component="audit_anchor_exporter",
            allow_schema_bootstrap=False,
            audit_checkpoint_backend="openbao",
            openbao_url="http://127.0.0.1:8100",
            openbao_auth_method="proxy",
        audit_anchor_backend="s3_object_lock",
        audit_anchor_s3_bucket="audit-lock",
        audit_anchor_s3_endpoint_url="https://s3.test",
        audit_anchor_s3_expected_bucket_owner="123456789012",
    )
    assert settings.api_key == "dev-agentops-key"
    assert settings.operator_api_key is None


def test_public_checkpoint_envelope_contains_no_audit_or_request_body():
    body = json.loads(public_checkpoint_bytes(_checkpoint()))

    assert body["schema"] == "agentops-audit-anchor/v1"
    assert set(body) == {
        "schema",
        "payload",
        "payload_digest",
        "signer",
        "key_name",
        "key_version",
        "signature",
        "public_key",
    }
    assert "before" not in body
    assert "after" not in body
    assert "metadata" not in body


def test_s3_sink_uses_compliance_lock_checksum_and_reads_back_exact_version():
    row = _checkpoint()
    now = datetime(2026, 9, 4, 1, 0, tzinfo=UTC)
    retain_until = now + timedelta(days=2555)
    body = public_checkpoint_bytes(row)
    checksum = b64encode(sha256(body).digest()).decode("ascii")
    project_partition = sha256(row.project_id.encode("utf-8")).hexdigest()[:32]
    key = f"anchors/{project_partition}/{row.payload_digest}.json"
    client = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="non-secret-test-id",
        aws_secret_access_key="non-secret-test-key",
    )
    stubber = Stubber(client)
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Enabled"},
        {"Bucket": "audit-lock", "ExpectedBucketOwner": "123456789012"},
    )
    stubber.add_response(
        "get_object_lock_configuration",
        {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}},
        {"Bucket": "audit-lock", "ExpectedBucketOwner": "123456789012"},
    )
    stubber.add_response(
        "put_object",
        {"VersionId": "version-1", "ChecksumSHA256": checksum},
        {
            "Bucket": "audit-lock",
            "ExpectedBucketOwner": "123456789012",
            "Key": key,
            "Body": body,
            "ContentLength": len(body),
            "ContentType": "application/json",
            "ChecksumSHA256": checksum,
            "IfNoneMatch": "*",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": retain_until,
        },
    )
    stubber.add_response(
        "get_object",
        {
            "Body": StreamingBody(BytesIO(body), len(body)),
            "ChecksumSHA256": checksum,
            "VersionId": "version-1",
        },
        {
            "Bucket": "audit-lock",
            "ExpectedBucketOwner": "123456789012",
            "Key": key,
            "VersionId": "version-1",
            "ChecksumMode": "ENABLED",
        },
    )
    stubber.add_response(
        "get_object_retention",
        {"Retention": {"Mode": "COMPLIANCE", "RetainUntilDate": retain_until}},
        {
            "Bucket": "audit-lock",
            "ExpectedBucketOwner": "123456789012",
            "Key": key,
            "VersionId": "version-1",
        },
    )

    with stubber:
        sink = S3ObjectLockSink(
            client=client,
            bucket="audit-lock",
            prefix="anchors",
            retention_days=2555,
            expected_bucket_owner="123456789012",
        )
        sink.check_ready()
        receipt = sink.store(row, now=now)

    assert receipt.object_key == key
    assert receipt.version_id == "version-1"
    assert receipt.retain_until == retain_until
    assert receipt.already_existed is False
    stubber.assert_no_pending_responses()


def test_export_validates_every_checkpoint_before_contacting_storage(monkeypatch):
    rows = [_checkpoint()]

    class Query:
        def order_by(self, _column):
            return self

        def all(self):
            return rows

    class Database:
        def query(self, _model):
            return Query()

    class Sink:
        contacted = False

        def check_ready(self):
            self.contacted = True

        def store(self, _row):
            self.contacted = True

    monkeypatch.setattr(
        "agentops_guard.backend.services.audit_anchors.verify_audit_checkpoint",
        lambda *_args, **_kwargs: AuditCheckpointIntegrity(
            valid=False,
            signature_valid=False,
            chain_prefix_valid=False,
            reason="checkpoint_signature_invalid",
        ),
    )
    sink = Sink()

    with pytest.raises(InvalidAuditCheckpoint):
        export_audit_checkpoints(Database(), sink=sink, signer=object())

    assert sink.contacted is False


def test_repeated_export_reuses_and_verifies_the_existing_locked_version():
    row = _checkpoint()
    body = public_checkpoint_bytes(row)
    checksum = b64encode(sha256(body).digest()).decode("ascii")
    now = datetime(2026, 9, 4, 1, 0, tzinfo=UTC)

    class ExistingObjectClient:
        def put_object(self, **_parameters):
            raise ClientError(
                {"Error": {"Code": "PreconditionFailed", "Message": "already exists"}},
                "PutObject",
            )

        def head_object(self, **_parameters):
            return {"VersionId": "existing-version"}

        def get_object(self, **_parameters):
            return {
                "Body": StreamingBody(BytesIO(body), len(body)),
                "ChecksumSHA256": checksum,
            }

        def get_object_retention(self, **_parameters):
            return {
                "Retention": {
                    "Mode": "COMPLIANCE",
                    "RetainUntilDate": now + timedelta(days=1),
                }
            }

    sink = S3ObjectLockSink(
        client=ExistingObjectClient(),
        bucket="audit-lock",
        prefix="anchors",
        retention_days=2555,
    )
    receipt = sink.store(row, now=now)

    assert receipt.version_id == "existing-version"
    assert receipt.already_existed is True


@pytest.mark.parametrize(
    "page",
    [
        {"Versions": [{"Key": "anchors/unknown/history.json", "VersionId": "v1"}]},
        {"DeleteMarkers": [{"Key": "anchors/unknown/history.json", "VersionId": "delete-v1"}]},
    ],
)
def test_external_history_or_delete_marker_rejects_database_rollback(page):
    class Paginator:
        def paginate(self, **parameters):
            assert parameters == {"Bucket": "audit-lock", "Prefix": "anchors/"}
            return [page]

    class Client:
        def get_paginator(self, operation):
            assert operation == "list_object_versions"
            return Paginator()

    sink = S3ObjectLockSink(
        client=Client(),
        bucket="audit-lock",
        prefix="anchors",
        retention_days=2555,
    )

    with pytest.raises(AuditAnchorUnavailable):
        sink.assert_database_history_is_not_behind([_checkpoint()])


def test_export_fails_closed_when_openbao_key_origin_is_unavailable(monkeypatch):
    class Query:
        def order_by(self, _column):
            return self

        def all(self):
            return [_checkpoint()]

    class Database:
        def query(self, _model):
            return Query()

    class Sink:
        contacted = False

        def check_ready(self):
            self.contacted = True

    def unavailable(*_args, **_kwargs):
        raise AuditCheckpointUnavailable("unavailable")

    monkeypatch.setattr(
        "agentops_guard.backend.services.audit_anchors.verify_audit_checkpoint", unavailable
    )
    sink = Sink()

    with pytest.raises(AuditAnchorUnavailable, match="key origin"):
        export_audit_checkpoints(Database(), sink=sink, signer=object())

    assert sink.contacted is False
