from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy.orm import Session

from agentops_guard.backend.models import AuditCheckpoint
from agentops_guard.backend.services.audit_checkpoints import (
    AuditCheckpointUnavailable,
    AuditCheckpointIntegrity,
    OpenBaoTransitSigner,
    audit_checkpoint_payload,
    verify_audit_checkpoint,
)
from agentops_guard.backend.services.mcp_tool_revisions import canonical_json


class AuditAnchorUnavailable(RuntimeError):
    pass


class InvalidAuditCheckpoint(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditAnchorReceipt:
    payload_digest: str
    object_key: str
    version_id: str
    retain_until: datetime
    already_existed: bool


def public_checkpoint_bytes(row: AuditCheckpoint) -> bytes:
    payload = audit_checkpoint_payload(
        project_id=row.project_id,
        entry_id=row.entry_id,
        entry_hash=row.entry_hash,
        checked_entries=row.checked_entries,
        issued_at=row.issued_at,
    )
    if sha256(canonical_json(payload).encode("utf-8")).hexdigest() != row.payload_digest:
        raise InvalidAuditCheckpoint("audit checkpoint payload digest changed")
    envelope = {
        "schema": "agentops-audit-anchor/v1",
        "payload": payload,
        "payload_digest": row.payload_digest,
        "signer": row.signer,
        "key_name": row.key_name,
        "key_version": row.key_version,
        "signature": row.signature,
        "public_key": row.public_key,
    }
    return canonical_json(envelope).encode("utf-8")


class S3ObjectLockSink:
    """Store public audit checkpoints with S3 Object Lock COMPLIANCE retention."""

    def __init__(
        self,
        *,
        client: Any,
        bucket: str,
        prefix: str,
        retention_days: int,
        expected_bucket_owner: str | None = None,
    ) -> None:
        self._client = client
        self._bucket = bucket
        self._prefix = prefix.strip("/")
        self._retention_days = retention_days
        self._expected_bucket_owner = expected_bucket_owner

    def check_ready(self) -> None:
        parameters = self._bucket_parameters()
        try:
            versioning = self._client.get_bucket_versioning(**parameters)
            object_lock = self._client.get_object_lock_configuration(**parameters)
        except (BotoCoreError, ClientError) as exc:
            raise AuditAnchorUnavailable("audit anchor storage is unavailable") from exc
        if versioning.get("Status") != "Enabled":
            raise AuditAnchorUnavailable("audit anchor bucket versioning is not enabled")
        configuration = object_lock.get("ObjectLockConfiguration") or {}
        if configuration.get("ObjectLockEnabled") != "Enabled":
            raise AuditAnchorUnavailable("audit anchor bucket Object Lock is not enabled")

    def store(
        self,
        row: AuditCheckpoint,
        *,
        now: datetime | None = None,
    ) -> AuditAnchorReceipt:
        body = public_checkpoint_bytes(row)
        checksum = b64encode(sha256(body).digest()).decode("ascii")
        resolved_now = (now or datetime.now(UTC)).astimezone(UTC)
        retain_until = resolved_now + timedelta(days=self._retention_days)
        object_key = self._object_key(row)
        parameters: dict[str, Any] = {
            **self._bucket_parameters(),
            "Key": object_key,
            "Body": body,
            "ContentLength": len(body),
            "ContentType": "application/json",
            "ChecksumSHA256": checksum,
            "IfNoneMatch": "*",
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": retain_until,
        }
        already_existed = False
        try:
            response = self._client.put_object(**parameters)
            version_id = str(response.get("VersionId") or "")
        except ClientError as exc:
            if str(exc.response.get("Error", {}).get("Code")) not in {
                "PreconditionFailed",
                "412",
            }:
                raise AuditAnchorUnavailable("audit checkpoint upload failed") from exc
            already_existed = True
            version_id = self._existing_version_id(object_key)
        except BotoCoreError as exc:
            raise AuditAnchorUnavailable("audit checkpoint upload failed") from exc
        if not version_id:
            raise AuditAnchorUnavailable("audit anchor storage did not return an object version")

        stored_body, stored_checksum = self._read_back(object_key, version_id)
        if stored_body != body or (stored_checksum is not None and stored_checksum != checksum):
            raise AuditAnchorUnavailable("stored audit checkpoint content does not match")
        stored_retention = self._read_retention(object_key, version_id)
        minimum_retention = resolved_now if already_existed else retain_until
        if stored_retention[0] != "COMPLIANCE" or stored_retention[1] < minimum_retention:
            raise AuditAnchorUnavailable("stored audit checkpoint retention is insufficient")
        return AuditAnchorReceipt(
            payload_digest=row.payload_digest,
            object_key=object_key,
            version_id=version_id,
            retain_until=stored_retention[1],
            already_existed=already_existed,
        )

    def assert_database_history_is_not_behind(
        self,
        rows: list[AuditCheckpoint],
    ) -> None:
        expected_keys = {self._object_key(row) for row in rows}
        versions_by_key: dict[str, set[str]] = {}
        prefix = f"{self._prefix}/" if self._prefix else ""
        parameters: dict[str, str] = {**self._bucket_parameters(), "Prefix": prefix}
        try:
            paginator = self._client.get_paginator("list_object_versions")
            for page in paginator.paginate(**parameters):
                if page.get("DeleteMarkers"):
                    raise AuditAnchorUnavailable(
                        "audit anchor storage contains a deletion marker"
                    )
                for version in page.get("Versions", []):
                    key = str(version.get("Key") or "")
                    version_id = str(version.get("VersionId") or "")
                    if not key or not version_id:
                        raise AuditAnchorUnavailable(
                            "audit anchor storage returned an incomplete object version"
                        )
                    versions_by_key.setdefault(key, set()).add(version_id)
        except AuditAnchorUnavailable:
            raise
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as exc:
            raise AuditAnchorUnavailable("audit anchor history cannot be listed") from exc

        if set(versions_by_key) - expected_keys:
            raise AuditAnchorUnavailable(
                "external audit anchor history is ahead of the database"
            )
        if any(len(version_ids) != 1 for version_ids in versions_by_key.values()):
            raise AuditAnchorUnavailable("audit anchor object has unexpected versions")

    def _object_key(self, row: AuditCheckpoint) -> str:
        project_partition = sha256(row.project_id.encode("utf-8")).hexdigest()[:32]
        name = f"{project_partition}/{row.payload_digest}.json"
        return f"{self._prefix}/{name}" if self._prefix else name

    def _bucket_parameters(self) -> dict[str, str]:
        parameters = {"Bucket": self._bucket}
        if self._expected_bucket_owner:
            parameters["ExpectedBucketOwner"] = self._expected_bucket_owner
        return parameters

    def _existing_version_id(self, object_key: str) -> str:
        try:
            response = self._client.head_object(
                **self._bucket_parameters(), Key=object_key, ChecksumMode="ENABLED"
            )
        except (BotoCoreError, ClientError) as exc:
            raise AuditAnchorUnavailable("existing audit checkpoint cannot be inspected") from exc
        version_id = str(response.get("VersionId") or "")
        if not version_id:
            raise AuditAnchorUnavailable("existing audit checkpoint has no object version")
        return version_id

    def _read_back(self, object_key: str, version_id: str) -> tuple[bytes, str | None]:
        try:
            response = self._client.get_object(
                **self._bucket_parameters(),
                Key=object_key,
                VersionId=version_id,
                ChecksumMode="ENABLED",
            )
            body = response["Body"].read()
        except (BotoCoreError, ClientError, KeyError, OSError) as exc:
            raise AuditAnchorUnavailable("stored audit checkpoint cannot be read back") from exc
        return body, response.get("ChecksumSHA256")

    def _read_retention(self, object_key: str, version_id: str) -> tuple[str, datetime]:
        try:
            response = self._client.get_object_retention(
                **self._bucket_parameters(), Key=object_key, VersionId=version_id
            )
            retention = response["Retention"]
            mode = str(retention["Mode"])
            retain_until = retention["RetainUntilDate"].astimezone(UTC)
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as exc:
            raise AuditAnchorUnavailable("stored audit checkpoint retention cannot be verified") from exc
        return mode, retain_until


def export_audit_checkpoints(
    db: Session,
    *,
    sink: S3ObjectLockSink,
    signer: OpenBaoTransitSigner,
) -> list[AuditAnchorReceipt]:
    rows = db.query(AuditCheckpoint).order_by(AuditCheckpoint.issued_at.asc()).all()
    try:
        checked: list[tuple[AuditCheckpoint, AuditCheckpointIntegrity]] = [
            (row, verify_audit_checkpoint(db, row, signer=signer)) for row in rows
        ]
    except AuditCheckpointUnavailable as exc:
        raise AuditAnchorUnavailable("audit checkpoint key origin cannot be verified") from exc
    invalid = next((row for row, integrity in checked if not integrity.valid), None)
    if invalid is not None:
        raise InvalidAuditCheckpoint("audit checkpoint failed integrity verification")
    sink.check_ready()
    sink.assert_database_history_is_not_behind(rows)
    return [sink.store(row) for row, _integrity in checked]
