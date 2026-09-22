"""At-least-once handoff to the existing transaction/job/outbox chain, never tool I/O."""
from dataclasses import asdict
from datetime import timedelta
from hashlib import sha256
import json
import secrets
from types import SimpleNamespace

from cryptography.fernet import InvalidToken
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError, TimeoutError as DatabaseTimeoutError

from agentops_guard.admission.store import Entry, Grant, digest, now, utc
from agentops_guard.backend.database_resilience import database_unavailable
from agentops_guard.backend.models import ApiKey, ToolInvocation
from agentops_guard.backend.security.context import clear_auth_context, current_auth_context, set_auth_context
from agentops_guard.backend.services import tool_invocations as inv
from agentops_guard.gateway.auth import GatewayIdentity


def provision(store, business, *, key_id, tool_ids, lifetime_seconds=3600):
    """Operator-only: caller writes returned token straight into a private file."""
    if not tool_ids or not 60 <= lifetime_seconds <= 86400:
        raise ValueError("A bounded lifetime and explicit reviewed tools are required")
    old_auth = current_auth_context()
    try:
        business_url, admission_url = business.get_bind().url, store.engine.url
        if (business_url.get_backend_name() == admission_url.get_backend_name() == "postgresql"
                and (business_url.host, business_url.port or 5432)
                == (admission_url.host, admission_url.port or 5432)):
            raise ValueError("Admission storage must use a separate PostgreSQL endpoint")
        key = business.get(ApiKey, key_id)
        if key is None:
            raise ValueError("Business API key not found")
        identity = GatewayIdentity(key.project_id, "api_key", key.id, key.agent_id, None)
        subject = asdict(identity)
        bound = SimpleNamespace(subject=subject, project_id=key.project_id, actor_digest=digest(subject))
        inv.queued_identity(business, bound)
        tools = {}
        for tool_id in tool_ids:
            reviewed = SimpleNamespace(project_id=key.project_id, tool_id=tool_id,
                                       revision_digest=None, execution_policy_digest=None)
            inv._reviewed_policy(business, reviewed)
            tools[tool_id] = {"revision": reviewed.revision_digest, "policy": reviewed.execution_policy_digest}
        business.commit()
        token = "admission_" + secrets.token_urlsafe(32)
        with store.sessions() as db:
            # Provisioning is a serialized operator command, not a public endpoint.
            # Only one grant per actor, including revoked grants. Rotation of the
            # token preserves the grant and queued records, never creates a competing scope.
            existing = db.scalar(select(Grant).where(Grant.project_id == key.project_id,
                                                     Grant.actor_digest == digest(subject)))
            if existing is not None:
                raise ValueError("Grant already exists; revoke or rotate that grant explicitly")
            row = Grant(id="adg_" + secrets.token_hex(16), token_hash=sha256(token.encode()).hexdigest(),
                subject=subject, project_id=key.project_id, actor_digest=digest(subject), tools=tools,
                expires_at=now() + timedelta(seconds=lifetime_seconds))
            db.add(row)
            db.commit()
            return row.id, token
    finally:
        set_auth_context(old_auth) if old_auth is not None else clear_auth_context()


def handoff(store, business_sessions, claim, *, after_business_commit=None):
    """Recoverable even if the importer dies after business commit, before local ack."""
    old_auth = current_auth_context()
    try:
        with store.sessions() as local:
            row = local.get(Entry, claim[0])
            if row is None or row.lease_token != claim[1] or utc(row.lease_until) <= now():
                return False
            grant = local.get(Grant, row.grant_id)
            identity = GatewayIdentity(**grant.subject)
            if row.actor_digest != digest(grant.subject) or row.project_id != grant.project_id:
                raise ValueError("Admission identity integrity failure")
            binding = grant.tools[row.tool_id]
        with business_sessions() as db:
            # Query the original number BEFORE expiry/revocation handling. A prior
            # handoff may have committed even though the importer never saw its reply.
            existing = db.scalar(select(ToolInvocation).where(ToolInvocation.project_id == row.project_id,
                ToolInvocation.actor_digest == row.actor_digest, ToolInvocation.request_id == row.request_id))
            payload = None
            if row.encrypted_payload is not None:
                try:
                    envelope = json.loads(store.cipher.decrypt(row.encrypted_payload.encode()))
                except (InvalidToken, ValueError):
                    return store.finish(claim, state="rejected", reason="payload_integrity_failed", encrypted_payload=None)
                expected = {"id": row.id, "grant": grant.id, "project": row.project_id, "actor": row.actor_digest}
                if (not isinstance(envelope, dict) or any(envelope.get(k) != v for k, v in expected.items())
                        or digest(envelope.get("payload")) != row.payload_digest):
                    return store.finish(claim, state="rejected", reason="payload_binding_failed", encrypted_payload=None)
                payload = envelope["payload"]
            if existing is None:
                if row.business_id is not None:
                    return store.finish(claim, reason="business_record_unavailable")
                if utc(row.expires_at) <= now():
                    return store.finish(claim, state="expired", reason="not_imported_before_expiry", encrypted_payload=None)
                if payload is None:
                    return store.finish(claim, state="rejected", reason="payload_missing")
                identity = inv.queued_identity(db, SimpleNamespace(subject=grant.subject,
                    project_id=row.project_id, actor_digest=row.actor_digest))
                pinned = SimpleNamespace(project_id=row.project_id, tool_id=row.tool_id,
                    revision_digest=binding["revision"], execution_policy_digest=binding["policy"])
                inv._reviewed_policy(db, pinned)
                existing, _ = inv.register(db, payload, identity, queued=True,
                    expected_review=(binding["revision"], binding["policy"]))
                if after_business_commit is not None:
                    after_business_commit()  # Test injection only, never an HTTP option.
            else:
                # A matching number from another submission cannot silently become
                # our result. Recompute the digest when the encrypted input remains.
                if payload is not None:
                    stable = {k: v for k, v in payload.items() if k != "requestId"}
                    if existing.payload_digest != inv._digest(stable) or existing.mode != "queued":
                        return store.finish(claim, state="rejected", reason="business_request_conflict", encrypted_payload=None)
                elif existing.id != row.business_id:
                    raise ValueError("Business invocation identity changed")
            observed = inv.public_status(existing)["state"]
            # Unknown/confirmed/approval states stay polled: receipt recovery or
            # an operator can still change them. They are NOT full success.
            final = observed in {"succeeded", "failed", "expired", "not_dispatched"}
            return store.finish(claim, state="completed" if final else "imported", reason=None,
                business_id=existing.id, business_state=observed, business_observed_at=now(), encrypted_payload=None)
    except HTTPException as error:
        if error.status_code in {429, 502, 503}:
            return store.finish(claim, reason="business_temporarily_unavailable")
        if error.status_code in {400, 403, 404, 409, 410, 413}:
            return store.finish(claim, state="rejected", reason=f"business_admission_denied_{error.status_code}", encrypted_payload=None)
        raise
    except (DBAPIError, DatabaseTimeoutError) as error:
        if not database_unavailable(error):
            raise
        # Ambiguous business commit: leave accepted, preserve payload, retry ONLY
        # lookup/registration of the same number after connectivity returns.
        return store.finish(claim, reason="business_temporarily_unavailable")
    finally:
        set_auth_context(old_auth) if old_auth is not None else clear_auth_context()
