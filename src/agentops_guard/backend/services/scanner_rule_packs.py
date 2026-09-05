from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from sqlalchemy.orm import Session

from agentops_guard.backend.models import ScanRule
from agentops_guard.backend.services.audit import record_audit
from agentops_guard.backend.services.projects import ensure_project
from agentops_guard.backend.services.safe_regex import (
    MAX_CONFIGURABLE_PATTERN_CHARACTERS,
    SafeRegexError,
    compile_configurable_pattern,
)


MANAGED_SCAN_RULE_PREFIX = "managed_scan_"
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
REVISION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
MAX_PACK_BYTES = 128 * 1024
MAX_RULES = 32


class ScannerRulePackError(ValueError):
    pass


class ManagedScannerRuleImmutable(ScannerRulePackError):
    pass


@dataclass(frozen=True)
class ScannerRulePack:
    pack_id: str
    revision: str
    description: str
    provenance: dict[str, str]
    rules: tuple[dict[str, Any], ...]
    sha256: str


def is_managed_scan_rule_id(rule_id: str) -> bool:
    return rule_id.startswith(MANAGED_SCAN_RULE_PREFIX)


def _strict_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        raise ScannerRulePackError(f"{context} fields do not match schema")


def load_scanner_rule_pack(path: Path) -> ScannerRulePack:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.stat().st_size > MAX_PACK_BYTES:
        raise ScannerRulePackError("scanner rule pack must be a bounded regular file")
    raw = resolved.read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerRulePackError("scanner rule pack must be UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ScannerRulePackError("scanner rule pack root must be an object")
    _strict_keys(
        payload,
        {"schema_version", "pack_id", "revision", "description", "provenance", "rules"},
        "scanner rule pack",
    )
    pack_id = payload["pack_id"]
    revision = payload["revision"]
    description = payload["description"]
    provenance = payload["provenance"]
    rules = payload["rules"]
    if payload["schema_version"] != 1:
        raise ScannerRulePackError("unsupported scanner rule pack schema")
    if not isinstance(pack_id, str) or IDENTIFIER_PATTERN.fullmatch(pack_id) is None:
        raise ScannerRulePackError("scanner rule pack id is invalid")
    if not isinstance(revision, str) or REVISION_PATTERN.fullmatch(revision) is None:
        raise ScannerRulePackError("scanner rule pack revision is invalid")
    if not isinstance(description, str) or not description or len(description) > 500:
        raise ScannerRulePackError("scanner rule pack description is invalid")
    if not isinstance(provenance, dict):
        raise ScannerRulePackError("scanner rule pack provenance is invalid")
    _strict_keys(
        provenance,
        {"package", "package_version", "benchmark_version", "license", "source"},
        "scanner rule pack provenance",
    )
    if not all(isinstance(value, str) and 0 < len(value) <= 500 for value in provenance.values()):
        raise ScannerRulePackError("scanner rule pack provenance values are invalid")
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise ScannerRulePackError("scanner rule pack rules are invalid")
    validated_rules: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ScannerRulePackError("scanner rule must be an object")
        _strict_keys(
            rule,
            {"rule_id", "label", "pattern", "severity", "score", "description"},
            "scanner rule",
        )
        rule_id = rule["rule_id"]
        label = rule["label"]
        pattern = rule["pattern"]
        severity = rule["severity"]
        score = rule["score"]
        rule_description = rule["description"]
        if (
            not isinstance(rule_id, str)
            or IDENTIFIER_PATTERN.fullmatch(rule_id) is None
            or rule_id in rule_ids
        ):
            raise ScannerRulePackError("scanner rule id is invalid or duplicated")
        if not isinstance(label, str) or IDENTIFIER_PATTERN.fullmatch(label.replace("_", "-")) is None:
            raise ScannerRulePackError("scanner rule label is invalid")
        if (
            not isinstance(pattern, str)
            or not 1 <= len(pattern) <= MAX_CONFIGURABLE_PATTERN_CHARACTERS
        ):
            raise ScannerRulePackError("scanner rule pattern is invalid")
        try:
            compile_configurable_pattern(pattern)
        except SafeRegexError as exc:
            raise ScannerRulePackError("scanner rule pattern is not supported by RE2") from exc
        if severity not in SEVERITIES:
            raise ScannerRulePackError("scanner rule severity is invalid")
        if not isinstance(score, int | float) or isinstance(score, bool) or not 0 <= score <= 1:
            raise ScannerRulePackError("scanner rule score is invalid")
        if (
            not isinstance(rule_description, str)
            or not rule_description
            or len(rule_description) > 500
        ):
            raise ScannerRulePackError("scanner rule description is invalid")
        rule_ids.add(rule_id)
        validated_rules.append(dict(rule))
    return ScannerRulePack(
        pack_id=pack_id,
        revision=revision,
        description=description,
        provenance=dict(provenance),
        rules=tuple(validated_rules),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _managed_rule_id(project_id: str, pack: ScannerRulePack, rule_id: str) -> str:
    identity = "\0".join((project_id, pack.pack_id, pack.revision, rule_id)).encode("utf-8")
    return MANAGED_SCAN_RULE_PREFIX + hashlib.sha256(identity).hexdigest()[:40]


def _managed_description(pack: ScannerRulePack, rule: dict[str, Any]) -> str:
    return json.dumps(
        {
            "managed_pack": pack.pack_id,
            "pack_sha256": pack.sha256,
            "revision": pack.revision,
            "rule_description": rule["description"],
            "rule_id": rule["rule_id"],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def install_scanner_rule_pack(
    db: Session,
    *,
    project_id: str,
    path: Path,
) -> dict[str, Any]:
    pack = load_scanner_rule_pack(path)
    ensure_project(db, project_id)
    installed = 0
    unchanged = 0
    rule_ids = []
    for rule in pack.rules:
        rule_id = _managed_rule_id(project_id, pack, rule["rule_id"])
        rule_ids.append(rule_id)
        description = _managed_description(pack, rule)
        expected = {
            "project_id": project_id,
            "label": rule["label"],
            "pattern": rule["pattern"],
            "severity": rule["severity"],
            "score": float(rule["score"]),
            "status": "enabled",
            "description": description,
        }
        existing = db.get(ScanRule, rule_id)
        if existing is not None:
            actual = {name: getattr(existing, name) for name in expected}
            if actual != expected:
                raise ManagedScannerRuleImmutable(
                    "installed managed scanner rule differs from the reviewed pack"
                )
            unchanged += 1
            continue
        row = ScanRule(id=rule_id, **expected)
        db.add(row)
        db.flush()
        record_audit(
            db,
            project_id=project_id,
            action="scanner_rule_pack.install",
            resource_type="scan_rule",
            resource_id=rule_id,
            after={
                "label": rule["label"],
                "pack_id": pack.pack_id,
                "pack_sha256": pack.sha256,
                "revision": pack.revision,
                "status": "enabled",
            },
        )
        installed += 1
    return {
        "pack_id": pack.pack_id,
        "revision": pack.revision,
        "pack_sha256": pack.sha256,
        "installed": installed,
        "unchanged": unchanged,
        "rule_ids": rule_ids,
    }
