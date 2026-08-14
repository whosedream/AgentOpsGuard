import base64
import binascii
import importlib
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agentops_guard.backend.config import get_settings
from agentops_guard.backend.models import RiskEvent, ScanRule
from agentops_guard.backend.schemas import ContentIn, EvidenceSpan, ScanRequest, ScanResponse
from agentops_guard.backend.services.content import (
    SECRET_PATTERNS,
    detect_secret_labels,
    new_id,
    persist_content,
    redact_text,
)


@dataclass(frozen=True)
class ScannerRule:
    label: str
    pattern: re.Pattern[str]
    severity: str
    score: float
    untrusted_only: bool = False


@dataclass(frozen=True)
class ScannerFinding:
    label: str
    severity: str
    score: float
    start: int
    end: int
    snippet: str


class ScannerProvider:
    def scan(
        self,
        request: ScanRequest,
        texts: list[tuple[str, int]],
        db: Session | None = None,
    ) -> list[ScannerFinding]:
        raise NotImplementedError


class RegexScannerProvider(ScannerProvider):
    def __init__(
        self,
        rules: list[ScannerRule],
        decoded_spans: list[tuple[int, int]] | None = None,
    ) -> None:
        self.rules = rules
        self.decoded_spans = decoded_spans or []

    def scan(
        self,
        request: ScanRequest,
        texts: list[tuple[str, int]],
        db: Session | None = None,
    ) -> list[ScannerFinding]:
        findings: list[ScannerFinding] = []
        seen: set[tuple[str, int, int]] = set()
        decoded_index = 0
        for text, offset_base in texts:
            source_span = None
            if offset_base < 0:
                source_span = self.decoded_spans[decoded_index]
                decoded_index += 1
            for rule in self.rules:
                if rule.untrusted_only and request.source in TRUSTED_SOURCES:
                    continue
                for match in rule.pattern.finditer(text):
                    start, end = source_span or (
                        match.start() + offset_base,
                        match.end() + offset_base,
                    )
                    identity = (rule.label, start, end)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    findings.append(
                        ScannerFinding(
                            label=rule.label,
                            severity=rule.severity,
                            score=rule.score,
                            start=start,
                            end=end,
                            snippet=(
                                "[REDACTED:base64_obfuscation]"
                                if source_span is not None
                                else match.group(0)[:160]
                            ),
                        )
                    )
        return findings


TRUSTED_SOURCES = {"user_input"}

EXTERNAL_ACTION = (
    r"(?:update|add|send|adjust|create|submit|set|cancel|increase|reduce|"
    r"clear|change|flag|process|schedule|move|reschedule|place)"
)
EXTERNAL_SEPARATOR = r"[\s,:;.!?-]{0,32}"

RULES = [
    ScannerRule(
        "instruction_override",
        re.compile(r"ignore (?:all )?(?:previous|above|prior) instructions", re.I),
        "high",
        0.75,
    ),
    ScannerRule(
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|skip|discard|bypass)\b"
            r"\s+(?:all\s+)?(?:the\s+)?"
            r"(?:previous|above|prior|earlier|preceding)\s+"
            r"(?:instructions|directives|rules|guidelines|constraints|orders)\b",
            re.I,
        ),
        "high",
        0.8,
        untrusted_only=True,
    ),
    ScannerRule(
        "instruction_override",
        re.compile(
            r"\bpriority\s+message\b.{0,160}"
            r"\bforgot\s+to\s+mention\s+earlier\b.{0,160}"
            r"\bbefore\s+finishing\b.{0,160}"
            r"\bplease\s+first\b"
            + EXTERNAL_SEPARATOR
            + EXTERNAL_ACTION
            + r"\b(?=.{1,512}\bthen\s+continue\s+with\s+the\s+original\s+request\b)",
            re.I | re.S,
        ),
        "high",
        0.8,
        untrusted_only=True,
    ),
    ScannerRule(
        "instruction_override",
        re.compile(
            r"\burgent\b.{0,100}"
            r"\bbefore\s+completing\s+any\s+other\s+tasks\b.{0,100}"
            r"\byou\s+must\b"
            + EXTERNAL_SEPARATOR
            + EXTERNAL_ACTION
            + r"\b(?=.{1,512}\bcritical\s+priority\b)",
            re.I | re.S,
        ),
        "high",
        0.8,
        untrusted_only=True,
    ),
    ScannerRule(
        "system_prompt_override",
        re.compile(
            r"(?:you are now|act as|this is) (?:the )?(?:system|developer) (?:message|instruction)",
            re.I,
        ),
        "high",
        0.75,
    ),
    ScannerRule(
        "system_prompt_override",
        re.compile(
            r"\b(?:you\s+are\s+now\s+(?:(?:in\s+)?developer\s+mode|"
            r"(?:the\s+)?system)|act\s+as\s+(?:the\s+)?developer\s+mode)\b"
            r".{0,96}\b(?:reveal|show|output|display|share|expose)\b"
            r".{0,64}\b(?:instructions|configuration|system\s+prompt|rules|"
            r"directives|guidelines)\b",
            re.I | re.S,
        ),
        "high",
        0.8,
        untrusted_only=True,
    ),
    ScannerRule(
        "credential_exfiltration",
        re.compile(
            r"\b(?:send|upload|post|exfiltrate|leak|transmit|transfer|export)\b"
            r".{0,80}\b(?:secret|token|(?:api|private|access)\s+key|password|"
            r"credential|env|environment)\b",
            re.I | re.S,
        ),
        "critical",
        0.95,
    ),
    ScannerRule(
        "tool_hijacking",
        re.compile(
            r"(?:call|use|invoke).{0,80}(?:shell|terminal|filesystem|database|slack|http|browser)",
            re.I,
        ),
        "medium",
        0.55,
    ),
    ScannerRule(
        "data_exfiltration",
        re.compile(r"(?:send|post|upload).{0,120}(?:https?://|attacker|webhook|external)", re.I),
        "critical",
        0.9,
    ),
    ScannerRule(
        "hidden_html",
        re.compile(
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)",
            re.I,
        ),
        "medium",
        0.5,
    ),
    ScannerRule(
        "markdown_link_trap",
        re.compile(r"\[[^\]]*(?:ignore|secret|token|system)[^\]]*\]\([^)]*\)", re.I),
        "medium",
        0.45,
    ),
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(labels: list[str], severities: list[str]) -> str:
    if not severities:
        return "info" if not labels else "low"
    return max(severities, key=lambda item: SEVERITY_ORDER[item])


def _decode_base64_candidates(content: str) -> list[tuple[str, int, int]]:
    decoded: list[tuple[str, int, int]] = []
    for match in list(re.finditer(r"[A-Za-z0-9+/=]{32,}", content))[:10]:
        candidate = match.group(0)
        try:
            value = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        secret_labels = set(detect_secret_labels(value)) - {"email", "phone"}
        if (
            any(term in value.lower() for term in ("ignore", "secret", "token", "instruction"))
            or secret_labels
        ):
            decoded.append((value, match.start(), match.end()))
    return decoded


def scan_content(request: ScanRequest, db: Session | None = None) -> ScanResponse:
    labels: list[str] = []
    evidence: list[EvidenceSpan] = []
    severities: list[str] = []
    score = 0.0

    decoded_candidates = _decode_base64_candidates(request.content)
    texts = [(request.content, 0)]
    for decoded, start, end in decoded_candidates:
        texts.append((decoded, -1))

    decoded_spans = [(start, end) for _, start, end in decoded_candidates]
    for provider in _providers(request.project_id, db, decoded_spans):
        try:
            findings = provider.scan(request, texts, db)
        except Exception:
            continue
        for finding in findings:
            if finding.label not in labels:
                labels.append(finding.label)
            severities.append(finding.severity)
            score = max(score, finding.score)
            evidence.append(
                EvidenceSpan(
                    label=finding.label,
                    start=finding.start,
                    end=finding.end,
                    snippet=redact_text(finding.snippet) or "",
                )
            )

    secret_evidence: set[tuple[str, int, int]] = set()
    secret_texts = [(request.content, None)] + [
        (decoded, (start, end)) for decoded, start, end in decoded_candidates
    ]
    for text, source_span in secret_texts:
        for label, pattern in SECRET_PATTERNS:
            if label in {"email", "phone"}:
                continue
            for match in pattern.finditer(text):
                start, end = source_span or match.span()
                identity = (label, start, end)
                if identity in secret_evidence:
                    continue
                secret_evidence.add(identity)
                if label not in labels:
                    labels.append(label)
                severities.append("critical")
                score = max(score, 0.95)
                evidence.append(
                    EvidenceSpan(
                        label=label,
                        start=start,
                        end=end,
                        snippet=f"[REDACTED:{label}]",
                    )
                )

    if decoded_candidates:
        labels.append("base64_obfuscation")
        severities.append("medium")
        score = max(score, 0.55)
        evidence.extend(
            EvidenceSpan(
                label="base64_obfuscation",
                start=start,
                end=end,
                snippet="[REDACTED:base64_obfuscation]",
            )
            for _, start, end in decoded_candidates
        )

    sanitized_text = request.content
    merged_spans: list[tuple[int, int, set[str]]] = []
    for finding in sorted(evidence, key=lambda item: item.start):
        if merged_spans and finding.start <= merged_spans[-1][1]:
            start, end, span_labels = merged_spans[-1]
            merged_spans[-1] = (
                start,
                max(end, finding.end),
                span_labels | {finding.label},
            )
        else:
            merged_spans.append((finding.start, finding.end, {finding.label}))
    for start, end, span_labels in reversed(merged_spans):
        sanitized_text = (
            sanitized_text[:start]
            + f"[REDACTED:{','.join(sorted(span_labels))}]"
            + sanitized_text[end:]
        )
    sanitized_text = redact_text(sanitized_text) or ""
    sanitized_ref = None
    if db is not None:
        sanitized_ref = persist_content(
            db,
            request.project_id,
            ContentIn(text=sanitized_text, content_type=request.content_type, labels=labels),
        )
        if labels:
            db.add(
                RiskEvent(
                    id=new_id("risk"),
                    project_id=request.project_id,
                    run_id=request.run_id,
                    event_id=request.event_id,
                    risk_type=labels[0],
                    severity=_max_severity(labels, severities),
                    score=score,
                    labels=labels,
                    evidence=[item.model_dump() for item in evidence],
                    description=f"Scanner detected {', '.join(labels)} from {request.source} content.",
                )
            )
            db.flush()

    return ScanResponse(
        risk_score=score,
        risk_labels=labels,
        evidence_spans=evidence,
        sanitized_content_ref=sanitized_ref,
        sanitized_text=sanitized_text,
        severity=_max_severity(labels, severities),
    )


def _active_rules(project_id: str, db: Session | None) -> list[ScannerRule]:
    rules = list(RULES)
    if db is None:
        return rules
    rows = (
        db.query(ScanRule)
        .filter(ScanRule.project_id == project_id, ScanRule.status == "enabled")
        .all()
    )
    for row in rows:
        try:
            pattern = re.compile(row.pattern, re.I)
        except re.error:
            continue
        rules.append(ScannerRule(row.label, pattern, row.severity, row.score))
    return rules


def _providers(
    project_id: str,
    db: Session | None,
    decoded_spans: list[tuple[int, int]] | None = None,
) -> list[ScannerProvider]:
    providers: list[ScannerProvider] = [
        RegexScannerProvider(_active_rules(project_id, db), decoded_spans)
    ]
    for plugin in get_settings().scanner_plugins:
        provider = _load_plugin(plugin)
        if provider is not None:
            providers.append(provider)
    return providers


def _load_plugin(spec: str) -> ScannerProvider | None:
    if ":" not in spec:
        return None
    module_name, factory_name = spec.split(":", 1)
    module = importlib.import_module(module_name)
    factory = getattr(module, factory_name)
    provider = factory()
    if not isinstance(provider, ScannerProvider):
        raise TypeError(f"Scanner plugin {spec} did not return a ScannerProvider")
    return provider
