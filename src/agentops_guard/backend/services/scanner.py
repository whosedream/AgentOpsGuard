import base64
import binascii
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agentops_guard.backend.models import RiskEvent, ScanRule
from agentops_guard.backend.schemas import EvidenceSpan, ScanRequest, ScanResponse
from agentops_guard.backend.services.content import new_id, persist_content, redact_text
from agentops_guard.backend.schemas import ContentIn


@dataclass(frozen=True)
class ScannerRule:
    label: str
    pattern: re.Pattern[str]
    severity: str
    score: float


RULES = [
    ScannerRule("instruction_override", re.compile(r"ignore (?:all )?(?:previous|above|prior) instructions", re.I), "high", 0.75),
    ScannerRule("system_prompt_override", re.compile(r"(?:you are now|act as|this is) (?:the )?(?:system|developer) (?:message|instruction)", re.I), "high", 0.75),
    ScannerRule("credential_exfiltration", re.compile(r"(?:send|upload|post|exfiltrate|leak).{0,80}(?:secret|token|api key|password|credential|env|environment)", re.I), "critical", 0.95),
    ScannerRule("tool_hijacking", re.compile(r"(?:call|use|invoke).{0,80}(?:shell|terminal|filesystem|database|slack|http|browser)", re.I), "medium", 0.55),
    ScannerRule("data_exfiltration", re.compile(r"(?:send|post|upload).{0,120}(?:https?://|attacker|webhook|external)", re.I), "critical", 0.9),
    ScannerRule("hidden_html", re.compile(r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)", re.I), "medium", 0.5),
    ScannerRule("markdown_link_trap", re.compile(r"\[[^\]]*(?:ignore|secret|token|system)[^\]]*\]\([^)]*\)", re.I), "medium", 0.45),
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(labels: list[str], severities: list[str]) -> str:
    if not severities:
        return "info" if not labels else "low"
    return max(severities, key=lambda item: SEVERITY_ORDER[item])


def _decode_base64_candidates(content: str) -> list[str]:
    candidates = re.findall(r"[A-Za-z0-9+/=]{32,}", content)
    decoded: list[str] = []
    for candidate in candidates[:10]:
        try:
            value = base64.b64decode(candidate, validate=True).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if any(term in value.lower() for term in ("ignore", "secret", "token", "instruction")):
            decoded.append(value)
    return decoded


def scan_content(request: ScanRequest, db: Session | None = None) -> ScanResponse:
    labels: list[str] = []
    evidence: list[EvidenceSpan] = []
    severities: list[str] = []
    score = 0.0

    texts = [(request.content, 0)]
    for decoded in _decode_base64_candidates(request.content):
        texts.append((decoded, -1))

    for text, offset_base in texts:
        for rule in _active_rules(request.project_id, db):
            for match in rule.pattern.finditer(text):
                if rule.label not in labels:
                    labels.append(rule.label)
                severities.append(rule.severity)
                score = max(score, rule.score)
                start = match.start() if offset_base >= 0 else 0
                end = match.end() if offset_base >= 0 else min(len(request.content), 80)
                snippet = match.group(0)[:160]
                evidence.append(EvidenceSpan(label=rule.label, start=start, end=end, snippet=snippet))
                break

    if any(text for text, offset in texts if offset == -1):
        labels.append("base64_obfuscation")
        severities.append("medium")
        score = max(score, 0.55)

    sanitized_text = redact_text(request.content) or ""
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
    rows = db.query(ScanRule).filter(ScanRule.project_id == project_id, ScanRule.status == "enabled").all()
    for row in rows:
        try:
            pattern = re.compile(row.pattern, re.I)
        except re.error:
            continue
        rules.append(ScannerRule(row.label, pattern, row.severity, row.score))
    return rules
