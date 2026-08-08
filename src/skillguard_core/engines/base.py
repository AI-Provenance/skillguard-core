import hashlib
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_ALIASES = {
    "info": "low",
    "minor": "low",
    "warning": "medium",
    "severe": "high",
    "crit": "critical",
}

Runner = Callable[..., subprocess.CompletedProcess]


def normalize_severity(value: str | None) -> str:
    v = (value or "").strip().lower()
    v = SEVERITY_ALIASES.get(v, v)
    return v if v in SEVERITIES else "medium"


def truncate_evidence(text: str | None, limit: int = 400) -> str:
    if not text:
        return ""
    text = text.strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def make_fingerprint(engine: str, rule_id: str, file_path: str, title: str) -> str:
    raw = f"{engine}|{rule_id}|{file_path}|{title}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass(slots=True)
class EngineFinding:
    engine: str
    rule_id: str
    category: str
    title: str
    severity: str
    file_path: str = ""
    evidence: str = ""
    fingerprint: str = ""


@dataclass(slots=True)
class EngineResult:
    engine: str
    score: int | None = None
    findings: list[EngineFinding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
