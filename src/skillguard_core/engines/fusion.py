from dataclasses import dataclass

from skillguard_core.engines.base import EngineResult

SEVERITY_SCORES = {"critical": 95, "high": 80, "medium": 50, "low": 20}


@dataclass(slots=True)
class FusedVerdict:
    score: int
    severity: str
    verdict: str
    engine_errors: dict[str, str]


def engine_score(result: EngineResult) -> int:
    score = 0
    if result.score is not None:
        score = max(0, min(100, result.score))
    if result.findings:
        score = max(score, *(SEVERITY_SCORES.get(f.severity, 0) for f in result.findings))
    return score


def score_to_severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def fuse(results: list[EngineResult], danger_min: int = 70, caution_min: int = 30) -> FusedVerdict:
    errors = {r.engine: r.error for r in results if r.error}
    valid = [r for r in results if r.error is None]
    if not valid:
        return FusedVerdict(score=0, severity="unknown", verdict="inconclusive", engine_errors=errors)
    score = max(engine_score(r) for r in valid)
    if score >= danger_min:
        verdict = "dangerous"
    elif score >= caution_min:
        verdict = "caution"
    else:
        verdict = "safe"
    return FusedVerdict(score=score, severity=score_to_severity(score), verdict=verdict, engine_errors=errors)
