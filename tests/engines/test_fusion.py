from skillguard_core.engines.base import EngineFinding, EngineResult
from skillguard_core.engines.fusion import fuse


def finding(severity: str) -> EngineFinding:
    return EngineFinding(engine="cisco", rule_id="R", category="c", title="t", severity=severity)


def test_skillspector_score_wins_when_highest():
    results = [
        EngineResult(engine="skillspector", score=87),
        EngineResult(engine="cisco", score=None, findings=[finding("medium")]),
    ]
    fused = fuse(results)
    assert fused.score == 87
    assert fused.severity == "high"
    assert fused.verdict == "dangerous"


def test_cisco_findings_derive_score_when_no_numeric_score():
    fused = fuse([EngineResult(engine="cisco", score=None, findings=[finding("high")])])
    assert fused.score == 80
    assert fused.verdict == "dangerous"


def test_caution_band():
    fused = fuse([EngineResult(engine="skillspector", score=45)])
    assert fused.verdict == "caution"


def test_safe_band():
    fused = fuse([EngineResult(engine="skillspector", score=10)])
    assert fused.verdict == "safe"
    assert fused.severity == "low"


def test_clean_scan_is_safe():
    fused = fuse([EngineResult(engine="skillspector", score=0), EngineResult(engine="cisco", score=None, findings=[])])
    assert fused.verdict == "safe"
    assert fused.severity == "none"


def test_all_engines_failed_is_inconclusive():
    results = [
        EngineResult(engine="skillspector", error="no report produced"),
        EngineResult(engine="cisco", error="timeout after 300s"),
    ]
    fused = fuse(results)
    assert fused.verdict == "inconclusive"
    assert fused.engine_errors == {"skillspector": "no report produced", "cisco": "timeout after 300s"}


def test_partial_failure_still_fuses():
    results = [
        EngineResult(engine="skillspector", score=92),
        EngineResult(engine="cisco", error="boom"),
    ]
    fused = fuse(results)
    assert fused.verdict == "dangerous"
    assert fused.engine_errors == {"cisco": "boom"}
