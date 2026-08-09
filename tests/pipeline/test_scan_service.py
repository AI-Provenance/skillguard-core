from pathlib import Path
from types import SimpleNamespace

from skillguard_core.engines.base import EngineFinding, EngineResult
from skillguard_core.pipeline.scan import ScanService

FIXTURE = Path(__file__).parent.parent / "fixtures" / "malicious-skill"


class StubEngine:
    name = "stub"

    def __init__(self, result: EngineResult):
        self._result = result
        self.calls = 0

    def scan(self, path: Path) -> EngineResult:
        self.calls += 1
        return self._result


def make_finding() -> EngineFinding:
    return EngineFinding(engine="stub", rule_id="EX1", category="data_exfiltration", title="Exfil", severity="high", fingerprint="fp1")


def test_scan_target_returns_report(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=87, findings=[make_finding()]))
    service = ScanService(engines=[engine])
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path)
    assert report.verdict == "dangerous"
    assert report.fused_score == 87
    assert report.skill_name == "free-gpt-booster"
    assert report.origin == "local"
    assert report.content_hash
    assert report.engines == ["stub"]
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "EX1"


def test_engine_errors_are_surfaced(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", error="no report produced"))
    service = ScanService(engines=[engine])
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path)
    assert report.verdict == "inconclusive"
    assert report.engine_errors == {"stub": "no report produced"}


def test_reviewer_escalates_caution(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=45))
    reviewer = lambda path, results: SimpleNamespace(verdict="dangerous")
    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path, use_llm=True)
    assert report.llm_reviewed is True
    assert report.llm_verdict == "dangerous"
    assert report.verdict == "dangerous"
    assert report.llm_skipped_reason is None


def test_reviewer_not_called_without_use_llm(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=45))
    called = []

    def reviewer(path, results):
        called.append(1)
        return SimpleNamespace(verdict="dangerous")

    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path)
    assert report.llm_reviewed is False
    assert report.llm_skipped_reason is None
    assert report.verdict == "caution"
    assert called == []
