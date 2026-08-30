import time
from pathlib import Path
from types import SimpleNamespace

from skillguard_core.engines.base import EngineFinding, EngineResult
from skillguard_core.pipeline.scan import ScanService, parse_skill_name

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


def test_parse_skill_name_prefers_frontmatter_over_fallback(tmp_path):
    assert parse_skill_name(FIXTURE, fallback="owner/repo") == "free-gpt-booster"


def test_parse_skill_name_uses_fallback_without_skill_md(tmp_path):
    assert parse_skill_name(tmp_path, fallback="owner/repo") == "owner/repo"


def test_parse_skill_name_falls_back_to_dir_name(tmp_path):
    assert parse_skill_name(tmp_path) == tmp_path.name


def test_scan_fetched_git_origin_derives_name_from_url(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "helper.sh").write_text("echo hi")
    engine = StubEngine(EngineResult(engine="stub", score=5, findings=[]))
    service = ScanService(engines=[engine])
    from skillguard_core.ingest.fetcher import Fetched

    fetched = Fetched(
        path=skill_dir,
        origin="git",
        source_url="https://github.com/langchain-ai/langsmith-skills",
        version_ref="abc123",
    )
    report = service.scan_fetched(fetched)
    assert report.skill_name == "langchain-ai/langsmith-skills"


def test_scan_fetched_git_origin_strips_git_suffix(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=5, findings=[]))
    service = ScanService(engines=[engine])
    from skillguard_core.ingest.fetcher import Fetched

    fetched = Fetched(
        path=tmp_path,
        origin="git",
        source_url="https://github.com/owner/my-skill.git",
        version_ref="abc123",
    )
    report = service.scan_fetched(fetched)
    assert report.skill_name == "owner/my-skill"


def test_scan_target_returns_report(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=87, findings=[make_finding()]))
    service = ScanService(engines=[engine])
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path)
    assert report.verdict == "dangerous"
    assert report.fused_score == 87
    assert report.skill_name == "free-gpt-booster"
    assert report.origin == "local"
    assert report.source_url == str(FIXTURE.resolve())
    assert report.content_hash and len(report.content_hash) == 64
    assert report.engines == ["stub"]
    assert report.version_ref == ""
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
    reviewer = lambda path, results: SimpleNamespace(verdict="dangerous", confidence=0.9, rationale="test")
    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path, use_llm=True)
    assert report.llm_reviewed is True
    assert report.llm_verdict == "dangerous"
    assert report.llm_confidence == 0.9
    assert report.verdict == "dangerous"
    assert report.llm_skipped_reason is None


def test_reviewer_cannot_downgrade_caution(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=45))
    reviewer = lambda path, results: SimpleNamespace(verdict="safe", confidence=0.95, rationale="looks fine")
    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path, use_llm=True)
    assert report.llm_reviewed is True
    assert report.llm_verdict == "safe"
    assert report.llm_confidence == 0.95
    assert report.verdict == "caution"


def test_reviewer_not_called_for_inconclusive(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", error="no report produced"))
    called = []

    def reviewer(path, results):
        called.append(1)
        return SimpleNamespace(verdict="dangerous", confidence=0.9, rationale="test")

    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path, use_llm=True)
    assert report.llm_reviewed is False
    assert report.verdict == "inconclusive"
    assert called == []


def test_reviewer_not_called_without_use_llm(tmp_path):
    engine = StubEngine(EngineResult(engine="stub", score=45))
    called = []

    def reviewer(path, results):
        called.append(1)
        return SimpleNamespace(verdict="dangerous", confidence=0.9, rationale="test")

    service = ScanService(engines=[engine], reviewer=reviewer)
    report = service.scan_target(str(FIXTURE), tmp_root=tmp_path)
    assert report.llm_reviewed is False
    assert report.llm_skipped_reason is None
    assert report.verdict == "caution"
    assert called == []


class DelayedStubEngine:
    name = "stub"

    def __init__(self, delay: float = 0.1):
        self.delay = delay

    def scan(self, path: Path) -> EngineResult:
        time.sleep(self.delay)
        return EngineResult(engine="stub", score=5)


def test_scan_directory_parallel_is_faster_than_sequential(tmp_path):
    delay = 0.1
    for i in range(4):
        skill_dir = tmp_path / f"skill-{i}"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(f"---\nname: skill-{i}\n---\n# Skill {i}")
    engine = DelayedStubEngine(delay=delay)
    service = ScanService(engines=[engine])
    # sequential
    started = time.monotonic()
    reports_seq = service.scan_directory(str(tmp_path), max_workers=1)
    elapsed_seq = time.monotonic() - started
    assert len(reports_seq) == 4
    # parallel
    started = time.monotonic()
    reports_par = service.scan_directory(str(tmp_path), max_workers=4)
    elapsed_par = time.monotonic() - started
    assert len(reports_par) == 4
    assert {r.skill_name for r in reports_par} == {r.skill_name for r in reports_seq}
    assert elapsed_par < elapsed_seq * 0.6  # at least 40% faster with 4 workers
