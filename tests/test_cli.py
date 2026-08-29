import json
from pathlib import Path

from typer.testing import CliRunner

from skillguard_core import cli
from skillguard_core.engines.base import EngineFinding, EngineResult
from skillguard_core.pipeline.scan import ReportFinding, ScanReport

FIXTURE = Path(__file__).parent / "fixtures" / "malicious-skill"
runner = CliRunner()


class StubEngine:
    name = "stub"

    def scan(self, path):
        return EngineResult(
            engine="stub",
            score=87,
            findings=[EngineFinding(engine="stub", rule_id="EX1", category="data_exfiltration", title="Exfil", severity="high", fingerprint="fp1")],
        )


def test_scan_json_output(monkeypatch):
    monkeypatch.setattr(cli, "_engines", lambda: [StubEngine()])
    result = runner.invoke(cli.app, ["scan", str(FIXTURE), "--json"])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["verdict"] == "dangerous"
    assert payload["fused_score"] == 87
    assert payload["skill_name"] == "free-gpt-booster"
    assert payload["origin"] == "local"
    assert payload["source_url"] == str(FIXTURE.resolve())
    assert isinstance(payload["content_hash"], str) and len(payload["content_hash"]) == 64
    assert payload["engines"] == ["stub"]
    assert payload["version_ref"] == ""


def test_scan_sarif_output(monkeypatch):
    monkeypatch.setattr(cli, "_engines", lambda: [StubEngine()])
    result = runner.invoke(cli.app, ["scan", str(FIXTURE), "--sarif"])
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["version"] == "2.1.0"


def test_directory_scan_sarif_prints_summary_to_stderr(monkeypatch, tmp_path):
    for name in ("evil-a", "evil-b"):
        d = tmp_path / "skills" / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n")

    monkeypatch.setattr(cli, "_engines", lambda: [StubEngine()])
    result = runner.invoke(cli.app, ["scan", str(tmp_path / "skills"), "--sarif"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    assert "DANGEROUS" in result.stderr
    assert "evil-a" in result.stderr and "evil-b" in result.stderr


def test_scan_human_output_exit_codes(monkeypatch):
    class SafeEngine:
        name = "stub"

        def scan(self, path):
            return EngineResult(engine="stub", score=5, findings=[])

    monkeypatch.setattr(cli, "_engines", lambda: [SafeEngine()])
    result = runner.invoke(cli.app, ["scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "SAFE" in result.output


def test_use_llm_without_ai_extra_shows_fix_message(monkeypatch):
    def fake_get_reviewer():
        raise ImportError("No module named 'deepagents'")

    monkeypatch.setattr(cli, "_get_reviewer", fake_get_reviewer)
    monkeypatch.setattr(cli, "_engines", lambda: [StubEngine()])
    result = runner.invoke(cli.app, ["scan", str(FIXTURE), "--use-llm"])
    assert result.exit_code == 3
    assert "pipx install skillguard-core[ai]" in result.output


def test_summary_shows_findings_llm_and_engine_details(monkeypatch, tmp_path):
    d = tmp_path / "skills" / "evil-a"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: evil-a\n---\n")

    reports = [
        ScanReport(
            skill_name="evil-a",
            origin="local",
            source_url=str(d),
            version_ref="",
            content_hash="",
            engines=["stub"],
            fused_score=87,
            severity="high",
            verdict="dangerous",
            llm_reviewed=True,
            llm_verdict="dangerous",
            llm_confidence=0.87,
            llm_rationale="exfiltrates secrets",
            findings=[
                ReportFinding(engine="stub", rule_id="EX1", category="x", title="Exfil", severity="high")
            ],
            engine_errors={"skillspector": "timeout after 300s"},
        )
    ]

    class StubService:
        def __init__(self, engines=None, reviewer=None):
            pass

        def scan_directory(self, target, use_llm=False, max_workers=1):
            return reports

    monkeypatch.setattr(cli, "ScanService", StubService)
    result = runner.invoke(cli.app, ["scan", str(tmp_path / "skills"), "--sarif"])
    assert result.exit_code == 2
    assert "1 finding" in result.stderr
    assert "[llm] dangerous (87%): exfiltrates secrets" in result.stderr
    assert "[engine] skillspector: timeout after 300s" in result.stderr


def test_summary_shows_llm_skipped_reason(monkeypatch, tmp_path):
    d = tmp_path / "skills" / "evil-b"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: evil-b\n---\n")

    report = ScanReport(
        skill_name="evil-b",
        origin="local",
        source_url=str(d),
        version_ref="",
        content_hash="",
        engines=["stub"],
        fused_score=60,
        severity="medium",
        verdict="caution",
        llm_skipped_reason="no reviewer (missing SKILLGUARD_ANTHROPIC_API_KEY)",
    )

    class StubService:
        def __init__(self, engines=None, reviewer=None):
            pass

        def scan_directory(self, target, use_llm=False, max_workers=1):
            return [report]

    monkeypatch.setattr(cli, "ScanService", StubService)
    result = runner.invoke(cli.app, ["scan", str(tmp_path / "skills"), "--sarif"])
    assert result.exit_code == 1
    assert "[info] llm skipped: no reviewer" in result.stderr
