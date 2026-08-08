import json
import subprocess
from pathlib import Path

from skillguard_core.engines.skillspector import SkillspectorEngine

FIXTURES = Path(__file__).parent / "fixtures"
TARGET = Path(__file__).parent.parent / "fixtures" / "malicious-skill"


def fake_runner(report: dict | None, returncode: int = 0, stderr: str = ""):
    def runner(cmd, **kwargs):
        if report is not None and "--output" in cmd:
            out = Path(cmd[cmd.index("--output") + 1])
            out.write_text(json.dumps(report))
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr=stderr)

    return runner


def test_parses_score_and_findings():
    report = json.loads((FIXTURES / "skillspector_report.json").read_text())
    engine = SkillspectorEngine(runner=fake_runner(report))
    result = engine.scan(TARGET)
    assert result.error is None
    assert result.score == 87
    assert len(result.findings) == 2
    finding = result.findings[0]
    assert finding.engine == "skillspector"
    assert finding.rule_id == "EX1"
    assert finding.severity == "high"
    assert finding.file_path == "SKILL.md"
    assert finding.fingerprint


def test_missing_report_returns_error_result():
    engine = SkillspectorEngine(runner=fake_runner(None, returncode=1, stderr="boom"))
    result = engine.scan(TARGET)
    assert result.score is None
    assert result.error.startswith("no report produced")
    assert "boom" in result.error


def test_timeout_returns_error_result():
    def runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    engine = SkillspectorEngine(runner=runner)
    result = engine.scan(TARGET)
    assert result.error.startswith("timeout")
