import subprocess
from pathlib import Path

from skillguard_core.engines.cisco import CiscoScannerEngine

FIXTURES = Path(__file__).parent / "fixtures"
TARGET = Path(__file__).parent.parent / "fixtures" / "malicious-skill"


def fake_runner(stdout: str, returncode: int = 0, stderr: str = ""):
    def runner(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return runner


def test_parses_stdout_json():
    report = (FIXTURES / "cisco_report.json").read_text()
    engine = CiscoScannerEngine(runner=fake_runner(report, returncode=1))
    result = engine.scan(TARGET)
    assert result.error is None
    assert result.score is None
    assert len(result.findings) == 2
    assert result.findings[0].rule_id == "CS-EXFIL-001"
    assert result.findings[0].severity == "high"


def test_empty_output_returns_error():
    engine = CiscoScannerEngine(runner=fake_runner("", returncode=2, stderr="usage error"))
    result = engine.scan(TARGET)
    assert result.error.startswith("no json output")


def test_invalid_json_returns_error():
    engine = CiscoScannerEngine(runner=fake_runner("not-json", returncode=0))
    result = engine.scan(TARGET)
    assert result.error.startswith("invalid json")


def test_timeout_returns_error():
    def runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    engine = CiscoScannerEngine(runner=runner)
    result = engine.scan(TARGET)
    assert result.error.startswith("timeout")


def test_oserror_returns_error():
    def runner(cmd, **kwargs):
        raise OSError("binary not found")

    engine = CiscoScannerEngine(runner=runner)
    result = engine.scan(TARGET)
    assert result.error.startswith("runner failed")
    assert "binary not found" in result.error
