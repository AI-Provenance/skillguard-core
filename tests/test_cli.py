import json
from pathlib import Path

from typer.testing import CliRunner

from skillguard_core import cli
from skillguard_core.engines.base import EngineFinding, EngineResult

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


def test_scan_human_output_exit_codes(monkeypatch):
    class SafeEngine:
        name = "stub"

        def scan(self, path):
            return EngineResult(engine="stub", score=5, findings=[])

    monkeypatch.setattr(cli, "_engines", lambda: [SafeEngine()])
    result = runner.invoke(cli.app, ["scan", str(FIXTURE)])
    assert result.exit_code == 0
    assert "SAFE" in result.output
