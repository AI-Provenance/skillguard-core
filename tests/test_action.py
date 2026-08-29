from pathlib import Path

import yaml


def load_manifest() -> dict:
    return yaml.safe_load((Path(__file__).parent.parent / "action.yml").read_text())


def test_action_manifest_is_valid():
    manifest = load_manifest()
    assert manifest["name"] == "SkillGuard Scan"
    assert manifest["runs"]["using"] == "composite"
    assert "path" in manifest["inputs"]
    assert manifest["inputs"]["fail-on"]["default"] == "dangerous"


def test_action_exposes_use_llm_input():
    manifest = load_manifest()
    assert "use-llm" in manifest["inputs"]
    assert manifest["inputs"]["use-llm"]["default"] == "false"


def test_action_installs_ai_extra_when_use_llm():
    manifest = load_manifest()
    install_step = next(s for s in manifest["runs"]["steps"] if "pipx install" in s["run"])
    assert "inputs.use-llm" in install_step["run"]
    assert "[ai]" in install_step["run"]


def test_action_passes_use_llm_flag_to_scan():
    manifest = load_manifest()
    scan_step = next(s for s in manifest["runs"]["steps"] if s.get("id") == "scan")
    assert "inputs.use-llm" in scan_step["run"]
    assert "--use-llm" in scan_step["run"]


def test_action_scan_step_reports_verdict_and_error_annotation():
    manifest = load_manifest()
    scan_step = next(s for s in manifest["runs"]["steps"] if s.get("id") == "scan")
    assert "::error::" in scan_step["run"]
    assert 'echo "verdict=$verdict" >> "$GITHUB_OUTPUT"' in scan_step["run"]
