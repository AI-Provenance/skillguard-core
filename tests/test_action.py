from pathlib import Path

import yaml


def test_action_manifest_is_valid():
    manifest = yaml.safe_load((Path(__file__).parent.parent / "action.yml").read_text())
    assert manifest["name"] == "SkillGuard Scan"
    assert manifest["runs"]["using"] == "composite"
    assert "path" in manifest["inputs"]
    assert manifest["inputs"]["fail-on"]["default"] == "dangerous"
