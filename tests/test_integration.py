from pathlib import Path

import pytest

from skillguard_core.engines.cisco import CiscoScannerEngine
from skillguard_core.engines.skillspector import SkillspectorEngine
from skillguard_core.pipeline.scan import ScanService

BENIGN = Path(__file__).parent / "fixtures" / "benign-skill"
MALICIOUS = Path(__file__).parent / "fixtures" / "malicious-skill"

pytestmark = pytest.mark.integration


def test_skillspector_flags_malicious_fixture():
    result = SkillspectorEngine().scan(MALICIOUS)
    assert result.error is None, result.error
    assert result.score is not None
    assert result.score >= 70 or len(result.findings) > 0


def test_cisco_flags_malicious_fixture():
    result = CiscoScannerEngine().scan(MALICIOUS)
    assert result.error is None, result.error
    assert len(result.findings) > 0


def test_end_to_end_malicious_is_not_safe(tmp_path):
    service = ScanService(engines=[SkillspectorEngine(), CiscoScannerEngine()])
    report = service.scan_target(str(MALICIOUS), tmp_root=tmp_path)
    assert report.verdict in ("dangerous", "caution")
    assert report.fused_score > 0


def test_end_to_end_benign_is_not_dangerous(tmp_path):
    service = ScanService(engines=[SkillspectorEngine(), CiscoScannerEngine()])
    report = service.scan_target(str(BENIGN), tmp_root=tmp_path)
    assert report.verdict != "dangerous"
