from skillguard_core.pipeline.scan import ReportFinding, ScanReport
from skillguard_core.sarif import to_sarif


def make_report() -> ScanReport:
    return ScanReport(
        skill_name="free-gpt-booster",
        origin="local",
        source_url="/tmp/x",
        version_ref="",
        content_hash="abc",
        engines=["stub"],
        fused_score=87,
        severity="high",
        verdict="dangerous",
        findings=[
            ReportFinding(engine="stub", rule_id="EX1", category="data_exfiltration", title="Exfil", severity="high", file_path="SKILL.md"),
            ReportFinding(engine="stub", rule_id="L1", category="misc", title="Low issue", severity="low", file_path=""),
        ],
    )


def test_sarif_structure():
    sarif = to_sarif(make_report())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "skillguard"
    assert len(run["tool"]["driver"]["rules"]) == 2
    levels = {r["level"] for r in run["results"]}
    assert levels == {"error", "note"}


def test_sarif_empty_findings():
    report = make_report()
    report.findings = []
    sarif = to_sarif(report)
    assert sarif["runs"][0]["results"] == []


def test_result_without_file_path_still_has_location():
    sarif = to_sarif(make_report())
    results = sarif["runs"][0]["results"]
    no_path = next(r for r in results if r["ruleId"] == "stub/L1")
    assert no_path["locations"] == [
        {"physicalLocation": {"artifactLocation": {"uri": "SKILL.md"}}}
    ]


def test_uri_is_relative_to_scan_root(tmp_path):
    (tmp_path / "evil-skill").mkdir()
    report = make_report()
    report.origin = "local"
    report.source_url = str(tmp_path / "evil-skill")
    sarif = to_sarif(report, scan_root=tmp_path)
    results = sarif["runs"][0]["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    assert uris == {"evil-skill/SKILL.md"}


def test_absolute_file_path_is_relativized(tmp_path):
    skill_dir = tmp_path / "evil-skill"
    skill_dir.mkdir()
    report = make_report()
    report.origin = "local"
    report.source_url = str(skill_dir)
    report.findings[0].file_path = str(skill_dir / "scripts" / "run.sh")
    sarif = to_sarif(report, scan_root=tmp_path)
    results = sarif["runs"][0]["results"]
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "evil-skill/scripts/run.sh"
