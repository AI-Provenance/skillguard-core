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
