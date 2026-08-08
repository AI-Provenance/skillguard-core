from skillguard_core.pipeline.scan import ScanReport

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def to_sarif(report: ScanReport) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in report.findings:
        rule_key = f"{f.engine}/{f.rule_id}"
        if rule_key not in rules:
            rules[rule_key] = {"id": rule_key, "shortDescription": {"text": f.title or rule_key}}
        results.append({
            "ruleId": rule_key,
            "level": LEVELS.get(f.severity, "warning"),
            "message": {"text": f.title or rule_key},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file_path or "SKILL.md"}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "skillguard", "informationUri": "https://skillguard.dev", "rules": list(rules.values())}},
            "results": results,
        }],
    }
