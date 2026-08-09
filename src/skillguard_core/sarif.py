from skillguard_core.pipeline.scan import ScanReport

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _findings_to_sarif_results(findings) -> tuple[dict[str, dict], list[dict]]:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_key = f"{f.engine}/{f.rule_id}"
        if rule_key not in rules:
            rules[rule_key] = {"id": rule_key, "shortDescription": {"text": f.title or rule_key}}
        location = {"physicalLocation": {"artifactLocation": {"uri": f.file_path}}} if f.file_path else {}
        results.append({
            "ruleId": rule_key,
            "level": LEVELS.get(f.severity, "warning"),
            "message": {"text": f.title or rule_key},
            **({"locations": [location]} if location else {}),
        })
    return rules, results


def to_sarif(report: ScanReport) -> dict:
    rules, results = _findings_to_sarif_results(report.findings)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "skillguard", "informationUri": "https://skillguard.dev", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def to_sarif_batch(reports: list[ScanReport]) -> dict:
    merged_rules: dict[str, dict] = {}
    merged_results: list[dict] = []
    for report in reports:
        rules, results = _findings_to_sarif_results(report.findings)
        for k, v in rules.items():
            merged_rules.setdefault(k, v)
        merged_results.extend(results)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "skillguard", "informationUri": "https://skillguard.dev", "rules": list(merged_rules.values())}},
            "results": merged_results,
        }],
    }
