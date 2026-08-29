from pathlib import Path

from skillguard_core.pipeline.scan import ScanReport

LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _skill_dir_uri(report: ScanReport, scan_root: Path | None) -> str:
    if scan_root is None or report.origin != "local" or not report.source_url:
        return ""
    src = Path(report.source_url)
    if not src.is_absolute():
        return ""
    try:
        return src.resolve().relative_to(scan_root.resolve()).as_posix()
    except ValueError:
        return ""


def _finding_uri(file_path: str, skill_dir_uri: str, scan_root: Path | None) -> str:
    if file_path:
        p = Path(file_path)
        if p.is_absolute() and scan_root is not None:
            try:
                return p.resolve().relative_to(scan_root.resolve()).as_posix()
            except ValueError:
                return file_path
        if skill_dir_uri and not file_path.startswith(skill_dir_uri):
            return f"{skill_dir_uri}/{file_path}"
        return file_path
    return f"{skill_dir_uri}/SKILL.md" if skill_dir_uri else "SKILL.md"


def _findings_to_sarif_results(
    findings, skill_dir_uri: str, scan_root: Path | None
) -> tuple[dict[str, dict], list[dict]]:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        rule_key = f"{f.engine}/{f.rule_id}"
        if rule_key not in rules:
            rules[rule_key] = {"id": rule_key, "shortDescription": {"text": f.title or rule_key}}
        uri = _finding_uri(f.file_path, skill_dir_uri, scan_root)
        results.append({
            "ruleId": rule_key,
            "level": LEVELS.get(f.severity, "warning"),
            "message": {"text": f.title or rule_key},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        })
    return rules, results


def to_sarif(report: ScanReport, scan_root: Path | None = None) -> dict:
    scan_root = scan_root or Path.cwd()
    skill_dir_uri = _skill_dir_uri(report, scan_root)
    rules, results = _findings_to_sarif_results(report.findings, skill_dir_uri, scan_root)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "skillguard", "informationUri": "https://skillguard.dev", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def to_sarif_batch(reports: list[ScanReport], scan_root: Path | None = None) -> dict:
    scan_root = scan_root or Path.cwd()
    merged_rules: dict[str, dict] = {}
    merged_results: list[dict] = []
    for report in reports:
        skill_dir_uri = _skill_dir_uri(report, scan_root)
        rules, results = _findings_to_sarif_results(report.findings, skill_dir_uri, scan_root)
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
