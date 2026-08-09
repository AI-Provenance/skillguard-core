import json
from dataclasses import asdict
from pathlib import Path

import typer

from skillguard_core.config import get_settings
from skillguard_core.engines.cisco import CiscoScannerEngine
from skillguard_core.engines.skillspector import SkillspectorEngine
from skillguard_core.pipeline.scan import ScanService
from skillguard_core.sarif import to_sarif
from skillguard_core.semantic.reviewer import build_reviewer

app = typer.Typer(no_args_is_help=True)

EXIT_CODES = {"safe": 0, "caution": 1, "dangerous": 2, "inconclusive": 3}


@app.command(hidden=True)
def _version():
    """Show version."""
    from skillguard_core import __version__

    typer.echo(f"skillguard-core {__version__}")


def _engines() -> list:
    settings = get_settings()
    return [
        SkillspectorEngine(binary=settings.skillspector_bin, timeout_s=settings.scan_timeout_s),
        CiscoScannerEngine(binary=settings.cisco_bin, policy=settings.cisco_policy, timeout_s=settings.scan_timeout_s),
    ]


def _is_skills_dir(target: str) -> bool:
    try:
        path = Path(target).expanduser().resolve()
        return path.is_dir() and not (path / "SKILL.md").exists() and any(
            d.is_dir() and (d / "SKILL.md").exists() for d in path.iterdir()
        )
    except OSError:
        return False


def _format_report(report, json_output: bool, sarif: bool):
    if sarif:
        return json.dumps(to_sarif(report), indent=2)
    if json_output:
        return json.dumps(asdict(report), indent=2)
    lines = [f"{report.skill_name}: {report.verdict.upper()} (score {report.fused_score})"]
    if report.llm_reviewed:
        lines.append(f"  [llm] verdict '{report.llm_verdict}', confidence {report.llm_confidence:.0%}: {report.llm_rationale}")
    elif report.llm_skipped_reason:
        lines.append(f"  [info] --use-llm skipped: {report.llm_skipped_reason}")
    for f in report.findings:
        lines.append(f"  [{f.severity}] {f.engine}/{f.rule_id}: {f.title} ({f.file_path})")
    return "\n".join(lines)


@app.command()
def scan(
    target: str = typer.Argument(...),
    use_llm: bool = False,
    json_output: bool = typer.Option(False, "--json"),
    sarif: bool = typer.Option(False, "--sarif"),
) -> None:
    """Scan a skill directory, git URL, or zip URL."""
    if json_output and sarif:
        typer.echo("error: --json and --sarif are mutually exclusive", err=True)
        raise typer.Exit(3)
    service = ScanService(engines=_engines(), reviewer=build_reviewer())

    if _is_skills_dir(target):
        try:
            reports = service.scan_directory(target, use_llm=use_llm)
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(3)
        if json_output or sarif:
            typer.echo(json.dumps([asdict(r) if json_output else to_sarif(r) for r in reports], indent=2))
        else:
            for report in reports:
                typer.echo(_format_report(report, False, False))
                typer.echo()
        worst = max(reports, key=lambda r: EXIT_CODES.get(r.verdict, 0))
        raise typer.Exit(EXIT_CODES.get(worst.verdict, 3))

    try:
        report = service.scan_target(target, use_llm=use_llm)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(3)
    typer.echo(_format_report(report, json_output, sarif))
    raise typer.Exit(EXIT_CODES.get(report.verdict, 3))
