import json
from dataclasses import asdict

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


@app.command()
def scan(
    target: str = typer.Argument(...),
    use_llm: bool = False,
    json_output: bool = typer.Option(False, "--json"),
    sarif: bool = typer.Option(False, "--sarif"),
) -> None:
    """Scan a skill directory, git URL, or zip URL."""
    service = ScanService(engines=_engines(), reviewer=build_reviewer())
    try:
        report = service.scan_target(target, use_llm=use_llm)
    except Exception as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(3)
    if sarif:
        typer.echo(json.dumps(to_sarif(report), indent=2))
    elif json_output:
        typer.echo(json.dumps(asdict(report), indent=2))
    else:
        typer.echo(f"{report.skill_name}: {report.verdict.upper()} (score {report.fused_score})")
        for f in report.findings:
            typer.echo(f"  [{f.severity}] {f.engine}/{f.rule_id}: {f.title} ({f.file_path})")
    raise typer.Exit(EXIT_CODES.get(report.verdict, 3))
