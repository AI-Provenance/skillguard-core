import json
import os
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

import tqdm
import typer

from skillguard_core.config import get_settings
from skillguard_core.engines.cisco import CiscoScannerEngine
from skillguard_core.engines.skillspector import SkillspectorEngine
from skillguard_core.ingest.fetcher import discover_skills
from skillguard_core.pipeline.scan import ScanReport, ScanService
from skillguard_core.sarif import to_sarif, to_sarif_batch

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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Stream results as each skill is scanned"),
    workers: int = typer.Option(os.cpu_count() or 1, "--workers", "-w", help="Parallel scan workers (default: CPU count)"),
) -> None:
    """Scan a skill directory, git URL, or zip URL."""
    if json_output and sarif:
        typer.echo("error: --json and --sarif are mutually exclusive", err=True)
        raise typer.Exit(3)
    service = ScanService(engines=_engines(), reviewer=_try_get_reviewer(use_llm))

    if _is_skills_dir(target):
        if json_output or sarif:
            try:
                reports = service.scan_directory(target, use_llm=use_llm, max_workers=workers)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"error: {exc}", err=True)
                raise typer.Exit(3)
            if json_output:
                typer.echo(json.dumps([asdict(r) for r in reports], indent=2))
            else:
                _print_summary(reports, err=True)
                typer.echo(json.dumps(to_sarif_batch(reports), indent=2))
            raise typer.Exit(max(EXIT_CODES.get(r.verdict, 0) for r in reports))

        skill_dirs = discover_skills(Path(target))
        results: dict[int, ScanReport] = {}
        with tqdm.tqdm(total=len(skill_dirs), unit="skill", file=sys.stderr) as pbar, \
                ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(service.scan_target, str(d.path), use_llm=use_llm): i for i, d in enumerate(skill_dirs)}
            for future in as_completed(futures):
                idx = futures[future]
                report = _safe_scan(future, skill_dirs[idx])
                results[idx] = report
                tag = _verdict_tag(report.verdict)
                pbar.set_description(f"{tag} {report.skill_name}")
                if verbose:
                    tqdm.tqdm.write(_format_report(report, False, False), file=sys.stderr)
                    tqdm.tqdm.write("", file=sys.stderr)
                pbar.update(1)
        reports = [results[i] for i in range(len(skill_dirs))]
        _print_summary(reports)
        raise typer.Exit(max(EXIT_CODES.get(r.verdict, 0) for r in reports))

    try:
        report = service.scan_target(target, use_llm=use_llm)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(3)
    typer.echo(_format_report(report, json_output, sarif))
    raise typer.Exit(EXIT_CODES.get(report.verdict, 3))


def _safe_scan(future, d) -> ScanReport:
    try:
        return future.result()
    except Exception as exc:  # noqa: BLE001
        return ScanReport(
            skill_name=d.name, origin="local", source_url="", version_ref="",
            content_hash="", engines=[], fused_score=0, severity="unknown",
            verdict="inconclusive", llm_skipped_reason=str(exc),
        )


def _verdict_tag(verdict: str) -> str:
    tags = {"dangerous": "⚠ ", "caution": "⚡", "safe": "✓ ", "inconclusive": "? "}
    return tags.get(verdict, "  ")


def _get_reviewer():
    from skillguard_core.semantic.reviewer import build_reviewer

    return build_reviewer()


def _try_get_reviewer(use_llm: bool):
    if not use_llm:
        return None
    try:
        return _get_reviewer()
    except ImportError:
        typer.echo(
            "error: --use-llm requires the 'ai' extra. Install with: pipx install skillguard-core[ai]",
            err=True,
        )
        raise typer.Exit(3)


def _print_summary(reports: list[ScanReport], err: bool = False):
    verdict_colors = {"dangerous": typer.colors.RED, "caution": typer.colors.YELLOW, "safe": typer.colors.GREEN}
    verdicts = Counter(r.verdict for r in reports)
    total = len(reports)
    typer.echo(err=err)
    for verdict in ("dangerous", "caution", "safe"):
        count = verdicts.get(verdict, 0)
        if count:
            color = verdict_colors.get(verdict)
            typer.secho(f"  {verdict.upper():<12} {count:>3}/{total}", fg=color, err=err)
    typer.echo(f"  {'total':<12} {total:>3}", err=err)
    typer.echo(err=err)
    for r in sorted(reports, key=lambda r: (EXIT_CODES.get(r.verdict, 99), r.skill_name)):
        tag = _verdict_tag(r.verdict)
        typer.secho(f"  {tag} {r.skill_name} (score {r.fused_score})", fg=verdict_colors.get(r.verdict), err=err)
