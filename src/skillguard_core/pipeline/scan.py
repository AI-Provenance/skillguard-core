import re
import shutil
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from skillguard_core.config import get_settings
from skillguard_core.engines.fusion import fuse
from skillguard_core.ingest.fetcher import Fetched, content_hash, discover_skills, fetch


@dataclass(slots=True)
class ReportFinding:
    engine: str
    rule_id: str
    category: str
    title: str
    severity: str
    file_path: str = ""
    evidence: str = ""
    fingerprint: str = ""


@dataclass(slots=True)
class ScanReport:
    skill_name: str
    origin: str
    source_url: str
    version_ref: str
    content_hash: str
    engines: list[str]
    fused_score: int
    severity: str
    verdict: str
    llm_reviewed: bool = False
    llm_verdict: str | None = None
    llm_confidence: float | None = None
    llm_rationale: str | None = None
    llm_skipped_reason: str | None = None
    findings: list[ReportFinding] = field(default_factory=list)
    engine_errors: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0


def parse_skill_name(path: Path) -> str:
    skill_md = path / "SKILL.md"
    if skill_md.exists():
        text = skill_md.read_text(errors="replace")[:4000]
        match = re.search(r"^name:\s*(.+)$", text, re.MULTILINE)
        if match:
            return match.group(1).strip()
    return path.name


class ScanService:
    def __init__(self, engines: list, reviewer=None):
        self.engines = engines
        self.reviewer = reviewer

    def scan_target(self, target: str, *, tmp_root: Path | None = None, use_llm: bool = False) -> ScanReport:
        settings = get_settings()
        tmp_root = tmp_root or Path(tempfile.gettempdir()) / "skillguard"
        fetched = fetch(
            target,
            tmp_root=tmp_root,
            max_bytes=settings.ingest_max_bytes,
            max_zip_members=settings.ingest_max_zip_members,
        )
        try:
            return self.scan_fetched(fetched, use_llm=use_llm)
        finally:
            if fetched.origin != "local":
                root = fetched.path.parent if fetched.path.parent != tmp_root else fetched.path
                shutil.rmtree(root, ignore_errors=True)

    def scan_directory(self, target: str, *, use_llm: bool = False, on_report: Callable[["ScanReport", int, int], None] | None = None) -> list[ScanReport]:
        skill_dirs = discover_skills(Path(target))
        reports: list[ScanReport] = []
        total = len(skill_dirs)
        for i, d in enumerate(skill_dirs, 1):
            report = self.scan_target(str(d.path), use_llm=use_llm)
            reports.append(report)
            if on_report:
                on_report(report, i, total)
        return reports

    def scan_fetched(self, fetched: Fetched, *, use_llm: bool = False) -> ScanReport:
        settings = get_settings()
        started = time.monotonic()
        results = [engine.scan(fetched.path) for engine in self.engines]
        fused = fuse(results, danger_min=settings.danger_min, caution_min=settings.caution_min)

        llm_verdict = None
        llm_confidence = None
        llm_rationale = None
        llm_skipped_reason = None
        if use_llm and self.reviewer is None:
            llm_skipped_reason = "no reviewer (missing SKILLGUARD_ANTHROPIC_API_KEY)"
        elif use_llm and fused.verdict not in ("caution", "dangerous"):
            llm_skipped_reason = f"verdict is '{fused.verdict}' — review only escalates caution and dangerous scans"
        elif use_llm and fused.verdict in ("caution", "dangerous") and self.reviewer is not None:
            decision = self.reviewer(fetched.path, results)
            if decision is not None:
                llm_verdict = decision.verdict
                llm_confidence = decision.confidence
                llm_rationale = decision.rationale
                fused = replace(fused, verdict=decision.verdict)
            else:
                llm_skipped_reason = "reviewer returned no decision"

        findings = [
            ReportFinding(
                engine=f.engine,
                rule_id=f.rule_id,
                category=f.category,
                title=f.title,
                severity=f.severity,
                file_path=f.file_path,
                evidence=f.evidence,
                fingerprint=f.fingerprint,
            )
            for r in results
            for f in r.findings
        ]
        return ScanReport(
            skill_name=parse_skill_name(fetched.path),
            origin=fetched.origin,
            source_url=fetched.source_url,
            version_ref=fetched.version_ref,
            content_hash=content_hash(fetched.path),
            engines=[e.name for e in self.engines],
            fused_score=fused.score,
            severity=fused.severity,
            verdict=fused.verdict,
            llm_reviewed=llm_verdict is not None,
            llm_verdict=llm_verdict,
            llm_confidence=llm_confidence,
            llm_rationale=llm_rationale,
            llm_skipped_reason=llm_skipped_reason,
            findings=findings,
            engine_errors=fused.engine_errors,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
