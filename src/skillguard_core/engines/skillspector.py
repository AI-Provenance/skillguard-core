import json
import subprocess
import tempfile
import time
from pathlib import Path

from skillguard_core.engines.base import (
    EngineFinding,
    EngineResult,
    Runner,
    make_fingerprint,
    normalize_severity,
    truncate_evidence,
)


class SkillspectorEngine:
    name = "skillspector"

    def __init__(self, binary: str = "skillspector", timeout_s: int = 300, runner: Runner = subprocess.run):
        self.binary = binary
        self.timeout_s = timeout_s
        self.runner = runner

    def scan(self, path: Path) -> EngineResult:
        started = time.monotonic()
        with tempfile.TemporaryDirectory() as td:
            report_path = Path(td) / "report.json"
            cmd = [
                self.binary, "scan", str(path),
                "--no-llm", "--format", "json", "--output", str(report_path),
            ]
            try:
                proc = self.runner(cmd, capture_output=True, text=True, timeout=self.timeout_s)
            except subprocess.TimeoutExpired:
                return EngineResult(engine=self.name, error=f"timeout after {self.timeout_s}s", duration_ms=self._ms(started))
            if not report_path.exists():
                tail = (proc.stderr or proc.stdout or "").strip()[-2000:]
                return EngineResult(engine=self.name, error=f"no report produced: {tail}", duration_ms=self._ms(started))
            data = json.loads(report_path.read_text())
        return self._parse(data, started)

    def _parse(self, data: dict, started: float) -> EngineResult:
        findings: list[EngineFinding] = []
        for f in data.get("findings", []):
            finding = EngineFinding(
                engine=self.name,
                rule_id=str(f.get("rule_id") or f.get("id") or ""),
                category=str(f.get("category") or ""),
                title=str(f.get("title") or f.get("description") or ""),
                severity=normalize_severity(f.get("severity")),
                file_path=str(f.get("file") or f.get("path") or ""),
                evidence=truncate_evidence(f.get("snippet") or f.get("evidence")),
            )
            finding.fingerprint = make_fingerprint(self.name, finding.rule_id, finding.file_path, finding.title)
            findings.append(finding)
        score = data.get("risk_score")
        return EngineResult(
            engine=self.name,
            score=int(score) if score is not None else None,
            findings=findings,
            duration_ms=self._ms(started),
        )

    @staticmethod
    def _ms(started: float) -> int:
        return int((time.monotonic() - started) * 1000)
