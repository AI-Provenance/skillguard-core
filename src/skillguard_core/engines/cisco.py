import json
import subprocess
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


class CiscoScannerEngine:
    name = "cisco"

    def __init__(
        self,
        binary: str = "skill-scanner",
        policy: str = "balanced",
        timeout_s: int = 300,
        runner: Runner = subprocess.run,
    ):
        self.binary = binary
        self.policy = policy
        self.timeout_s = timeout_s
        self.runner = runner

    def scan(self, path: Path) -> EngineResult:
        started = time.monotonic()
        cmd = [self.binary, "scan", str(path), "--policy", self.policy, "--format", "json"]
        try:
            proc = self.runner(cmd, capture_output=True, text=True, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            return EngineResult(engine=self.name, error=f"timeout after {self.timeout_s}s", duration_ms=self._ms(started))
        except OSError as exc:
            return EngineResult(engine=self.name, error=f"runner failed: {exc}", duration_ms=self._ms(started))
        stdout = (proc.stdout or "").strip()
        if not stdout:
            tail = (proc.stderr or "").strip()[-2000:]
            return EngineResult(engine=self.name, error=f"no json output: {tail}", duration_ms=self._ms(started))
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return EngineResult(engine=self.name, error=f"invalid json: {exc}", duration_ms=self._ms(started))
        return self._parse(data, started)

    def _parse(self, data: dict, started: float) -> EngineResult:
        findings: list[EngineFinding] = []
        for f in data.get("findings") or []:
            finding = EngineFinding(
                engine=self.name,
                rule_id=str(f.get("id") or f.get("rule_id") or ""),
                category=str(f.get("category") or ""),
                title=str(f.get("title") or f.get("description") or ""),
                severity=normalize_severity(f.get("severity")),
                file_path=str(f.get("path") or f.get("file") or ""),
                evidence=truncate_evidence(f.get("snippet") or f.get("evidence")),
            )
            finding.fingerprint = make_fingerprint(self.name, finding.rule_id, finding.file_path, finding.title)
            findings.append(finding)
        return EngineResult(engine=self.name, score=None, findings=findings, duration_ms=self._ms(started))

    @staticmethod
    def _ms(started: float) -> int:
        return int((time.monotonic() - started) * 1000)
