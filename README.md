# skillguard-core

Security scanner for AI agent skills. Wraps NVIDIA SkillSpector and Cisco
skill-scanner, fuses their findings into a verdict, and reports via JSON,
SARIF, or CI exit codes. Apache-2.0.

Part of SkillGuard — continuous trust for AI agent skills. Hosted drift
monitoring and CI policy live at skillguard.dev.

## How it works

The scanner follows a deterministic pipeline — no agent framework on the hot path:

```
fetch → engines → fuse → (optional: semantic review) → report
```

1. **Ingest** (`ingest/fetcher.py`) — Fetches a skill from a local directory, Git URL, or zip URL.
   Size-capped with zip bomb protection (path traversal checks, member count limits).

2. **Engines** (`engines/`) — Runs two open-source scanners as subprocesses behind a uniform `EngineResult` interface:
   - **NVIDIA SkillSpector** — Heuristic+LLM-aware static analysis (`engines/skillspector.py`)
   - **Cisco skill-scanner** — Policy-based static analysis (`engines/cisco.py`)
   - Each engine returns parsed findings with severity, fingerprint, and truncated evidence.
   - Runners are injectable — unit tests work without real binaries.

3. **Fusion** (`engines/fusion.py`) — Takes the highest score across engines, maps severity
   thresholds to a verdict: `safe` (<30), `caution` (30–69), `dangerous` (≥70).
   Partial engine failures are surfaced but don't block the verdict.

4. **Semantic review** (`semantic/reviewer.py`) — Optional BYOK Deep Agents pass.
   Activates only when `--use-llm` is set and the fused verdict is `caution`.
   Slim harness: no subagents, no filesystem tools, structured `ReviewDecision` output.
   Returns `None` gracefully when no API key is configured.

5. **Report** — The `ScanReport` dataclass (`pipeline/scan.py`) is storage-agnostic:
   no database, no persistence — the private repo plugs in a store.

## Install

```bash
pipx install skillguard-core
uv tool install git+https://github.com/NVIDIA/skillspector.git
uv tool install git+https://github.com/cisco-ai-defense/skill-scanner.git
```

## Usage

```bash
skillguard scan ./my-skill                 # human output
skillguard scan ./my-skill --json          # machine output
skillguard scan ./my-skill --sarif         # SARIF 2.1.0
skillguard scan ./my-skill --use-llm       # semantic review (needs SKILLGUARD_ANTHROPIC_API_KEY)
```

Exit codes: `0` safe · `1` caution · `2` dangerous · `3` inconclusive/error.

## GitHub Action

```yaml
- uses: skillguardai/skillguard-core@v0
  with:
    path: skills/my-skill
    fail-on: dangerous
```

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[ai,dev]"
pytest -v                 # unit tests (no scanner binaries required)
pytest -m integration -v  # requires real scanner binaries
```
