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
   A directory of skills (subdirs with SKILL.md) is scanned in batch with a progress bar.

2. **Engines** (`engines/`) — Runs two open-source scanners as subprocesses:
   - **NVIDIA SkillSpector** — Heuristic+LLM-aware static analysis
   - **Cisco skill-scanner** — Policy-based static analysis
   - Runners are injectable — unit tests work without real binaries.

3. **Fusion** (`engines/fusion.py`) — Conservative scoring: takes the max of the engine's risk
   score and individual finding severities. Verdicts: `safe` (<30), `caution` (30–69),
   `dangerous` (≥70). Partial engine failures are surfaced but don't block the verdict.

4. **Semantic review** (`semantic/reviewer.py`) — Optional Deep Agents pass triggered on
   `caution` and `dangerous` verdicts (not safe). Supports Anthropic natively or any
   OpenAI-compatible provider via `LLM_API_KEY` + `LLM_BASE_URL`.

5. **Report** — The `ScanReport` dataclass (`pipeline/scan.py`) is storage-agnostic:
   no database, no persistence — the private repo plugs in a store.

## Install

```bash
# Scanner engines (required)
uv tool install git+https://github.com/NVIDIA/skillspector.git
uv tool install git+https://github.com/cisco-ai-defense/skill-scanner.git

# CLI
pipx install skillguard-core                          # from PyPI (once published)
pipx install "git+https://github.com/AI-Provenance/skillguard-core.git@v0.1.0"  # from git
```

For LLM review, install with the `ai` extra:
```bash
pipx install "skillguard-core[ai]"
```

## Usage

```bash
# Single skill
skillguard scan ./my-skill                 # human output
skillguard scan ./my-skill --json          # machine output
skillguard scan ./my-skill --sarif         # SARIF 2.1.0

# Directory of skills (batch)
skillguard scan ./skills                   # progress bar + summary
skillguard scan ./skills -v                # verbose: stream results as they complete

# LLM review (second opinion on caution/dangerous verdicts)
skillguard scan ./my-skill --use-llm       # needs ANTHROPIC_API_KEY or LLM_API_KEY+LLM_BASE_URL
```

Exit codes: `0` safe · `1` caution · `2` dangerous · `3` inconclusive/error.

## LLM Provider Setup

**Anthropic (native structured output):**
```bash
export SKILLGUARD_ANTHROPIC_API_KEY=sk-ant-...
export SKILLGUARD_SEMANTIC_MODEL=claude-sonnet-4-5  # default
```

**Any OpenAI-compatible provider (Ollama, vLLM, Groq, DeepSeek, etc.):**
```bash
export SKILLGUARD_LLM_API_KEY=sk-...
export SKILLGUARD_LLM_BASE_URL=https://api.groq.com/openai/v1
export SKILLGUARD_SEMANTIC_MODEL=llama-3.3-70b
```

## GitHub Action

```yaml
name: Scan skills
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install scanner engines
        run: |
          pipx install git+https://github.com/NVIDIA/skillspector.git
          pipx install git+https://github.com/cisco-ai-defense/skill-scanner.git

      - uses: AI-Provenance/skillguard-core@v0.1.0
        with:
          path: skills/
          fail-on: dangerous    # or "caution" to fail on any warning

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillguard.sarif
```

The action outputs `skillguard.sarif` at the workspace root, compatible with
GitHub Code Scanning.

## Development

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[ai,dev]"
pytest -v                 # unit tests (no scanner binaries required)
pytest -m integration -v  # requires real scanner binaries
```
