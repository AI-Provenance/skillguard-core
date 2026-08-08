# skillguard-core

Security scanner for AI agent skills. Wraps NVIDIA SkillSpector and Cisco
skill-scanner, fuses their findings into a verdict, and reports via JSON,
SARIF, or CI exit codes. Apache-2.0.

Part of SkillGuard — continuous trust for AI agent skills. Hosted drift
monitoring and CI policy live at skillguard.dev.

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
