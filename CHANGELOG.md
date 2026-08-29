# Changelog

## v0.1.4 (2026-08-29)

### Changed
- **CI failure UX**: directory scans with `--sarif` now print the human summary (per-verdict counts and per-skill lines) to stderr, so CI logs show which skills were dangerous without touching the SARIF on stdout.
- GitHub Action scan step now emits a `::error::` annotation on a threshold breach naming the worst verdict, exit code, and `fail-on` threshold, and exposes a `verdict` output.

## v0.1.3 (2026-08-29)

### Fixed
- SARIF output now always includes a `locations` entry per result, with URIs relativized against the scan root (repo root in CI), so GitHub code scanning accepts the uploaded file. Findings without a file path fall back to `SKILL.md`.

## v0.1.2 (2026-08-28)

### Added
- GitHub Action `use-llm` input: enables the LLM reviewer (BYOK) by installing the `ai` extra and passing `--use-llm`. Keys come from the environment via `secrets` (never as inputs): `SKILLGUARD_ANTHROPIC_API_KEY` or `SKILLGUARD_LLM_API_KEY` + `SKILLGUARD_LLM_BASE_URL`.

## v0.1.1 (2026-08-10)

### Added
- `ScanReport` identity fields (`origin`, `source_url`, `version_ref`, `content_hash`, `engines`) are now populated and surfaced in JSON/SARIF output.

### Changed
- **LLM reviewer escalate-only policy**: the reviewer may escalate the fused verdict (e.g. caution→dangerous) but can never downgrade it (e.g. caution→safe). Recorded `llm_verdict` remains transparent.
- `deepagents` pinned to `==0.7.5` in the `ai` extra to avoid breakage from upstream API changes.

### Fixed
- `--use-llm` without the `ai` extra now shows a clear error: `pipx install skillguard-core[ai]`.
- CI scan job hardened: scan step uses `|| true` so malicious fixture exits don't fail the build; integration tests (`pytest -m integration`) are now run in the scan job.

## v0.1.0 (2026-08-08)

Initial public release.
