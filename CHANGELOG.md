# Changelog

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
