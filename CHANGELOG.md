# Changelog

## v0.1.9 (2026-08-30)

### Changed
- Git and zip targets now resolve individual skill directories: each directory containing `SKILL.md` is scanned as its own skill (the repo root counts when it has a `SKILL.md`), files outside skill dirs are ignored, and repos with no skills fail with "no skills found". The CLI reports one result per skill for URL targets.
- GitHub `/tree/<ref>/<subpath>` URLs are supported: the repo root is cloned and discovery is scoped to the subpath (percent-decoded).
- Local targets without a root `SKILL.md` are no longer rejected by `fetch()` — skill discovery decides what gets scanned.

## v0.1.8 (2026-08-30)

### Fixed
- Scanning a git repo URL now derives the skill name from the repository path (e.g. `owner/repo`, `.git` suffix stripped) instead of the temporary clone directory name (`repo`), so report pages and batch output name multi-repo scans correctly when no `SKILL.md` exists at the repo root.

## v0.1.7 (2026-08-29)

### Changed
- GitHub Action: SARIF artifact upload now tolerates a missing file (`if-no-files-found: ignore`) so a crashed scan doesn't fail the upload step.
- README GitHub Action example: `codeql-action/upload-sarif` step now uses `if: always()` so Code Scanning still gets results when the scan step fails.

## v0.1.6 (2026-08-29)

### Added
- CI scan summary now shows richer per-skill detail: finding counts, engine errors, LLM verdict/confidence/rationale when LLM review ran, and why the LLM was skipped otherwise.

## v0.1.5 (2026-08-29)

### Changed
- README GitHub Action example: document `SKILLGUARD_SEMANTIC_MODEL` as required for LLM review and clarify that the action stores the SARIF as a workflow artifact while the `codeql-action/upload-sarif` step feeds GitHub Code Scanning.

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
