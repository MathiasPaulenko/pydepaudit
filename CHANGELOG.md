# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: package layout, CLI skeleton (`check`, `show`), lint/type-check/test tooling and CI.
- Dependency parsing for uv.lock, requirements.txt and pyproject.toml.
- PyPI metadata per dependency: latest version, license and last release date.
- CVE audit via the OSV API with GHSA/CVSS severity mapping.
- Maintainer health via the GitHub API: archived flag, last push, contributor count.
- Findings engine with severities, `.pydepaudit.toml` config, `--fail-on` and `--license` options.
- Local HTTP cache (1h TTL, `--no-cache` to bypass) and parallel source fetching.
- poetry.lock parsing, PEP 735 dependency-groups and pip-compile-style
  requirements (inline `--hash`, line continuations); dual-license (SPDX `OR`)
  handling; project license autodetection from pyproject.toml/LICENSE.
- Graceful handling of malformed API payloads, dependency files, network errors
  and non-UTF-8 consoles.

### Added (v0.2 preview)

- Vulnerability records are deduplicated by shared CVE/GHSA/PYSEC aliases and
  now carry `fixed` — the earliest version resolving the vuln — shown in the
  table and JSON output.
- Yanked-version detection: an exact pin to a release yanked from PyPI
  (PEP 592) produces a medium finding.
- CVSS v4.0 scoring (macrovector + interpolation, ported from the official
  FIRST reference implementation) — v4 vectors now resolve to severities
  instead of `unknown`.
- requirements.txt `-r`/`--requirement` includes are followed recursively
  (cycle-safe); `-c`/`--constraint` files narrow declared pins, pip-style.
- Environment markers (`; sys_platform == ...`) are evaluated against the
  current platform — inapplicable requirements are not audited.
- `check --installed` audits the live environment via `importlib.metadata`
  instead of declared dependency files.
- `--format sarif` emits SARIF 2.1.0 for GitHub code scanning upload.
- OpenSSF Scorecard as an extra maintainer-health signal: repos scoring below
  `scorecard_min` (default 5.0, configurable in `.pydepaudit.toml`) produce a
  low-severity finding; `show` prints the score.
- Composite GitHub Action (`action.yml`): `uses: MathiasPaulenko/pydepaudit@v*`.

### Fixed

- OSV `querybatch` returns trimmed records (id + modified only); vulnerability
  details are now hydrated from `/v1/vulns/{id}` in parallel and cached, so
  severities, aliases and summaries are complete.
