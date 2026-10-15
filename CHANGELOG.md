# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-15

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
- CVSS v4: strict vector validation (invalid metric values no longer crash the
  scorer), `MSI/MSA` correctly default to base `SI/SA`, and the final rounding
  now matches the reference implementation's half-up epsilon rule.
- A malformed pin in a lock file no longer aborts the whole audit — the
  dependency falls back to its latest released version.
- requirements.txt: UTF-8 BOM files are parsed, `-r` inside a `-c` file stays
  a constraint (no phantom dependencies), `-cfile` attached form is supported,
  and include targets that can't be resolved are skipped instead of crashing.
- Malformed API payloads harden end to end: non-dict PyPI/GitHub bodies, bad
  upload timestamps, non-string license fields, corrupt cache files and OSV
  hydration failures degrade cleanly instead of crashing.
- GitHub 403 responses (rate limiting) are treated as transient and are no
  longer cached as "repository not found".
- Auxiliary endpoints (contributors, Scorecard) failing no longer kills the
  audit; the signals degrade to `None`.
- OSV queries now use the canonical PyPI package name, and yanked-version
  detection compares PEP 440 versions (`==1.0.0` matches yanked `1.0`).
- Terminal output sanitizes control/bidi characters in untrusted upstream text
  (package names, license strings, vuln summaries) — no more ANSI injection or
  `UnicodeEncodeError` crashes on legacy consoles.
- GitHub repo URLs with `www.github.com` are detected; invalid or hostile repo
  strings are rejected before request construction.
- Config validation rejects wrong types for `denied_licenses`, `ignore` and
  numeric fields with clear errors instead of `TypeError` tracebacks.
- Cache writes are atomic (write-then-rename) so concurrent readers never see
  a torn JSON file.
- SARIF output omits the `locations` block when the dependency has no source
  file instead of emitting an empty `uri`.
- Composite GitHub Action passes inputs via environment variables, closing the
  shell-injection path on `path`/`format`/`fail-on` inputs.
- `GITHUB_TOKEN` was set as a client-level header and therefore sent to
  api.securityscorecards.dev. Auth is now applied per request to GitHub
  endpoints only; third-party calls send an empty `Authorization` header.
- Cache filenames now include a digest (avoiding sanitized-key collisions),
  and each atomic write uses a unique temporary file for concurrent writers.
  Invalid UTF-8 entries are treated as cache misses.
- Distinct version declarations for the same normalized package are no longer
  discarded; contradictory exact pins are not misreported as installable.
- PEP 735 dependency-group includes are flattened with cycle protection, and
  requirements includes support quoted paths containing spaces.
- CVSS v3 vectors now reject malformed headers, duplicate/unknown metrics and
  invalid optional values instead of calculating a score from partial input.
- PyPI timestamps without time zones are normalized to UTC; malformed package
  versions/names and unknown-license sentinels no longer produce unsafe or
  misleading metadata.
- Rich markup in untrusted dependency/license text is rendered literally, and
  terminal sanitization also strips Arabic letter marks and deprecated bidi
  controls without mutating the library caller's stdout configuration.
- `show` reports malformed upstream JSON as a clean CLI error; blank declared
  project-license metadata falls back to LICENSE-file detection.
- Cache records are checked against their package/repository/vulnerability key,
  so a malformed entry cannot substitute metadata for a different object.
- The default HTTP cache is now per-user and outside the audited project;
  checked-in `.pydepaudit-cache` files can no longer poison audit results.
- GitHub API redirects are followed only to HTTPS repository endpoints on
  `api.github.com`; other source clients do not follow redirects. External
  redirects cannot trigger SSRF or receive tokens.
- Excessively nested JSON/TOML and requirement markers now degrade to clean
  parse errors or skipped malformed records instead of leaking recursion
  tracebacks from cache, API, and project-file parsing.
- Cache writes reject non-standard JSON numbers, and long requirements
  continuations are assembled in linear time.
- Requirements includes now parse quoted paths and distinguish constraint and
  requirement visits to the same file; redundant constraints are not repeated.
- Repeated declarations for one package retain distinct version pins, while
  PEP 735 group includes and cycles are handled without dropping dependencies.
- CVSS v3 rejects malformed vectors; non-finite/out-of-range Scorecard values
  and malformed license sentinels no longer distort findings or JSON output.
- SARIF source paths are URI-escaped, and installed-environment results no
  longer claim a fictitious file location.

[Unreleased]: https://github.com/MathiasPaulenko/pydepaudit/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/MathiasPaulenko/pydepaudit/releases/tag/v1.0.0
