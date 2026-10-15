# pydepaudit

[![PyPI](https://img.shields.io/pypi/v/pydepaudit)](https://pypi.org/project/pydepaudit/)
[![CI](https://github.com/MathiasPaulenko/pydepaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/MathiasPaulenko/pydepaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit Python dependencies for **known vulnerabilities, license-policy signals,
release staleness, yanked releases and repository health** in one command.

`pydepaudit` complements vulnerability scanners with metadata-driven license and
maintenance signals. It does not determine whether a package is legally
compliant or safe to use.

```text
$ pydepaudit check

Package    Declared   Status   Details
requests   2.31.0     ✅       no CVEs · Apache-2.0 · 8d ago · 157 contributors
urllib3    1.26.5     ⚠️       GHSA-34jh-... (CVE-2023-43804) | stale 14mo
some-lib   0.4.1      🔴       copyleft license: GPL-3.0 | single contributor, inactive 24mo

3 findings: 1 high, 2 medium
```

## Install

```bash
pip install pydepaudit
# or
pipx install pydepaudit
```

Requires Python 3.11+.

## Usage

```bash
pydepaudit check                  # audit pyproject.toml / requirements.txt / uv.lock
pydepaudit check --format json    # machine-readable output for CI
pydepaudit check --format sarif   # SARIF for GitHub code scanning
pydepaudit check --fail-on high   # exit 1 on findings >= severity
pydepaudit check --license MIT    # declare your project license for compat checks
pydepaudit check --no-cache       # bypass the local HTTP cache
pydepaudit check --installed      # audit the live environment instead
pydepaudit show requests          # details for one dependency
```

`--fail-on` accepts `low`, `medium`, `high` or `critical`. Ignored dependencies
do not count toward the threshold.

Dependency files are discovered in this order — the first one found wins:

1. `uv.lock` (exact pinned versions)
2. `poetry.lock`
3. `requirements.txt`
4. `pyproject.toml` (PEP 621 dependencies, optional-dependencies and PEP 735 dependency-groups)

## Reports

JSON output has a top-level `dependencies` array. Each entry includes the
declared dependency, status, PyPI metadata, optional `repo_health`, vulnerability
records (including `fixed` when OSV provides a fixing version), and findings.
SARIF output follows version 2.1.0 and can be uploaded to GitHub code scanning.

## What it checks

| Dimension | Source | Severity logic |
|---|---|---|
| Vulnerabilities | [OSV API](https://osv.dev) (`querybatch`) | OSV severity or supported CVSS score |
| License policy | PyPI metadata | denied alternatives only → high; weak-copyleft without a permissive option → medium; unknown metadata → low |
| Release age | PyPI release metadata | at least 18 months → medium; at least 12 months → low |
| Yanked pin | PyPI release metadata | exact pin to a fully yanked release → medium |
| Repository | GitHub and OpenSSF Scorecard | archived → high; one inactive contributor → medium; inactivity or low Scorecard → low |

All data sources are public. GitHub works unauthenticated (60 requests/hour);
set `GITHUB_TOKEN` for a higher rate limit. The token is sent only to
`api.github.com`.

License checks are heuristic: they compare PyPI license metadata with configured
substring patterns and recognize simple `OR` alternatives. They are not a full
SPDX evaluator or legal advice. Review the actual license terms before making a
compliance decision.

## CI

One line in your pipeline:

```yaml
- run: pydepaudit check --fail-on high
```

Or use the GitHub Action:

```yaml
- uses: MathiasPaulenko/pydepaudit@v1.0.0
  with:
    fail-on: high
```

Or upload findings to GitHub code scanning:

```yaml
- run: pydepaudit check --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v4
  with: {sarif_file: results.sarif}
```

Without `--fail-on`, findings alone do not change the exit code. Exit codes:
`0` unless a finding reaches the selected `--fail-on` threshold;
`1` when that threshold is reached, no dependency files are found, or the audit
fails; `2` for invalid arguments or configuration.

## Configuration

The project license is autodetected from `pyproject.toml` or `LICENSE`; declare it
explicitly with `--license` or `project_license` when detection misses.

Optional `.pydepaudit.toml` in the project root:

```toml
stale_months = 12            # low finding past this age
stale_medium_months = 18     # medium finding past this age
inactive_months = 12         # repo inactivity threshold
scorecard_min = 5.0           # low finding below this Scorecard score (0–10)
project_license = "MIT"      # copyleft deps are allowed if this is copyleft
denied_licenses = ["GPL", "AGPL", "SSPL"]

[ignore]
legacy-lib = "vendored fork, upstream abandoned on purpose"
```

Month thresholds must be non-negative integers, and
`stale_medium_months` must be greater than or equal to `stale_months`.
`scorecard_min` must be between 0 and 10. `[ignore]` suppresses all findings for
each listed package; keep a reason so the exception is reviewable.

## Cache

HTTP responses are cached for one hour in the per-user cache directory, outside
the audited project. This avoids trusting cache files supplied by a repository.
Use `--no-cache` to bypass the cache.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, test workflow and commit
conventions. Security issues go to [SECURITY.md](SECURITY.md), never to public
issues.

## Status

Stable 1.0.0 release. See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
