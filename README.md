# pydepaudit

[![PyPI](https://img.shields.io/pypi/v/pydepaudit)](https://pypi.org/project/pydepaudit/)
[![CI](https://github.com/MathiasPaulenko/pydepaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/MathiasPaulenko/pydepaudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Audit your Python dependencies for **vulnerabilities, licenses, staleness and maintainer health** in a single command.

`pip-audit` tells you what is vulnerable. `pydepaudit` tells you what is vulnerable, illegal, abandoned or fragile.

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
pydepaudit check --fail-on high   # exit 1 on findings >= severity
pydepaudit check --license MIT    # declare your project license for compat checks
pydepaudit check --no-cache       # bypass the local HTTP cache
pydepaudit show requests          # details for one dependency
```

Dependency files are discovered in this order — the first one found wins:

1. `uv.lock` (exact pinned versions)
2. `requirements.txt`
3. `pyproject.toml` (PEP 621 dependencies, including optional-dependencies)

## What it checks

| Dimension | Source | Severity logic |
|---|---|---|
| CVEs | [OSV API](https://osv.dev) (`querybatch`) | critical/high/medium/low per GHSA or CVSS score |
| Licenses | PyPI metadata | GPL/AGPL/SSPL → high · LGPL/MPL/EPL → medium · unknown → low |
| Age | PyPI releases | stale >18mo → medium · 12–18mo → low |
| Maintainer | GitHub API (via `project_urls`) | archived → high · single inactive contributor → medium · inactive repo → low |

All sources are public and free. GitHub works unauthenticated (60 req/h); export
`GITHUB_TOKEN` for higher rate limits.

## CI

One line in your pipeline:

```yaml
- run: pydepaudit check --fail-on high
```

Exit codes: `0` clean or below threshold, `1` findings at/above `--fail-on`, no
dependency files found, or audit failure, `2` invalid arguments or config.

## Configuration

The project license is autodetected from `pyproject.toml` or `LICENSE`; declare it
explicitly with `--license` or `project_license` when detection misses.

Optional `.pydepaudit.toml` in the project root:

```toml
stale_months = 12            # low finding past this age
stale_medium_months = 18     # medium finding past this age
inactive_months = 12         # repo inactivity threshold
project_license = "MIT"      # copyleft deps are allowed if this is copyleft
denied_licenses = ["GPL", "AGPL", "SSPL"]

[ignore]
legacy-lib = "vendored fork, upstream abandoned on purpose"
```

## Cache

HTTP responses are cached in `.pydepaudit-cache/` (1h TTL) so repeated runs stay
fast and don't hammer the APIs. Add it to your `.gitignore` or use `--no-cache`.

## Status

Early development — the CLI surface may change before 1.0.

## License

MIT
