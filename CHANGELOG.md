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

### Fixed

- OSV `querybatch` returns trimmed records (id + modified only); vulnerability
  details are now hydrated from `/v1/vulns/{id}` in parallel and cached, so
  severities, aliases and summaries are complete.
