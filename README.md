# pydepaudit

Audit your Python dependencies for **vulnerabilities, licenses, staleness and maintainer health** in a single command.

`pip-audit` tells you what is vulnerable. `pydepaudit` tells you what is vulnerable, illegal, abandoned or fragile.

## Features

- **CVEs** — known vulnerabilities per dependency + version, via the [OSV](https://osv.dev) API (same source as `pip-audit`, no auth required)
- **Licenses** — flags GPL/AGPL/SSPL and licenses incompatible with your project
- **Age** — warns when the last release is too old
- **Maintainer health** — upstream repo signals (maintainers, activity, archived flag) via the GitHub API

## Usage

```bash
pydepaudit check                  # audit pyproject.toml / requirements.txt / uv.lock
pydepaudit check --format json    # machine-readable output for CI
pydepaudit check --fail-on high   # exit 1 on findings >= severity
pydepaudit show requests          # details for one dependency
```

## Status

Early development — the CLI surface is not stable yet.

## License

MIT
