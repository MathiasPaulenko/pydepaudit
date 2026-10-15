# Security Policy

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| < latest| no        |

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities.

Report them privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (private vulnerability reporting).
3. Include a description, affected versions and reproduction steps.

You will get an acknowledgement as soon as possible. If the report is accepted,
a fix release is published and the advisory is disclosed after release.

## Scope

pydepaudit does not modify dependency or source files in the audited project.
It fetches public metadata from PyPI, OSV, GitHub and OpenSSF Scorecard, and
writes HTTP responses to a per-user cache unless `--no-cache` is used. The most
relevant risks are:

- mishandling tokens (`GITHUB_TOKEN` is read from the environment and only sent
  to `api.github.com` — report any code path that could leak it)
- malicious project-supplied cache files or redirects causing false results,
  token exposure or requests to unintended hosts
- unsafe parsing of project files or API responses
- anything that lets a dependency file trigger code execution or unwanted
  network access
