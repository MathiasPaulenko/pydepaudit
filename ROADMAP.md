# Roadmap

Ordered by value vs effort. Check items off as they land; each entry should ship
with tests and a CHANGELOG line.

## v0.2 — quality improvements

- [ ] **Dedup vulnerabilities by alias overlap** — OSV returns separate records
      for the same CVE (e.g. `GHSA-8q59` and `PYSEC-2021-142`). Merge entries
      that share a CVE/GHSA alias so each real vulnerability reports once.
- [ ] **Show the fixing version** — OSV `affected[].ranges[].events[].fixed`
      gives the version where each vuln is resolved. Display
      `GHSA-x (fixed in 1.26.19)` in Details and add `fixed_version` to the
      JSON output so findings are actionable.
- [ ] **Detect yanked versions** — PyPI marks releases `yanked` in
      `releases[version][]`. A pinned yanked version should produce a finding
      (suggest `--no-cache` note or a warning-level signal).
- [ ] **CVSS v4 scoring** — OSV now emits `CVSS_V4` vectors; the scorer only
      understands v3.x, so those vulns degrade to `unknown`. Implement the v4
      macrovector computation (EQ1–EQ6).

## v0.3 — coverage of declared deps

- [ ] **Follow `-r` / `-c` includes** in requirements.txt (recursive, with
      cycle protection and missing-file tolerance).
- [ ] **Evaluate environment markers** — `pkg; sys_platform == "win32"` is
      audited on every OS today. Optionally evaluate markers against the
      current environment (or expose both counts in JSON).
- [ ] **`check --installed`** — audit the actual environment via
      `importlib.metadata` instead of declared files. Useful when no lock file
      exists.

## Later

- [ ] SARIF output (`--format sarif`) for GitHub code scanning.
- [ ] OpenSSF Scorecard as an extra maintainer-health signal.
- [ ] GitHub Action (`uses: pydepaudit/action@v1`) once the CLI stabilizes.
