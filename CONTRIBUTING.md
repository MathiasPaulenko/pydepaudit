# Contributing

Thanks for your interest in pydepaudit. Contributions of all kinds are welcome:
bug reports, feature requests, documentation and code.

## Development setup

```bash
git clone https://github.com/MathiasPaulenko/pydepaudit.git
cd pydepaudit
python -m venv .venv
.venv/Scripts/activate      # Windows
source .venv/bin/activate   # Linux/macOS
pip install -e .[dev]
pre-commit install
```

## Workflow

1. Open an issue first for anything non-trivial.
2. Create a branch, make your change, add tests.
3. Keep commits small and use [Conventional Commits](https://www.conventionalcommits.org)
   (`feat:`, `fix:`, `docs:`…).
4. Open a pull request — CI runs lint, type-check and tests on Linux/Windows.

## Checks

Everything must pass before merging:

```bash
ruff check . && ruff format --check .
mypy pydepaudit
pytest
```

- Tests use `pytest` + `respx` for HTTP mocking — no live network calls in tests.
- `mypy --strict` on the package; public APIs need type hints and docstrings.
- New parsers/sources get unit tests; CLI changes get `CliRunner` tests.

## Bug reports

Use the bug report issue template and include:

- `pydepaudit --version` and Python version
- the dependency file being audited (or a minimal reproducer)
- expected vs actual output

## Security issues

Do not open a public issue — see [SECURITY.md](SECURITY.md).
