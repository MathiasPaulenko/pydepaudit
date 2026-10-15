from pathlib import Path

from pydepaudit.parsers import parse_project


def test_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "# comment\n"
        "requests==2.31.0\n"
        "httpx>=0.27  # inline comment\n"
        "\n"
        "-r other.txt\n"
        "not a valid requirement ~~\n"
        "typer\n"
    )
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [
        ("requests", "==2.31.0"),
        ("httpx", ">=0.27"),
        ("typer", ""),
    ]
    assert all(d.source == "requirements.txt" for d in deps)


def test_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        'dependencies = ["requests>=2", "rich"]\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest>=8"]\n'
    )
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [
        ("requests", ">=2"),
        ("rich", ""),
        ("pytest", ">=8"),
    ]


def test_uvlock(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "demo"\nversion = "0.1.0"\n'
        'source = { editable = "." }\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n\n'
        '[[package]]\nname = "rich"\nversion = "13.7.1"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [
        ("requests", "==2.31.0"),
        ("rich", "==13.7.1"),
    ]


def test_lock_priority_over_requirements(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    (tmp_path / "requirements.txt").write_text("rich\n")
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["requests"]


def test_requirements_url_fragment(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "pkg @ https://example.com/pkg-1.0.tar.gz#sha256=abc\n"
    )
    deps = parse_project(tmp_path)
    assert deps[0].name == "pkg"


def test_requirements_hashes_and_continuation(tmp_path: Path) -> None:
    # pip-compile style: inline --hash and backslash continuations
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0 \\\n"
        "    --hash=sha256:abc123 \\\n"
        "    --hash=sha256:def456\n"
        "rich>=13 \\\n"
        "    --hash=sha256:999\n"
    )
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [
        ("requests", "==2.31.0"),
        ("rich", ">=13"),
    ]


def test_pyproject_dependency_groups(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests"]\n'
        '[dependency-groups]\ndev = ["pytest", {include-group = "lint"}]\n'
        'lint = ["ruff>=0.6"]\n'
    )
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == ["pytest", "requests", "ruff"]


def test_pyproject_malformed_shapes(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        'dependencies = "requests"  # wrong type: string, not list\n'
        "[project.optional-dependencies]\n"
        'dev = "pytest"  # wrong type too\n'
    )
    assert parse_project(tmp_path) == []


def test_uvlock_skips_non_string_names(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = 42\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n\n'
        '[[package]]\nname = "ok"\nversion = "2.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["ok"]


def test_requirements_include_r(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("maindep\n-r extra.txt\n")
    (tmp_path / "extra.txt").write_text("extradep>=2.0\n")
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == ["extradep", "maindep"]


def test_requirements_include_cycle(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("a-dep\n-r loop.txt\n")
    (tmp_path / "loop.txt").write_text("b-dep\n-r requirements.txt\n")
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == ["a-dep", "b-dep"]


def test_requirements_include_missing(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("maindep\n-r gone.txt\n")
    assert [d.name for d in parse_project(tmp_path)] == ["maindep"]


def test_requirements_constraint_applies_pin(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pkg>=1.0\n-c pins.txt\n")
    (tmp_path / "pins.txt").write_text("pkg==1.2.3\nother==9.9\n")
    deps = parse_project(tmp_path)
    # constraint narrows the declared dep; non-declared constraint ignored
    assert [(d.name, d.specifier) for d in deps] == [("pkg", ">=1.0,==1.2.3")]


def test_requirements_markers(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        'alwaysdep\nsysdep; sys_platform == "nonexistent-os"\n'
    )
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["alwaysdep"]


def test_pyproject_markers(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        'dependencies = ["okdep", \'skipdep; sys_platform == "nonexistent-os"\']\n'
    )
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["okdep"]


def test_requirements_include_longform(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("maindep\n--requirement=sub/extra.txt\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "extra.txt").write_text("nesteddep\n")
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == ["maindep", "nesteddep"]


def test_requirements_trailing_continuation(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pkg>=1.0 \\\n")
    deps = parse_project(tmp_path)
    assert deps[0].name == "pkg"


def test_poetrylock(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n\n'
        '[[package]]\nname = "rich"\nversion = "13.7.1"\n'
    )
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [
        ("requests", "==2.31.0"),
        ("rich", "==13.7.1"),
    ]


def test_poetrylock_skips_non_string_names(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = 42\nversion = "1.0"\n\n'
        '[[package]]\nname = "ok"\nversion = "2.0"\n'
    )
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["ok"]


def test_pyproject_without_project_table(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.black]\nline-length = 88\n")
    assert parse_project(tmp_path) == []


def test_pyproject_skips_invalid_requirements(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "1.0"\n'
        'dependencies = ["okdep", "!!not-a-req!!", 42]\n'
    )
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["okdep"]


def test_installed_parser() -> None:
    from pydepaudit.parsers import installed

    deps = installed.parse()
    # the dev environment always has pydepaudit itself installed
    names = {d.name.lower() for d in deps}
    assert "pydepaudit" in names
    assert all(d.specifier.startswith("==") for d in deps)


def test_no_files(tmp_path: Path) -> None:
    assert parse_project(tmp_path) == []
