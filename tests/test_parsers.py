from pathlib import Path

import pytest
from packaging.markers import Marker, UndefinedEnvironmentName

from pydepaudit.parsers import (
    parse_project,
    poetrylock,
    pyproject,
    requirements,
    uvlock,
)
from pydepaudit.parsers.markers import applies_to_env


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


def test_marker_undefined_environment_is_conservative(monkeypatch) -> None:
    def undefined(self, environment=None, context="metadata"):
        raise UndefinedEnvironmentName("unknown")

    monkeypatch.setattr(Marker, "evaluate", undefined)
    assert applies_to_env(Marker("extra == 'test'")) is True


def test_marker_recursion_is_conservative(monkeypatch) -> None:
    def recursive(self, environment=None, context="metadata"):
        raise RecursionError("nested marker")

    monkeypatch.setattr(Marker, "evaluate", recursive)
    assert applies_to_env(Marker("extra == 'test'")) is True


def test_marker_does_not_hide_unexpected_errors(monkeypatch) -> None:
    def broken(self, environment=None, context="metadata"):
        raise RuntimeError("bug")

    monkeypatch.setattr(Marker, "evaluate", broken)
    with pytest.raises(RuntimeError, match="bug"):
        applies_to_env(Marker("extra == 'test'"))


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


def test_pyproject_dependency_group_includes_and_cycles(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[dependency-groups]\n"
        'base = ["base-dep>=1"]\n'
        'dev = [{include-group = "base"}, "dev-dep"]\n'
        'loop = [{include-group = "cycle"}, "loop-dep"]\n'
        'cycle = [{include-group = "loop"}, "cycle-dep"]\n'
    )
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == [
        "base-dep",
        "cycle-dep",
        "dev-dep",
        "loop-dep",
    ]


@pytest.mark.parametrize(
    ("filename", "parser"),
    [
        ("pyproject.toml", pyproject.parse),
        ("poetry.lock", poetrylock.parse),
        ("uv.lock", uvlock.parse),
    ],
)
def test_deeply_nested_toml_is_clean_parse_error(
    tmp_path: Path, filename: str, parser
) -> None:
    (tmp_path / filename).write_text("value = " + "[" * 2000 + "0" + "]" * 2000)
    with pytest.raises(ValueError, match="too deeply nested"):
        parser(tmp_path / filename)


def test_deeply_nested_requirements_are_skipped_without_crashing(
    tmp_path: Path,
) -> None:
    marker_spec = "pkg; " + "(" * 500 + "python_version >= '3.0'" + ")" * 500
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(marker_spec + "\n")
    assert requirements.parse(req_file) == []

    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text('[project]\ndependencies = ["' + marker_spec + '"]\n')
    assert pyproject.parse(pyproject_file) == []


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


def test_requirements_many_continuations_preserve_single_logical_line() -> None:
    from pydepaudit.parsers.requirements import _logical_lines

    lines = _logical_lines("pkg\\\n" + "\\\n" * 5000 + "==1.0")
    assert len(lines) == 1
    assert lines[0].startswith("pkg ")
    assert lines[0].endswith("==1.0")


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


def test_requirements_utf8_bom(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfrequests==2.31.0\n")
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [("requests", "==2.31.0")]


def test_requirements_constraint_attached_form(tmp_path: Path) -> None:
    # pip accepts -cfile.txt (no space) too
    (tmp_path / "requirements.txt").write_text("pkg>=1.0\n-cpins.txt\n")
    (tmp_path / "pins.txt").write_text("pkg==1.2.3\n")
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [("pkg", ">=1.0,==1.2.3")]


def test_requirements_include_with_trailing_option(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("maindep\n-r extra.txt --hash=x\n")
    (tmp_path / "extra.txt").write_text("extradep\n")
    deps = parse_project(tmp_path)
    assert sorted(d.name for d in deps) == ["extradep", "maindep"]


def test_requirements_equal_include_with_trailing_option(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("-r=extra.txt --hash=x\n")
    (tmp_path / "extra.txt").write_text("extradep\n")
    assert [d.name for d in parse_project(tmp_path)] == ["extradep"]


def test_uvlock_malformed_package_table(tmp_path: Path) -> None:
    (tmp_path / "uv.lock").write_text('package = "not-a-list"\n')
    assert parse_project(tmp_path) == []


def test_poetrylock_malformed_package_table(tmp_path: Path) -> None:
    (tmp_path / "poetry.lock").write_text('package = "not-a-list"\n')
    assert parse_project(tmp_path) == []


def test_requirements_include_inside_constraint_is_constraint(tmp_path: Path) -> None:
    # -r inside a -c file is still a constraint — must not create deps
    (tmp_path / "requirements.txt").write_text("pkg\n-c pins.txt\n")
    (tmp_path / "pins.txt").write_text("-r more.txt\npkg==1.2.3\n")
    (tmp_path / "more.txt").write_text("phantom==9.9\n")
    deps = parse_project(tmp_path)
    assert [(d.name, d.specifier) for d in deps] == [("pkg", "==1.2.3")]


def test_requirements_same_file_can_be_requirement_and_constraint(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text("pkg\n-r shared.txt\n-c shared.txt\n")
    (tmp_path / "shared.txt").write_text("pkg==1.2.3\n")
    deps = parse_project(tmp_path)
    assert [d.specifier for d in deps] == ["==1.2.3", "==1.2.3"]


def test_requirements_include_path_with_spaces(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text('-r "sub dir/req file.txt"\n')
    (tmp_path / "sub dir").mkdir()
    (tmp_path / "sub dir" / "req file.txt").write_text("pkg==1.0\n")
    assert [(d.name, d.specifier) for d in parse_project(tmp_path)] == [
        ("pkg", "==1.0")
    ]


def test_requirements_include_nul_byte_target(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pkg==1.0\n-r a\x00b.txt\n")
    deps = parse_project(tmp_path)
    assert [d.name for d in deps] == ["pkg"]


def test_requirements_skips_include_with_symlink_resolution_error(
    tmp_path: Path, monkeypatch
) -> None:
    from pydepaudit.parsers import requirements

    f = tmp_path / "requirements.txt"
    f.write_text("pkg==1.0\n-r bad.txt\n")
    original_resolve = Path.resolve

    def resolve(path: Path, *args, **kwargs) -> Path:
        if path.name == "bad.txt":
            raise RuntimeError("symlink loop")
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    assert [dep.name for dep in requirements.parse(f)] == ["pkg"]


def test_requirements_binary_file_raises(tmp_path: Path) -> None:
    from pydepaudit.parsers import requirements

    f = tmp_path / "requirements.txt"
    f.write_bytes(b"\xff\xfe\x00pkg")
    with pytest.raises(UnicodeDecodeError):
        requirements.parse(f)


def test_uvlock_skips_workspace_members(tmp_path: Path) -> None:
    content = (
        "version = 1\n"
        '[[package]]\nname = "mypkg"\nversion = "1.0"\n'
        "source = { workspace = true }\n"
        '[[package]]\nname = "dep"\nversion = "2.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    (tmp_path / "uv.lock").write_text(content)
    assert [d.name for d in parse_project(tmp_path)] == ["dep"]


def test_poetrylock_skips_local_source_types(tmp_path: Path) -> None:
    content = (
        '[[package]]\nname = "vendored"\nversion = "1.0"\n'
        '[package.source]\ntype = "directory"\nurl = "libs/vendored"\n'
        '[[package]]\nname = "realdep"\nversion = "2.0"\n'
    )
    (tmp_path / "poetry.lock").write_text(content)
    assert [d.name for d in parse_project(tmp_path)] == ["realdep"]


def test_uvlock_empty_version_not_a_pin(tmp_path: Path) -> None:
    # version = "" would produce the invalid specifier "==" — emit no pin
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "pkg"\nversion = ""\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    deps = parse_project(tmp_path)
    assert deps[0].specifier == ""
