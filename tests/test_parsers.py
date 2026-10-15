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


def test_no_files(tmp_path: Path) -> None:
    assert parse_project(tmp_path) == []
