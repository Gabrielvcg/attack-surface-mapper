from pathlib import Path


def test_public_project_text_has_no_mojibake_markers() -> None:
    root = Path(__file__).resolve().parents[1]
    source_files = [
        root / "main.py",
        root / "README.md",
        root / "CHANGELOG.md",
        root / "pyproject.toml",
        *sorted((root / "src").rglob("*.py")),
    ]
    offenders = [
        str(path.relative_to(root))
        for path in source_files
        if any(marker in path.read_text(encoding="utf-8") for marker in ("Ã", "Â", "â€", "�"))
    ]

    assert offenders == []
