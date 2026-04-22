#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
DOC_REF_RE = re.compile(r"(?<![A-Za-z0-9_./-])((?:\./|\.\./)?[A-Za-z0-9_./-]+\.md)(?![A-Za-z0-9_./-])")
MAKE_RE = re.compile(r"\bmake(?:\s+-C\s+([^\s`]+))?\s+([A-Za-z0-9_.-]+)\b")
TARGET_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?![=])", re.MULTILINE)


def should_skip_path(path_text: str) -> bool:
    return (
        not path_text
        or path_text.startswith(("http://", "https://", "mailto:", "#"))
        or path_text.startswith("/")
        or path_text.startswith("output/")
        or "/output/" in path_text
        or "://" in path_text
        or "<" in path_text
        or ">" in path_text
    )


def parse_make_targets(makefile: Path) -> set[str]:
    return {match.group(1) for match in TARGET_RE.finditer(makefile.read_text())}


def resolve_markdown_path(markdown_file: Path, path_text: str) -> Path:
    return (markdown_file.parent / path_text).resolve()


def resolve_makefile(repo_root: Path, dir_arg: str | None) -> Path:
    workdir = repo_root if not dir_arg else (repo_root / dir_arg).resolve()
    return workdir / "Makefile"


def validate_doc_paths(markdown_file: Path, repo_root: Path, errors: list[str]) -> None:
    seen: set[tuple[int, str]] = set()
    lines = markdown_file.read_text().splitlines()
    for lineno, line in enumerate(lines, start=1):
        for match in LINK_RE.finditer(line):
            path_text = match.group(1).strip()
            if should_skip_path(path_text):
                continue
            key = (lineno, path_text)
            if key in seen:
                continue
            seen.add(key)
            target = resolve_markdown_path(markdown_file, path_text)
            if not target.exists():
                errors.append(
                    f"{markdown_file}:{lineno}: missing local doc reference `{path_text}`"
                )
        for match in DOC_REF_RE.finditer(line):
            path_text = match.group(1).strip()
            if should_skip_path(path_text):
                continue
            key = (lineno, path_text)
            if key in seen:
                continue
            seen.add(key)
            target = resolve_markdown_path(markdown_file, path_text)
            if not target.exists():
                errors.append(
                    f"{markdown_file}:{lineno}: missing local doc reference `{path_text}`"
                )


def validate_make_commands(markdown_file: Path, repo_root: Path, errors: list[str]) -> None:
    cached_targets: dict[Path, set[str]] = {}
    lines = markdown_file.read_text().splitlines()
    for lineno, line in enumerate(lines, start=1):
        for match in MAKE_RE.finditer(line):
            dir_arg, target = match.groups()
            if "<" in target or ">" in target or target.startswith("$"):
                continue
            makefile = resolve_makefile(repo_root, dir_arg)
            if not makefile.exists():
                display_dir = dir_arg or "."
                errors.append(
                    f"{markdown_file}:{lineno}: missing Makefile for `make -C {display_dir} {target}`"
                )
                continue
            if makefile not in cached_targets:
                cached_targets[makefile] = parse_make_targets(makefile)
            if target not in cached_targets[makefile]:
                prefix = f"make -C {dir_arg}" if dir_arg else "make"
                errors.append(
                    f"{markdown_file}:{lineno}: unknown target `{target}` in `{prefix} {target}`"
                )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate repository docs and command references")
    parser.add_argument("markdown_files", nargs="+", type=Path)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    errors: list[str] = []
    for markdown_file in args.markdown_files:
        if not markdown_file.exists():
            errors.append(f"{markdown_file}: file does not exist")
            continue
        validate_doc_paths(markdown_file, repo_root, errors)
        validate_make_commands(markdown_file, repo_root, errors)

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("docs check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
