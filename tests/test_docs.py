"""Проверка документации: ссылки, якоря, команды, флаги, версия.

Запуск: python tests/test_docs.py
Сеть не нужна.
"""
import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# консоль Windows по умолчанию cp1251: русский текст и рамки падают при печати
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import cli  # noqa: E402

DOC_FILES = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "CHANGELOG.md",
    *sorted((ROOT / "docs").glob("*.md")),
]

FENCE_RE = re.compile(r"^\s*(```|~~~)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
PERIMETER_RE = re.compile(r"(?<![\w-])perimeter(?:\.exe)?\s+([^\n`]*)")
LONG_FLAG_RE = re.compile(r"(?<!\S)--[a-z][a-z0-9-]+")
ENV_RE = re.compile(r"\bPERIMETER_[A-Z][A-Z0-9_]*\b")

KNOWN_ENV = {"PERIMETER_WORDLIST"}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def slugify(title: str) -> str:
    """GitHub-якорь: нижний регистр, пунктуация убрана, каждый пробел -> '-'."""
    text = title.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    return re.sub(r"\s", "-", text)


def collect_headings(text: str) -> list[str]:
    anchors = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_RE.match(line)
        if match:
            anchors.append(slugify(match.group(2)))
    return anchors


def collect_parser_surface() -> tuple[set[str], set[str]]:
    commands: set[str] = set()
    options: set[str] = set()

    def walk(parser):
        for action in parser._actions:
            options.update(action.option_strings)
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    commands.add(name)
                    walk(child)

    walk(cli.build_parser())
    return commands, options


def check_links(anchors: dict[Path, list[str]]) -> list[str]:
    errors = []
    for path in DOC_FILES:
        text = read(path)
        for raw_target in LINK_RE.findall(text):
            target = raw_target.split()[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "tel:")):
                continue

            target = unquote(target)
            file_part, _, fragment = target.partition("#")

            if file_part:
                resolved = (path.parent / file_part).resolve()
                if not resolved.exists():
                    errors.append(f"{path.name}: ссылка на несуществующий файл: {file_part}")
                    continue
            else:
                resolved = path

            if fragment and resolved.suffix == ".md":
                wanted = fragment.lower()
                if wanted not in anchors.get(resolved, []):
                    errors.append(f"{path.name}: якорь не найден: {target}")
    return errors


def check_examples(commands: set[str], options: set[str]) -> list[str]:
    errors = []
    for path in DOC_FILES:
        for lineno, line in enumerate(read(path).splitlines(), start=1):
            for segment in PERIMETER_RE.findall(line):
                tokens = segment.split()
                if not tokens:
                    continue
                command = tokens[0]
                if re.fullmatch(r"[a-z][a-z0-9-]*", command) and command not in commands:
                    errors.append(f"{path.name}:{lineno}: неизвестная команда '{command}'")
                for flag in LONG_FLAG_RE.findall(segment):
                    flag = flag.split("=")[0]
                    if flag not in options:
                        errors.append(f"{path.name}:{lineno}: неизвестный флаг '{flag}'")
    return errors


def check_env() -> list[str]:
    errors = []
    for path in DOC_FILES:
        for name in set(ENV_RE.findall(read(path))):
            if name not in KNOWN_ENV:
                errors.append(f"{path.name}: неизвестная переменная окружения {name}")
    return errors


def has_h1(text: str) -> bool:
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence and re.match(r"^#\s+\S", line):
            return True
    return False


def check_structure() -> list[str]:
    errors = []
    for path in DOC_FILES:
        fences = sum(1 for line in read(path).splitlines() if FENCE_RE.match(line))
        if fences % 2:
            errors.append(f"{path.name}: нечётное число границ блоков кода ({fences})")
    return errors


def check_version_and_nav() -> list[str]:
    errors = []
    pyproject = read(ROOT / "pyproject.toml")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not match:
        return ["pyproject.toml: не найдена version"]
    version = match.group(1)

    changelog = read(ROOT / "CHANGELOG.md")
    if f"## [{version}]" not in changelog:
        errors.append(f"CHANGELOG.md: нет раздела ## [{version}]")
    if "## [Unreleased]" not in changelog:
        errors.append("CHANGELOG.md: нет раздела ## [Unreleased]")

    index = read(ROOT / "docs" / "README.md")
    for name in ("usage.md", "reference.md", "architecture.md"):
        if name not in index:
            errors.append(f"docs/README.md: не ссылается на {name}")

    readme = read(ROOT / "README.md")
    for name in ("docs/README.md", "CONTRIBUTING.md", "CHANGELOG.md", "LICENSE"):
        if name not in readme:
            errors.append(f"README.md: не ссылается на {name}")

    for path in DOC_FILES:
        if not has_h1(read(path)):
            errors.append(f"{path.name}: нет заголовка первого уровня")
    return errors


def main() -> int:
    anchors = {path: collect_headings(read(path)) for path in DOC_FILES}
    commands, options = collect_parser_surface()

    errors = []
    errors += check_links(anchors)
    errors += check_examples(commands, options)
    errors += check_env()
    errors += check_structure()
    errors += check_version_and_nav()

    if errors:
        for error in errors:
            print(f"FAIL {error}")
        print(f"\nДокументация: {len(errors)} ошибок")
        return 1

    print(f"OK: документация проверена ({len(DOC_FILES)} файлов, "
          f"{len(commands)} команд, {len(options)} флагов)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
