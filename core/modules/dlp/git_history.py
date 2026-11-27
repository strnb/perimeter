"""Скан истории git: секреты, удалённые из кода, но оставшиеся в коммитах.

Это главный реальный случай утечки: ключ убрали из файла, но он остался в
прошлых коммитах, откуда его достаёт любой, у кого есть клон репозитория.

Разбирается поток `git log --all -p -U0`: смотрим только добавленные строки
(именно там секрет и появился), номер строки берём из заголовка ханка.
YARA сюда не подключается: её правила проверяют файл целиком, а у нас
в руках отдельные строки диффа.
"""

import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterator

from .results import Finding
from .scanner import EXCLUDED_DIRS, _is_excluded
from .ssh_detector import detect_ssh
from .token_detector import detect_tokens
from .password_detector import detect_passwords
from .connection_detector import detect_connections

COMMIT_MARK = "\x01"
FIELD_SEP = "\x02"
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

DEFAULT_DEPTH = 1000
MAX_LINE_LENGTH = 4000       # строка минифицированного файла — не секрет, а шум
MAX_FINDINGS = 500

DETECTORS = (detect_ssh, detect_tokens, detect_passwords, detect_connections)


def git_available() -> bool:
    return shutil.which("git") is not None


def is_git_repo(path: str) -> bool:
    if not git_available():
        return False
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def repo_root(path: str):
    """Корень репозитория: пути в диффе считаются от него, а не от папки скана."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _git_log(path: str, depth: int):
    return subprocess.Popen(
        [
            "git", "-C", str(path), "log", "--all", "-p", "-U0",
            "--no-merges", "--no-color", "--no-ext-diff",
            "--max-count", str(depth),
            f"--format={COMMIT_MARK}%H{FIELD_SEP}%an{FIELD_SEP}%aI{FIELD_SEP}%s",
        ],
        stdout=subprocess.PIPE,
        # stderr в /dev/null: читать его после stdout можно только до 64 КБ,
        # дальше процесс встанет и скан зависнет
        stderr=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace",
    )


def _commit_fields(line: str) -> dict:
    parts = line[1:].split(FIELD_SEP, 3)
    parts += [""] * (4 - len(parts))
    return {
        "commit": parts[0],
        "author": parts[1][:80],
        "date": parts[2][:10],
        "subject": parts[3][:120],
    }


def iter_added_lines(stream, seen: set | None = None) -> Iterator[tuple[dict, str, int, str]]:
    """(коммит, путь, номер строки в новой версии, текст) для добавленных строк."""
    commit = None
    path = None
    lineno = None
    in_hunk = False

    for raw in stream:
        line = raw.rstrip("\r\n")

        if line.startswith(COMMIT_MARK):
            commit = _commit_fields(line)
            if seen is not None:
                seen.add(commit["commit"])
            path = None
            in_hunk = False
            lineno = None
            continue
        if commit is None:
            continue

        # Новый файл в диффе. Проверяем до состояния ханка: иначе удалённая
        # строка кода, начинающаяся с "diff --git", сломает разбор.
        if line.startswith("diff --git "):
            path = None
            lineno = None
            in_hunk = False
            continue

        if not in_hunk:
            if line.startswith("+++ "):
                # +++ /dev/null — файл удалён, добавленных строк у него нет
                target = line[4:].strip()
                path = target[2:] if target.startswith("b/") else None
                continue
            if line.startswith(("--- ", "index ")):
                continue

        header = HUNK_RE.match(line)
        if header:
            lineno = int(header.group(1))
            in_hunk = True
            continue
        if lineno is None:
            continue

        if line.startswith("+"):
            yield commit, path, lineno, line[1:]
            lineno += 1
        elif line.startswith("-"):
            # удалённая строка не сдвигает нумерацию новой версии
            continue
        elif line.startswith("\\"):
            # "\ No newline at end of file"
            continue
        else:
            lineno += 1


def _scan_line(path: str, lineno: int, text: str) -> list[Finding]:
    file = Path(path)
    findings = []
    for detect in DETECTORS:
        for finding in detect(file, [text]):
            finding.line = lineno
            # путь из диффа всегда posix-вида: так он одинаков на Windows и Linux
            finding.file = path
            findings.append(finding)
    return findings


def _excluded_git_path(path: str) -> bool:
    """Путь из диффа относителен корня репозитория — проверяем все каталоги."""
    directories = set(path.lower().split("/")[:-1])
    if directories & EXCLUDED_DIRS:
        return True
    return any(part.endswith(".egg-info") for part in directories) or _is_excluded(Path(path))


def scan_git_history(repo: str, depth: int = DEFAULT_DEPTH, stats: dict | None = None) -> list[dict]:
    """Находки в добавленных строках истории; один секрет — одна запись.

    В записи: коммит, где секрет появился впервые, автор, дата и сколько
    коммитов его содержат. Если сканируется подпапка, чужие пути не попадают.
    """
    if stats is None:
        stats = {}
    stats.setdefault("git_commits", 0)
    stats.setdefault("git_lines", 0)
    stats.setdefault("git_error", None)

    if not git_available():
        stats["git_error"] = "git не установлен"
        return []
    if not is_git_repo(repo):
        stats["git_error"] = f"это не git-репозиторий: {repo}"
        return []

    depth = max(1, int(depth or DEFAULT_DEPTH))

    # Пути в диффе считаются от корня репозитория: для подпапки нужен префикс
    prefix = ""
    top = repo_root(repo)
    if top:
        try:
            relative_root = Path(repo).resolve().relative_to(Path(top).resolve()).as_posix()
            if relative_root not in ("", "."):
                prefix = relative_root.rstrip("/") + "/"
        except (ValueError, OSError):
            pass

    # ключ -> запись; git log идёт от новых к старым, поэтому старый коммит
    # перезаписывает новый, а счётчик копит все встречи
    found: dict[tuple, dict] = {}
    seen_commits: set = set()
    process = _git_log(repo, depth)

    try:
        for commit, path, lineno, text in iter_added_lines(process.stdout, seen_commits):
            if not path or len(text) > MAX_LINE_LENGTH or _excluded_git_path(path):
                continue
            if prefix and not path.startswith(prefix):
                continue  # находка вне сканируемой папки
            stats["git_lines"] += 1

            for finding in _scan_line(path, lineno, text):
                key = (finding.type, finding.value, path)
                entry = found.get(key)
                if entry is None:
                    entry = finding.to_dict()
                    entry.update({
                        "commit": commit["commit"][:12],
                        "commit_full": commit["commit"],
                        "author": commit["author"],
                        "date": commit["date"],
                        "subject": commit["subject"],
                        "_commits": set(),
                    })
                    found[key] = entry
                else:
                    # более старый коммит: он и есть момент появления секрета
                    entry.update({
                        "commit": commit["commit"][:12],
                        "commit_full": commit["commit"],
                        "author": commit["author"],
                        "date": commit["date"],
                        "subject": commit["subject"],
                        "line": lineno,
                    })
                entry["_commits"].add(commit["commit"])
    finally:
        if process.stdout:
            process.stdout.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        if process.returncode not in (0, None):
            stats["git_error"] = f"git log завершился с кодом {process.returncode}"

    stats["git_commits"] = len(seen_commits)

    findings = list(found.values())[:MAX_FINDINGS]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (order.get(item["severity"], 9), item["date"], item["file"]))
    for item in findings:
        item["commits"] = len(item.pop("_commits"))
        item["source"] = "git"
    return findings
