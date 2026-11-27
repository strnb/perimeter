import os
from pathlib import Path

from .ssh_detector import detect_ssh
from .token_detector import detect_tokens
from .password_detector import detect_passwords
from .connection_detector import detect_connections
from .yara_scanner import run_yara, rules_failed
from .command_injection_detector import detect_command_injection
from .sql_injection_detector import detect_sql_injection
from .weak_session_detector import detect_weak_session

# Каталоги, в которые не заходим: зависимости, сборки, кеши
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", ".idea",
    "dist", "build", "target", "vendor", "coverage", ".next", ".nuxt",
}

# Двоичные форматы — читать их как текст бессмысленно
EXCLUDED_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".pyc", ".jar",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".svgz",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".db", ".sqlite", ".sqlite3",
    # правила самого сканера: они состоят из шаблонов секретов
    ".yar",
}

# Lock-файлы и минифицированный код: тысячи случайных base64-строк
EXCLUDED_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "cargo.lock", "go.sum", "composer.lock", "gemfile.lock", "pipfile.lock",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 МБ в байтах


def _is_excluded(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in EXCLUDED_FILENAMES
        or name.endswith((".min.js", ".min.css", ".map"))
        or path.suffix.lower() in EXCLUDED_EXTENSIONS
    )


def walk_files(root: str) -> list[Path]:
    result = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Отсекаем каталоги до входа в них — иначе rglob обходит .git целиком
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in EXCLUDED_DIRS and not d.lower().endswith(".egg-info")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if not _is_excluded(path):
                result.append(path)

    return result


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    for encoding in ("utf-8", "cp1251"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1")


def read_text(path: Path, stats: dict) -> tuple[bytes, str] | None:
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            stats["skipped_big"] += 1
            return None
        data = path.read_bytes()
    except OSError:
        stats["skipped_unreadable"] += 1
        return None

    if not data.startswith((b"\xff\xfe", b"\xfe\xff")) and b"\x00" in data[:4096]:
        stats["skipped_binary"] += 1
        return None

    return data, _decode(data)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_scan(root: str, stats: dict | None = None, git_history: bool = False,
             git_depth: int = 0) -> list[dict]:
    if stats is None:
        stats = {}
    stats.setdefault("scanned", 0)
    stats.setdefault("skipped_binary", 0)
    stats.setdefault("skipped_big", 0)
    stats.setdefault("skipped_unreadable", 0)

    if not Path(root).is_dir():
        return [{"error": f"Путь не найден или это не папка: {root}"}]

    findings = []

    for file in walk_files(root):
        content = read_text(file, stats)
        if content is None:
            continue
        data, text = content
        stats["scanned"] += 1

        lines = text.splitlines()
        findings += detect_ssh(file, lines)
        findings += detect_tokens(file, lines)
        findings += detect_passwords(file, lines)
        findings += detect_connections(file, lines)
        findings += run_yara(file, data)
        findings += detect_command_injection(file, lines)
        findings += detect_sql_injection(file, lines)
        findings += detect_weak_session(file, lines)

    # Дедупликация по точному месту и значению
    seen = set()
    unique = []
    for f in findings:
        key = (f.type, f.file, f.line, f.value)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
    stats["yara_failed"] = rules_failed()

    results = []
    for finding in unique:
        entry = finding.to_dict()
        entry["source"] = "fs"
        results.append(entry)

    if git_history:
        from .git_history import DEFAULT_DEPTH, repo_root, scan_git_history

        git_findings = scan_git_history(root, depth=git_depth or DEFAULT_DEPTH, stats=stats)

        # Пути в диффе относительны корня репозитория, а находки файловой
        # системы — абсолютные. Приводим к общему виду, чтобы не дублировать
        # секрет, который до сих пор лежит в файле.
        base = Path(repo_root(root) or root).resolve()

        def relative(path_value: str) -> str:
            try:
                return Path(path_value).resolve().relative_to(base).as_posix()
            except (ValueError, OSError):
                return Path(path_value).as_posix()

        present = {(item["type"], item["value"], relative(item["file"])): item
                   for item in results}
        for git_finding in git_findings:
            key = (git_finding["type"], git_finding["value"], git_finding["file"])
            if key in present:
                present[key].update({
                    "also_in_git": True,
                    "commit": git_finding["commit"],
                    "date": git_finding["date"],
                    "subject": git_finding["subject"],
                    "commits": git_finding["commits"],
                })
            else:
                results.append(git_finding)

    results.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9),
                                   item.get("file") or "", item.get("line") or 0))
    return results
