from pathlib import Path
from .ssh_detector import detect_ssh
from .token_detector import detect_tokens
from .password_detector import detect_passwords
from .yara_scanner import run_yara
from .command_injection_detector import detect_command_injection
from .sql_injection_detector import detect_sql_injection
from .weak_session_detector import detect_weak_session

ALLOWED_EXTENSIONS = {".txt", ".py", ".env", ".json", ".yaml", ".yml", ".cfg", ".ini", ".conf", ".php"}

EXCLUDED_DIRS = {"venv", ".venv", ".git", "node_modules", "__pycache__", ".idea"}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 МБ в байтах

def walk_files(root: str) -> list[Path]:
    result = []

    for path in Path(root).rglob("*"):
        # Пропустить если это папка, а не файл
        if not path.is_file():
            continue

        # Пропустить если файл лежит внутри запрещённой папки
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        # Пропустить если расширение не в списке разрешённых
        if path.suffix not in ALLOWED_EXTENSIONS:
            continue

        # Пропустить если файл больше 1 МБ
        if path.stat().st_size > MAX_FILE_SIZE:
            continue

        result.append(path)

    return result

def run_scan(root: str) -> list[dict]:
    findings = []

    for file in walk_files(root):
        try:
            lines = file.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        findings += detect_ssh(file, lines)
        findings += detect_tokens(file, lines)
        findings += detect_passwords(file, lines)
        findings += run_yara(file)
        findings += detect_command_injection(file, lines)
        findings += detect_sql_injection(file, lines)
        findings += detect_weak_session(file, lines)

    # Дедупликация — убрать записи с одинаковым типом и файлом
    seen = set()
    unique = []
    for f in findings:
        key = (f.type, f.file)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return [f.to_dict() for f in unique]