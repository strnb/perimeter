from pathlib import Path
from .ssh_detector import detect_ssh
from .token_detector import detect_tokens
from .password_detector import detect_passwords

ALLOWED_EXTENSIONS = {".txt", ".py", ".env", ".json", ".yaml", ".yml", ".cfg", ".ini", ".conf"}

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

    return [f.to_dict() for f in findings]