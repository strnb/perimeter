from pathlib import Path
from .ssh_detector import detect_ssh
from .token_detector import detect_tokens
from .password_detector import detect_passwords
from .yara_scanner import run_yara
from .command_injection_detector import detect_command_injection
from .sql_injection_detector import detect_sql_injection
from .weak_session_detector import detect_weak_session
from .dockerfile_detector import DOCKERFILE_NAMES, detect_dockerfile
from .config_detector import CONFIG_FILENAMES, detect_config

# ---------------------------------------------------------------------------
# Расширения файлов которые читаем и сканируем содержимое
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS = {
    # Языки программирования
    ".py", ".rb", ".php", ".js", ".mjs", ".ts", ".jsx", ".tsx",
    ".java", ".kt", ".scala", ".groovy",        # JVM
    ".cs", ".vb",                               # .NET
    ".go", ".rs",                               # системные
    ".cpp", ".c", ".h", ".hpp", ".cc",          # C/C++
    ".swift", ".m",                             # Apple
    ".pl", ".pm",                               # Perl
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".psm1", ".bat", ".cmd",  # shell

    # Конфиги и данные
    ".env", ".json", ".yaml", ".yml", ".toml", ".xml",
    ".cfg", ".ini", ".conf", ".config", ".properties",
    ".settings", ".plist", ".htaccess",

    # Инфраструктура как код
    ".dockerfile",
    ".tf", ".tfvars",                           # Terraform
    ".hcl",                                     # HashiCorp (Vault, Consul)
    ".nomad",                                   # Nomad
    ".gradle", ".pom",                          # Java build

    # CI/CD
    ".travis.yml",                              # ловится через .yml, но явно для ясности

    # Ключи и сертификаты
    ".pem", ".key", ".ppk", ".crt", ".cer", ".p12", ".pfx", ".jks",

    # Текст и документация
    ".txt", ".md", ".rst", ".log", ".csv",

    # Веб
    ".html", ".htm", ".vue", ".svelte", ".ejs", ".jinja", ".j2",

    # SQL
    ".sql",
}

# ---------------------------------------------------------------------------
# Файлы детектируемые по имени — включаем вне зависимости от расширения
# Содержимое всё равно читается и сканируется
# ---------------------------------------------------------------------------
KEY_FILENAMES = {
    # SSH ключи (обычно без расширения)
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",

    # Известные конфиги без расширения
    "Makefile", "Procfile",
    ".env", ".htpasswd", ".netrc",
    "config", "secrets", "credentials",
}

# ---------------------------------------------------------------------------
# Директории которые полностью пропускаем
# ---------------------------------------------------------------------------
EXCLUDED_DIRS = {
    "venv", ".venv", "env",
    ".git",
    "node_modules",
    "__pycache__",
    ".idea", ".vscode",
    "dist", "build", "target",          # артефакты сборки
    ".terraform",                        # Terraform state (бинарный)
    "coverage", ".pytest_cache",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 МБ — бинарники и дампы пропускаем


def walk_files(root: str) -> list[Path]:
    result = []

    for path in Path(root).rglob("*"):
        if not path.is_file():
            continue

        # Пропустить если внутри запрещённой директории
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue

        # Пропустить файлы больше 1 МБ
        if path.stat().st_size > MAX_FILE_SIZE:
            continue

        # Файлы с известными опасными именами — включать по имени
        if path.name in KEY_FILENAMES \
                or path.name in DOCKERFILE_NAMES \
                or path.name in CONFIG_FILENAMES:
            result.append(path)
            continue

        # Все остальные — только если расширение в списке разрешённых
        if path.suffix in ALLOWED_EXTENSIONS:
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
        findings += detect_dockerfile(file, lines)
        findings += detect_config(file, lines)

    # Дедупликация по типу + файл + строка
    seen = set()
    unique = []
    for f in findings:
        key = (f.type, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return [f.to_dict() for f in unique]