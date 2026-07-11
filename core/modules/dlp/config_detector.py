import re
from pathlib import Path
from .results import Finding

CONFIG_FILENAMES = {"docker-compose.yml", "docker-compose.yaml", ".env.example", "config.py", "settings.py"}
CONFIG_EXTENSIONS = {".cfg", ".ini"}

# Флаг — находимся ли мы внутри блока environment: в docker-compose
_in_environment_block = False

def is_config_file(file: Path) -> bool:
    return file.name in CONFIG_FILENAMES or file.suffix in CONFIG_EXTENSIONS

CONFIG_PATTERNS = [
    # DEBUG=True
    (r'^\s*DEBUG\s*=\s*True\s*$', "debug_enabled", "high"),

    # Пустой пароль: PASSWORD= или PASSWORD=""  или PASSWORD=''
    (r'(?i)PASSWORD\s*=\s*(["\']?\s*["\']?)\s*$', "empty_password", "critical"),

    # localhost как хост БД
    (r'(?i)(DB_HOST|DATABASE_HOST|PGHOST|MYSQL_HOST)\s*=\s*["\']?(localhost|127\.0\.0\.1)["\']?', "localhost_db", "medium"),

    # Секрет в environment: блоке docker-compose — значение не пустое и не переменная окружения
    (r'^\s{4,}-?\s*\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*(?!\$\{)[^\s$][^\s]*', "compose_secret", "critical"),
]

def detect_config(file: Path, lines: list[str]) -> list[Finding]:
    if not is_config_file(file):
        return []

    findings = []
    in_environment = False  # локальный флаг для отслеживания блока environment:

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Пропускать комментарии
        if stripped.startswith("#"):
            continue

        # Отслеживать блок environment: в docker-compose
        if stripped == "environment:":
            in_environment = True
            continue
        # Выход из блока если отступ вернулся на уровень выше
        if in_environment and line and not line[0].isspace():
            in_environment = False

        for pattern, finding_type, severity in CONFIG_PATTERNS:
            # compose_secret искать только внутри блока environment:
            if finding_type == "compose_secret" and not in_environment:
                continue

            if re.search(pattern, line):
                findings.append(Finding(
                    type=finding_type,
                    severity=severity,
                    file=str(file),
                    line=line_number,
                    value=line.strip()[:60],
                ))
                break

    return findings