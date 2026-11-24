import re
from pathlib import Path
from .results import Finding
from .patterns import SQL_INJECTION_PATTERNS

TARGET_EXTENSIONS = {".php", ".py"}
SAFE_KEYWORDS = ["prepare", "bind"]

def detect_sql_injection(file: Path, lines: list[str]) -> list[Finding]:
    if file.suffix not in TARGET_EXTENSIONS:
        return []

    findings = []

    for line_number, line in enumerate(lines, start=1):
        # Пропустить строку если в ней есть признаки подготовленного выражения
        if any(keyword in line.lower() for keyword in SAFE_KEYWORDS):
            continue

        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    type="sql_injection",
                    severity="critical",
                    file=str(file),
                    line=line_number,
                    kb_id="VULN-031",
                    value=line.strip()[:60],
                ))
                break  # не дублировать находку если совпали несколько паттернов на одной строке

    return findings