import re
from pathlib import Path
from .results import Finding

DOCKERFILE_PATTERNS = [
    (r'^\s*USER\s+root\s*$',            "dockerfile_root",   "high"),
    (r'^\s*ADD\s+',                      "dockerfile_add",    "medium"),
    (r'^\s*ENV\s+\w*PASSWORD\w*\s*=?\s*\S+', "dockerfile_secret", "critical"),
    (r'^\s*ENV\s+\w*SECRET\w*\s*=?\s*\S+',   "dockerfile_secret", "critical"),
    (r'^\s*ENV\s+\w*TOKEN\w*\s*=?\s*\S+',    "dockerfile_secret", "critical"),
]

DOCKERFILE_NAMES = {"Dockerfile", "dockerfile"}

def is_dockerfile(file: Path) -> bool:
    return file.suffix == ".dockerfile" or file.name in DOCKERFILE_NAMES

def detect_dockerfile(file: Path, lines: list[str]) -> list[Finding]:
    if not is_dockerfile(file):
        return []

    findings = []

    for line_number, line in enumerate(lines, start=1):
        # Пропускать комментарии
        if line.strip().startswith("#"):
            continue

        for pattern, finding_type, severity in DOCKERFILE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    type=finding_type,
                    severity=severity,
                    file=str(file),
                    line=line_number,
                    value=line.strip()[:60],
                ))
                break  # не дублировать если строка совпала с несколькими паттернами

    return findings