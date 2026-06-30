import re
from pathlib import Path
from .results import Finding
from .patterns import PASSWORD_PATTERNS, PASSWORD_EXCLUSIONS

PASSWORD_FILE_EXTENSIONS = {".env", ".cfg", ".ini", ".conf"}

def detect_passwords(file: Path, lines: list[str]) -> list[Finding]:
    # Пропустить файл если его расширение не в списке
    if file.suffix not in PASSWORD_FILE_EXTENSIONS:
        return []

    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in PASSWORD_PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue

            value = line.split("=", 1)[1].strip().strip("\"'")

            if value in PASSWORD_EXCLUSIONS:
                continue

            severity = "high" if len(value) < 12 else "medium"

            findings.append(Finding(
                type="password",
                severity=severity,
                file=str(file),
                line=line_number,
                    kb_id="VULN-006",
                    value=value[:40],
                ))

    return findings

"""
python -c "
from pathlib import Path
from core.modules.dlp.password_detector import detect_passwords

file = Path('tests/fixtures/fake_passwords.env')
lines = file.read_text().splitlines()
findings = detect_passwords(file, lines)

print('Найдено:', len(findings))
for f in findings:
    print(f.severity, '—', f.value)
"
"""