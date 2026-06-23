import re
from pathlib import Path
from .results import Finding
from .patterns import PASSWORD_PATTERNS, PASSWORD_EXCLUSIONS

def detect_passwords(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    for line_number, line in enumerate(lines, start=1):
        for pattern in PASSWORD_PATTERNS:
            match = re.search(pattern, line)
            if not match:
                continue

            # Вытащить только само значение после знака =
            value = line.split("=", 1)[1].strip().strip("\"'")

            # Пропустить если значение в списке исключений
            if value in PASSWORD_EXCLUSIONS:
                continue

            severity = "high" if len(value) < 12 else "medium"

            findings.append(Finding(
                type="password",
                severity=severity,
                file=str(file),
                line=line_number,
                value=value[:40],
            ))

    return findings

# python -c "
# from pathlib import Path
# from core.modules.dlp.password_detector import detect_passwords

# file = Path('tests/fixtures/fake_passwords.py')
# lines = file.read_text().splitlines()
# findings = detect_passwords(file, lines)

# print('Найдено:', len(findings))
# for f in findings:
#     print(f.severity, '—', f.value)
# "