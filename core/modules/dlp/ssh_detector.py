from pathlib import Path
from .results import Finding
from .patterns import SSH_PATTERNS

def detect_ssh(file: Path, lines: list[str]) -> list[Finding]:
    findings = []

    # Если само имя файла — известный ключ (id_rsa без расширения)
    if file.name in {"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"}:
        findings.append(Finding(
            type="ssh_key",
            severity="critical",
            file=str(file),
            line=0,
            value=f"Приватный ключ: {file.name}",
        ))
        return findings  # дальше не читаем — уже нашли

    for line_number, line in enumerate(lines, start=1):
        for pattern in SSH_PATTERNS:
            if pattern in line:
                findings.append(Finding(
                    type="ssh_key",
                    severity="critical",
                    file=str(file),
                    line=line_number,
                    value=line.strip()[:40],
                ))

    return findings