"""Отчёты по находкам: JSON / текст в консоль и файлы."""

import json
from datetime import datetime
from pathlib import Path


def generate_json_report(findings: list[dict]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)


def generate_text_report(findings: list[dict]) -> str:
    """Группирует находки по критичности и печатает читаемый текст."""
    sections: dict[str, list[dict]] = {"critical": [], "high": [], "medium": [], "other": []}
    for f in findings:
        sev = f.get("severity", "other").lower()
        sections.get(sev, sections["other"]).append(f)

    lines = [f"=== PERIMETER Security Report ({datetime.now().strftime('%Y-%m-%d %H:%M')}) ===\n"]
    for sev in ("critical", "high", "medium", "other"):
        items = sections[sev]
        if not items:
            continue
        lines.append(f"\n[{sev.upper()}] — {len(items)} finding(s)")
        lines.append("-" * 50)
        for f in items:
            lines.append(f"  Type   : {f.get('type') or f.get('vuln_type', '?')}")
            lines.append(f"  File   : {f.get('file', '?')}  (line {f.get('line', '?')})")
            if f.get("title"):
                lines.append(f"  Title  : {f['title']}")
            if f.get("fix"):
                lines.append(f"  Fix    : {f['fix']}")
            lines.append("")

    lines.append(f"Total findings: {len(findings)}")
    return "\n".join(lines)


def save_report(findings: list[dict], reports_dir: str = "reports") -> tuple[str, str]:
    """Пишет JSON и TXT отчёт с меткой времени, возвращает оба пути."""
    Path(reports_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    json_path = Path(reports_dir) / f"scan_{ts}.json"
    txt_path = Path(reports_dir) / f"scan_{ts}.txt"
    json_path.write_text(generate_json_report(findings), encoding="utf-8")
    txt_path.write_text(generate_text_report(findings), encoding="utf-8")
    return str(json_path), str(txt_path)
