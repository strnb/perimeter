"""Отчёты по находкам: JSON / текст в консоль и файлы.

Находки приходят из разных модулей (DLP: type/file/line, сеть: host/port,
веб: url/vuln_type), поэтому текстовый отчёт берёт то поле, которое есть.
"""

import json
from datetime import datetime
from pathlib import Path


def generate_json_report(findings: list[dict]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2, default=str)


def generate_text_report(findings: list[dict]) -> str:
    """Группирует находки по критичности и печатает читаемый текст."""
    sections: dict[str, list[dict]] = {
        "critical": [], "high": [], "medium": [], "low": [], "other": [],
    }
    for f in findings:
        sev = str(f.get("severity") or "other").lower()
        sections.get(sev, sections["other"]).append(f)

    lines = [f"=== PERIMETER Security Report ({datetime.now().strftime('%Y-%m-%d %H:%M')}) ===\n"]
    for sev in ("critical", "high", "medium", "low", "other"):
        items = sections[sev]
        if not items:
            continue
        lines.append(f"\n[{sev.upper()}] — {len(items)} finding(s)")
        lines.append("-" * 50)
        for f in items:
            lines.append(f"  Type   : {f.get('type') or f.get('vuln_type') or '?'}")
            where = f.get("file") or f.get("url") or f.get("host") or "-"
            if f.get("line"):
                where = f"{where}:{f['line']}"
            elif f.get("port"):
                where = f"{where}:{f['port']}"
            lines.append(f"  Where  : {where}")
            if f.get("commit"):
                origin = "still in file, also in history" if f.get("also_in_git") else "removed from code"
                lines.append(f"  Commit : {f['commit']} {f.get('date', '')} {f.get('subject', '')}".rstrip())
                lines.append(f"  History: {origin}; commits with this secret: {f.get('commits', 1)}")
            if f.get("title"):
                lines.append(f"  Title  : {f['title']}")
            if f.get("detail"):
                lines.append(f"  Detail : {f['detail']}")
            if f.get("fix"):
                lines.append(f"  Fix    : {f['fix']}")
            lines.append("")

    lines.append(f"Total findings: {len(findings)}")
    return "\n".join(lines)


def save_report(findings: list[dict], reports_dir: str = "reports") -> tuple[str, str]:
    """Пишет JSON и TXT отчёт с меткой времени, возвращает оба пути."""
    Path(reports_dir).mkdir(exist_ok=True)
    # микросекунды: два отчёта в одну секунду не должны затирать друг друга
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    json_path = Path(reports_dir) / f"scan_{ts}.json"
    txt_path = Path(reports_dir) / f"scan_{ts}.txt"
    json_path.write_text(generate_json_report(findings), encoding="utf-8")
    txt_path.write_text(generate_text_report(findings), encoding="utf-8")
    return str(json_path), str(txt_path)


def save_osint_report(result: dict, reports_dir: str = "reports") -> str:
    """Полный OSINT-отчёт одним JSON — можно отдать в другой инструмент."""
    Path(reports_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    domain = str(result.get("domain") or "domain").replace("/", "_")
    path = Path(reports_dir) / f"osint_{domain}_{ts}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8")
    return str(path)
