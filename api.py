"""
api.py — единая точка входа для UI (Артём).

Модули:
  - DLP (Дамир): scan_dlp, get_security_index
  - Crypto Vault (Дамир): vault_unlock, vault_save, vault_load, vault_list
  - Port Scanner (Демьян): scan_network
  - OSINT (Демьян): run_osint_report
  - Knowledge Base (Миша): enrich_finding

Все async-функции (scan_network, run_osint_report) нужно вызывать через asyncio.run()
или await внутри async-контекста Flet.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Импорты модулей с мягкой деградацией: если ветка не смержена — не падаем
# ---------------------------------------------------------------------------

try:
    from core.modules.dlp import run_scan as _dlp_run_scan
    _DLP_AVAILABLE = True
except ImportError:
    _DLP_AVAILABLE = False
    logger.warning("DLP module not available (merge Дамир's branch first)")

try:
    from core.modules.vault import (
        unlock as _vault_unlock,
        lock as _vault_lock,
        save_secret as _vault_save,
        load_secret as _vault_load,
        list_secrets as _vault_list,
        is_vault_initialized as _vault_initialized,
    )
    _VAULT_AVAILABLE = True
except ImportError:
    _VAULT_AVAILABLE = False
    logger.warning("Vault module not available (merge Дамир's branch first)")

try:
    from core.modules.scanner.port_scanner import scan_ports, DEFAULT_PORTS
    from core.modules.scanner.vuln_signatures import match_vulnerabilities
    _SCANNER_AVAILABLE = True
except ImportError:
    _SCANNER_AVAILABLE = False
    logger.warning("Scanner module not available")

try:
    from core.modules.scanner.osint import run_osint
    _OSINT_AVAILABLE = True
except ImportError:
    _OSINT_AVAILABLE = False
    logger.warning("OSINT module not available")

# ---------------------------------------------------------------------------
# База знаний (knowledge_base/vulnerabilities.json)
# ---------------------------------------------------------------------------

_KB_PATH = Path("knowledge_base/vulnerabilities.json")
_knowledge_base: list[dict] = []

def _load_knowledge_base() -> list[dict]:
    global _knowledge_base
    if _knowledge_base:
        return _knowledge_base
    if _KB_PATH.exists():
        try:
            with open(_KB_PATH, encoding="utf-8") as f:
                _knowledge_base = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")
            _knowledge_base = []
    return _knowledge_base


def enrich_finding(finding: dict) -> dict:
    """
    Обогащает finding описанием и рекомендацией из базы знаний.
    Ищет по полю 'type' или 'kb_id' совпадение с полем 'id' в базе.
    Возвращает finding с добавленными полями description и fix.
    """
    kb = _load_knowledge_base()
    finding_type = finding.get("type", "")
    kb_id = finding.get("kb_id", "")

    TYPE_TO_KB = {
        "ssh_key":     "VULN-005",
        "aws_key":     "VULN-007",
        "aws_secret":  "VULN-007",
        "github":      "VULN-007",
        "openai":      "VULN-007",
        "telegram":    "VULN-007",
        "jwt":         "VULN-007",
        "password":    "VULN-006",
    }

    target_id = kb_id or TYPE_TO_KB.get(finding_type, "")
    if not target_id:
        return finding

    for entry in kb:
        if entry.get("id") == target_id:
            enriched = dict(finding)
            enriched["title"] = entry.get("title", finding_type)
            enriched["description"] = entry.get("description", "")
            enriched["fix"] = entry.get("fix", "")
            enriched["risk"] = entry.get("risk", "")
            return enriched

    return finding


# ---------------------------------------------------------------------------
# DLP
# ---------------------------------------------------------------------------

# Последний скан — кешируем для get_security_index()
_last_scan_findings: list[dict] = []


def scan_dlp(path: str) -> list[dict]:
    """
    Запускает DLP-сканирование папки path.
    Возвращает список словарей Finding с полями:
      type, severity, file, line, value, title, description, fix, risk
    """
    if not _DLP_AVAILABLE:
        return [{"error": "DLP module not available. Merge Дамир's branch."}]

    global _last_scan_findings
    raw = _dlp_run_scan(path)
    enriched = [enrich_finding(f) for f in raw]
    _last_scan_findings = enriched
    return enriched


def get_security_index() -> int:
    """
    Индекс безопасности от 0 до 100 на основе последнего DLP-скана.
    Начинается с 100, вычитается:
      -10 за каждый critical finding
      -5  за каждый high finding
    """
    score = 100
    for f in _last_scan_findings:
        sev = f.get("severity", "")
        if sev == "critical":
            score -= 10
        elif sev == "high":
            score -= 5
    return max(0, score)


# ---------------------------------------------------------------------------
# Crypto Vault
# ---------------------------------------------------------------------------

def vault_unlock(password: str) -> bool:
    """
    Разблокирует Vault. При первом запуске — инициализирует мастер-пароль.
    Возвращает True при успехе.
    """
    if not _VAULT_AVAILABLE:
        logger.error("Vault module not available")
        return False
    try:
        return _vault_unlock(password)
    except Exception as e:
        logger.error(f"vault_unlock error: {e}")
        return False


def vault_lock():
    """Блокирует Vault (стирает ключ из памяти)."""
    if _VAULT_AVAILABLE:
        _vault_lock()


def vault_save(name: str, value: str) -> bool:
    """
    Сохраняет секрет в Vault. Vault должен быть разблокирован.
    Возвращает True при успехе.
    """
    if not _VAULT_AVAILABLE:
        logger.error("Vault module not available")
        return False
    try:
        _vault_save(name, value)
        return True
    except RuntimeError as e:
        logger.error(f"vault_save: {e}")
        return False


def vault_load(name: str) -> Optional[str]:
    """
    Загружает секрет из Vault. Vault должен быть разблокирован.
    Возвращает строку или None при ошибке.
    """
    if not _VAULT_AVAILABLE:
        return None
    try:
        return _vault_load(name)
    except Exception as e:
        logger.error(f"vault_load: {e}")
        return None


def vault_list() -> list[str]:
    """Возвращает список имён секретов без расшифровки значений."""
    if not _VAULT_AVAILABLE:
        return []
    try:
        return _vault_list()
    except Exception as e:
        logger.error(f"vault_list: {e}")
        return []


def vault_is_initialized() -> bool:
    """Проверяет, установлен ли мастер-пароль."""
    if not _VAULT_AVAILABLE:
        return False
    return _vault_initialized()


# ---------------------------------------------------------------------------
# Network Scanner
# ---------------------------------------------------------------------------

async def scan_network(
    target: str,
    ports: Optional[list[int]] = None,
) -> list[dict]:
    """
    Асинхронное сканирование портов цели (IP, домен или CIDR).
    Возвращает список словарей:
      {host, port, status, service, banner, findings: [...]}

    findings — уязвимости из vuln_signatures (если _SCANNER_AVAILABLE).

    Пример вызова из UI:
        results = asyncio.run(scan_network("192.168.1.1"))
    """
    if not _SCANNER_AVAILABLE:
        return [{"error": "Scanner module not available"}]

    scan_results = await scan_ports(target, ports=ports)
    vuln_findings = match_vulnerabilities(scan_results)

    # Группируем находки по хосту:порту для удобства UI
    findings_map: dict[tuple, list] = {}
    for vf in vuln_findings:
        key = (vf.host, vf.port)
        findings_map.setdefault(key, []).append({
            "cve": vf.cve,
            "severity": vf.severity,
            "title": vf.title,
            "recommendation": vf.recommendation,
            "kb_id": vf.kb_id,
        })

    output = []
    for r in scan_results:
        if r.status != "open":
            continue
        output.append({
            "host": r.host,
            "port": r.port,
            "status": r.status,
            "service": r.service or "unknown",
            "banner": r.banner or "",
            "findings": findings_map.get((r.host, r.port), []),
        })

    return output


# ---------------------------------------------------------------------------
# OSINT
# ---------------------------------------------------------------------------

async def run_osint_report(
    domain: str,
    wordlist_path: str = "core/subdomains_wordlist.txt",
) -> dict:
    """
    Полный OSINT-анализ домена: WHOIS + DNS + поддомены.
    Возвращает словарь:
      {domain, scan_time, whois: {...}, dns: {...}, subdomains: [...]}

    Пример вызова из UI:
        report = asyncio.run(run_osint_report("example.com"))
    """
    if not _OSINT_AVAILABLE:
        return {"error": "OSINT module not available"}

    try:
        return await run_osint(domain, wordlist_path=wordlist_path)
    except Exception as e:
        logger.error(f"run_osint_report error: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def generate_json_report(findings: list[dict]) -> str:
    """Сериализует результаты DLP-скана в JSON с отступами."""
    return json.dumps(findings, ensure_ascii=False, indent=2)


def generate_text_report(findings: list[dict]) -> str:
    """Читаемый текстовый отчёт с разбивкой по severity."""
    sections: dict[str, list[dict]] = {"critical": [], "high": [], "medium": [], "other": []}
    for f in findings:
        sev = f.get("severity", "other")
        sections.get(sev, sections["other"]).append(f)

    lines = [f"=== PERIMETER Security Report ({datetime.now().strftime('%Y-%m-%d %H:%M')}) ===\n"]
    for sev in ("critical", "high", "medium", "other"):
        items = sections[sev]
        if not items:
            continue
        lines.append(f"\n[{sev.upper()}] — {len(items)} finding(s)")
        lines.append("-" * 50)
        for f in items:
            lines.append(f"  Type   : {f.get('type', '?')}")
            lines.append(f"  File   : {f.get('file', '?')}  (line {f.get('line', '?')})")
            if f.get("title"):
                lines.append(f"  Title  : {f['title']}")
            if f.get("fix"):
                lines.append(f"  Fix    : {f['fix']}")
            lines.append("")

    lines.append(f"Total findings: {len(findings)}")
    lines.append(f"Security Index: {get_security_index()}/100")
    return "\n".join(lines)


def save_report(findings: list[dict], reports_dir: str = "reports") -> tuple[str, str]:
    """
    Сохраняет JSON и текстовый отчёт в папку reports/.
    Возвращает (путь_к_json, путь_к_txt).
    """
    Path(reports_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    json_path = Path(reports_dir) / f"scan_{ts}.json"
    txt_path = Path(reports_dir) / f"scan_{ts}.txt"
    json_path.write_text(generate_json_report(findings), encoding="utf-8")
    txt_path.write_text(generate_text_report(findings), encoding="utf-8")
    return str(json_path), str(txt_path)