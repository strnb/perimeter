"""
api.py — единая точка входа для UI (Артём).

Модули:
  - DLP (Дамир): scan_dlp, get_security_index
  - Crypto Vault (Дамир): vault_unlock, vault_save, vault_load, vault_list
  - Port Scanner (Демьян): scan_network
  - OSINT (Демьян): run_osint_report
  - Web Scanner (L7): scan_web
  - Combined Pipeline: run_combined_pipeline
  - Knowledge Base (Миша): enrich_finding

Все async-функции нужно вызывать через asyncio.run() или await внутри async-контекста Flet.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Импорты модулей с мягкой деградацией
# ---------------------------------------------------------------------------

from core.modules.git_audit import run_git_audit

try:
    from core.modules.dlp import run_scan as _dlp_run_scan
    _DLP_AVAILABLE = True
except Exception as e:
    _DLP_AVAILABLE = False
    logger.exception("Ошибка импорта DLP: %s", e)

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
except Exception as e:
    _VAULT_AVAILABLE = False
    logger.exception("Ошибка импорта Vault: %s", e)

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

try:
    from core.modules.web_scanner.web_pipeline import run_web_assessment
    _WEB_SCANNER_AVAILABLE = True
except ImportError:
    _WEB_SCANNER_AVAILABLE = False
    logger.warning("Web Scanner module not available")

try:
    from core.modules.audit.pipeline import run_audit
    _PIPELINE_AVAILABLE = True
except ImportError:
    _PIPELINE_AVAILABLE = False
    logger.warning("Audit module not available")



def run_project_audit(
    path: str,
    domain: str,
    wordlist_path: str = "core/subdomains_wordlist.txt",
    ports=None,
    host_concurrency: int = 10,
    enrich: bool = True,
) -> dict:
    """
    Полный аудит проекта.

    Включает:

    - Git Audit
    - DLP
    - Network Audit
    """

    result = {}

    #
    # Git
    #

    result["git"] = scan_git(path)

    #
    # DLP
    #

    result["dlp"] = scan_dlp(path)

    #
    # Network
    #

    result["audit"] = await run_combined_pipeline(
        run_combined_pipeline(
            domain=domain,
            wordlist_path=wordlist_path,
            ports=ports,
            host_concurrency=host_concurrency,
            enrich=enrich,
        )
    )

    return result
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
    Ищет по полю 'type'/'vuln_type' или 'kb_id' совпадение с полем 'id' в базе.
    """
    kb = _load_knowledge_base()
    finding_type = finding.get("type") or finding.get("vuln_type", "")
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

def generate_recommendations(
    findings: list[dict],
) -> list[dict]:
    """
    Генерирует список рекомендаций на основе базы знаний.

    Использует поле 'fix' из vulnerabilities.json.
    """

    recommendations = []
    seen = set()

    for finding in findings:

        enriched = enrich_finding(finding)

        fix = enriched.get("fix")

        if not fix:
            continue

        key = (
            enriched.get("kb_id"),
            fix,
        )

        if key in seen:
            continue

        seen.add(key)

        recommendations.append(
            {
                "id": enriched.get("kb_id"),
                "title": enriched.get("title"),
                "severity": enriched.get("severity"),
                "recommendation": fix,
            }
        )

    return recommendations

# ---------------------------------------------------------------------------
# DLP
# ---------------------------------------------------------------------------

_last_scan_findings: list[dict] = []

def scan_dlp(path: str) -> list[dict]:
    """Запускает DLP-сканирование папки path."""
    if not _DLP_AVAILABLE:
        return [{"error": "DLP module not available"}]

    global _last_scan_findings
    raw = _dlp_run_scan(path)
    enriched = [enrich_finding(f) for f in raw]
    _last_scan_findings = enriched
    return enriched

def scan_git(path: str) -> dict:
    """
    Запускает аудит Git-репозитория.
    Parameters
    ----------
    path : str
        Путь к проекту.
    Returns
    -------
    dict
    """
    from core.modules.git_audit import run_git_audit

    return run_git_audit(path)


def get_security_index() -> int:
    """Индекс безопасности от 0 до 100 на основе последнего DLP-скана."""
    score = 100
    for f in _last_scan_findings:
        sev = f.get("severity", "").lower()
        if sev == "critical":
            score -= 10
        elif sev == "high":
            score -= 5
    return max(0, score)


# ---------------------------------------------------------------------------
# Crypto Vault
# ---------------------------------------------------------------------------

def vault_unlock(password: str) -> bool:
    if not _VAULT_AVAILABLE:
        return False
    try:
        return _vault_unlock(password)
    except Exception as e:
        logger.error(f"vault_unlock error: {e}")
        return False

def vault_lock():
    if _VAULT_AVAILABLE:
        _vault_lock()

def vault_save(name: str, value: str) -> bool:
    if not _VAULT_AVAILABLE:
        return False
    try:
        _vault_save(name, value)
        return True
    except Exception as e:
        logger.error(f"vault_save error: {e}")
        return False

def vault_load(name: str) -> Optional[str]:
    if not _VAULT_AVAILABLE:
        return None
    try:
        return _vault_load(name)
    except Exception as e:
        logger.error(f"vault_load error: {e}")
        return None

def vault_list() -> list[str]:
    if not _VAULT_AVAILABLE:
        return []
    try:
        return _vault_list()
    except Exception as e:
        logger.error(f"vault_list error: {e}")
        return []

def vault_is_initialized() -> bool:
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
    """Асинхронное сканирование портов цели с обогащением из базы знаний."""
    if not _SCANNER_AVAILABLE:
        return [{"error": "Scanner module not available"}]

    scan_results = await scan_ports(target, ports=ports)
    vuln_findings = match_vulnerabilities(scan_results)

    findings_map: dict[tuple, list] = {}
    for vf in vuln_findings:
        key = (vf.host, vf.port)
        finding_dict = {
            "cve": vf.cve,
            "severity": vf.severity,
            "title": vf.title,
            "recommendation": vf.recommendation,
            "kb_id": vf.kb_id,
        }
        # Обогащаем находку из базы знаний
        enriched = enrich_finding(finding_dict)
        findings_map.setdefault(key, []).append(enriched)

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
    if not _OSINT_AVAILABLE:
        return {"error": "OSINT module not available"}
    try:
        return await run_osint(domain, wordlist_path=wordlist_path)
    except Exception as e:
        logger.error(f"run_osint_report error: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Web Scanner (L7)
# ---------------------------------------------------------------------------

async def scan_web(
    target_ip: str,
    port: int,
    cookies: Optional[dict] = None,
) -> list[dict]:
    """
    Асинхронный аудит веб-уязвимостей (L7) с обогащением из базы знаний.
    """
    if not _WEB_SCANNER_AVAILABLE:
        return [{"error": "Web Scanner module not available"}]
    try:
        raw_findings = await run_web_assessment(target_ip, port=port, cookies=cookies)
        return [enrich_finding(f) for f in raw_findings if f]
    except Exception as e:
        logger.error(f"scan_web error: {e}")
        return [{"error": str(e)}]


# ---------------------------------------------------------------------------
# Combined Pipeline (OSINT + Network Scan)
# ---------------------------------------------------------------------------

async def run_combined_pipeline(
    domain: str,
    wordlist_path: str = "core/subdomains_wordlist.txt",
    ports: Optional[list[int]] = None,
    host_concurrency: int = 10,
    enrich: bool = True,
) -> dict:
    """
    Полный аудит инфраструктуры.

    Pipeline:

        OSINT
            ↓
        Scanner
            ↓
        Web Scanner
            ↓
        Report
    """

    if not _PIPELINE_AVAILABLE:
        return {"error": "Audit module not available"}

    try:

        result = await run_audit(
            domain=domain,
            wordlist_path=wordlist_path,
            ports=ports,
            host_concurrency=host_concurrency,
            enrich=enrich,
        )

        if enrich and "findings" in result:

            enriched = []

            for finding in result["findings"]:

                if isinstance(finding, dict):
                    enriched.append(enrich_finding(finding))
                else:
                    enriched.append(
                        enrich_finding(
                            {
                                "host": finding.host,
                                "port": finding.port,
                                "service": finding.service,
                                "banner": finding.banner,
                                "cve": finding.cve,
                                "severity": finding.severity,
                                "title": finding.title,
                                "recommendation": finding.recommendation,
                                "kb_id": finding.kb_id,
                            }
                        )
                    )

            result["findings"] = enriched

            if "findings" in result:
                result["recommendations"] = generate_recommendations(
                    result["findings"]
                )

        return result

    except Exception as e:

        logger.exception("run_combined_pipeline")

        return {
            "error": str(e)
        }
# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def generate_json_report(findings: list[dict]) -> str:
    return json.dumps(findings, ensure_ascii=False, indent=2)


def generate_text_report(findings: list[dict]) -> str:
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
    lines.append(f"Security Index: {get_security_index()}/100")
    return "\n".join(lines)


def save_report(findings: list[dict], reports_dir: str = "reports") -> tuple[str, str]:
    Path(reports_dir).mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    json_path = Path(reports_dir) / f"scan_{ts}.json"
    txt_path = Path(reports_dir) / f"scan_{ts}.txt"
    json_path.write_text(generate_json_report(findings), encoding="utf-8")
    txt_path.write_text(generate_text_report(findings), encoding="utf-8")
    return str(json_path), str(txt_path)
    result["git"] = run_git_audit(project_path)