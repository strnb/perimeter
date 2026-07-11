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



async def run_project_audit(
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

    # result["git"] = scan_git(path)

    #
    # DLP
    #

    result["dlp"] = scan_dlp(path)

    #
    # Network + OSINT pipeline
    #

    result["audit"] = await run_combined_pipeline(
        domain=domain,
        wordlist_path=wordlist_path,
        ports=ports,
        host_concurrency=host_concurrency,
        enrich=enrich,
    )

    return result
# ---------------------------------------------------------------------------
# База знаний (knowledge_base/vulnerabilities.json)
# ---------------------------------------------------------------------------

_KB_PATH = Path("core/vulnerabilities.json")
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
        # SSH и приватные ключи
        "ssh_key":              "VULN-005",

        # Токены и API-ключи
        "aws_key":              "VULN-007",
        "aws_secret":           "VULN-007",
        "github":               "VULN-007",
        "gitlab":               "VULN-007",
        "openai":               "VULN-007",
        "telegram":             "VULN-007",
        "jwt":                  "VULN-007",
        "api_token":            "VULN-007",

        # Пароли и секреты в коде
        "password":             "VULN-006",
        "empty_password":       "VULN-043",
        "dockerfile_secret":    "VULN-041",

        # Небезопасные конфиги
        "debug_enabled":        "VULN-042",
        "localhost_db":         "VULN-044",
        "compose_secret":       "VULN-045",
        "dockerfile_root":      "VULN-039",
        "dockerfile_add":       "VULN-040",
        
        # Инъекции в коде
        "sql_injection":        "VULN-031",
        "command_injection":    "VULN-032",
        "weak_session_id":      "VULN-033",

        # Веб-сканер
        "brute_force":          "VULN-034",
        "csrf":                 "VULN-035",
        "xss":                  "VULN-036",
        "file_upload":          "VULN-037",
        "open_redirect":        "VULN-038",

        # Сетевые сервисы (из network scanner)
        "open_redis":           "VULN-001",
        "open_mongodb":         "VULN-002",
        "open_ftp":             "VULN-003",
        "open_telnet":          "VULN-004",
        "open_mysql":           "VULN-010",
        "open_postgres":        "VULN-011",
        "open_smb":             "VULN-012",
        "open_rdp":             "VULN-013",
        "default_creds":        "VULN-014",
        "outdated_software":    "VULN-015",

        # CVE
        "CVE-2011-2523":        "VULN-016",
        "CVE-2010-4221":        "VULN-017",
        "CVE-2007-2447":        "VULN-019",
        "CVE-2004-2687":        "VULN-020",
        "CVE-2010-2075":        "VULN-021",
        "CVE-2011-3556":        "VULN-028",
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

# api.py

_last_scan_findings: dict[str, list[dict]] = {
    "dlp": [],
    "network": [],
    "web": [],
}


def _all_findings() -> list[dict]:
    """Плоский список всех находок из всех категорий сканирования."""
    return [
        f
        for findings in _last_scan_findings.values()
        for f in findings
    ]


def scan_dlp(path: str) -> list[dict]:
    if not _DLP_AVAILABLE:
        return [{"error": "DLP module not available"}]
    raw = _dlp_run_scan(path)
    enriched = [enrich_finding(f) for f in raw]
    _last_scan_findings["dlp"] = enriched
    logger.info("[Index] scan_dlp: сохранено %d находок", len(enriched))
    return enriched


async def scan_network(target: str, ports: Optional[list[int]] = None) -> list[dict]:
    if not _SCANNER_AVAILABLE:
        return [{"error": "Scanner module not available"}]

    scan_results = await scan_ports(target, ports=ports)
    vuln_findings = match_vulnerabilities(scan_results)

    findings_map: dict[tuple, list] = {}
    for vf in vuln_findings:
        key = (vf.host, vf.port)
        finding_dict = {
            "cve": vf.cve, "severity": vf.severity, "title": vf.title,
            "recommendation": vf.recommendation, "kb_id": vf.kb_id,
        }
        findings_map.setdefault(key, []).append(enrich_finding(finding_dict))

    output = []
    all_network_findings = []
    for r in scan_results:
        if r.status != "open":
            continue
        port_findings = findings_map.get((r.host, r.port), [])
        output.append({
            "host": r.host, "port": r.port, "status": r.status,
            "service": r.service or "unknown", "banner": r.banner or "",
            "findings": port_findings,
        })
        all_network_findings.extend(port_findings)


    _last_scan_findings["network"] = all_network_findings
    logger.info("[Index] scan_network: сохранено %d находок", len(all_network_findings))
    return output


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
        web_result = await run_web_assessment(target_ip, port=port, cookies=cookies)
        raw_findings = web_result.get("findings", [])
        enriched = [enrich_finding(f) for f in raw_findings if f]
        _last_scan_findings["web"] = enriched
        logger.info(
            "[Index] scan_web: сохранено %d находок (severities: %s)",
            len(enriched),
            [f.get("severity") for f in enriched],
        )
        return enriched
    except Exception as e:
        logger.error(f"scan_web error: {e}")
        return [{"error": str(e)}]

def get_security_index() -> int:
    score = 100
    all_f = _all_findings()
    logger.info(
        "[Index] get_security_index: всего находок = %d (dlp=%d, network=%d, web=%d)",
        len(all_f),
        len(_last_scan_findings["dlp"]),
        len(_last_scan_findings["network"]),
        len(_last_scan_findings["web"]),
    )
    for f in all_f:
        sev = f.get("severity", "").lower()
        before = score
        if sev == "critical":
            score -= 10
        elif sev == "high":
            score -= 5
        elif sev == "medium":
            score -= 2
        if score != before:
            logger.info("[Index]   -%d за '%s' (severity=%s) → score=%d",
                        before - score, f.get("title") or f.get("vuln_type"), sev, score)
    final = max(0, score)
    logger.info("[Index] Итоговый security_index = %d", final)
    return final


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
        Scanner (порты + уязвимости)
            ↓
        Web Scanner (заголовки, TLS)
            ↓
        Report

    Если основной pipeline недоступен — собирает результат
    напрямую из доступных модулей (OSINT + Scanner + Web).
    """

    # ── Попытка через полный pipeline ───────────────────────────────────────
    if _PIPELINE_AVAILABLE:
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
                            enrich_finding({
                                "host": finding.host,
                                "port": finding.port,
                                "service": finding.service,
                                "banner": finding.banner,
                                "cve": finding.cve,
                                "severity": finding.severity,
                                "title": finding.title,
                                "recommendation": finding.recommendation,
                                "kb_id": finding.kb_id,
                            })
                        )
                result["findings"] = enriched
                result["recommendations"] = generate_recommendations(result["findings"])

            return result

        except Exception as e:
            logger.warning("run_audit failed (%s), falling back to direct modules", e)

    # ── Fallback: собираем результат из отдельных модулей ───────────────────
    logger.info("run_combined_pipeline: using direct module fallback for %s", domain)

    result: dict = {
        "domain": domain,
        "findings": [],
        "network": [],
        "osint": {},
        "web": [],
    }

    # 1. OSINT — пропускаем для localhost/IP, он там бессмысленен
    is_local = domain.lower() in ("localhost", "127.0.0.1", "::1") or domain.startswith("192.168.") or domain.startswith("10.")
    if _OSINT_AVAILABLE and not is_local:
        try:
            osint = await run_osint(domain, wordlist_path=wordlist_path)
            result["osint"] = osint

            # Субдомены → findings
            for sub in osint.get("subdomains", []):
                result["findings"].append({
                    "type": "osint_subdomain",
                    "title": f"Поддомен: {sub}",
                    "severity": "INFO",
                    "host": sub,
                    "fix": "Убедитесь, что поддомен нужен и не является забытым стендом.",
                })

            # Открытые записи DNS → findings
            for rec in osint.get("dns_records", []):
                if isinstance(rec, dict) and rec.get("type") == "MX":
                    result["findings"].append({
                        "type": "osint_dns",
                        "title": f"MX-запись: {rec.get('value', '')}",
                        "severity": "INFO",
                        "host": domain,
                    })
        except Exception as e:
            logger.error("OSINT fallback error: %s", e)
            result["osint"] = {"error": str(e)}

    # 2. Сканирование портов
    if _SCANNER_AVAILABLE:
        # Для localhost явно используем 127.0.0.1 чтобы избежать проблем с IPv6
        scan_target = "127.0.0.1" if domain.lower() in ("localhost", "::1") else domain
        try:
            scan_results = await scan_ports(scan_target, ports=ports)
            vuln_findings = match_vulnerabilities(scan_results)

            findings_map: dict = {}
            for vf in vuln_findings:
                key = (vf.host, vf.port)
                fd = {
                    "type": "vulnerability",
                    "vuln_type": vf.cve or "unknown",
                    "cve": vf.cve,
                    "severity": vf.severity,
                    "title": vf.title,
                    "recommendation": vf.recommendation,
                    "kb_id": vf.kb_id,
                    "host": vf.host,
                    "port": vf.port,
                }
                enriched_fd = enrich_finding(fd) if enrich else fd
                findings_map.setdefault(key, []).append(enriched_fd)

            for r in scan_results:
                if r.status != "open":
                    continue

                port_vulns = findings_map.get((r.host, r.port), [])
                sev = port_vulns[0]["severity"] if port_vulns else "LOW"

                port_entry = {
                    "host": r.host,
                    "port": r.port,
                    "status": r.status,
                    "service": r.service or "unknown",
                    "banner": r.banner or "",
                    "findings": port_vulns,
                }
                result["network"].append(port_entry)

                # Добавляем открытый порт как finding
                result["findings"].append({
                    "type": "open_port",
                    "title": f"Открытый порт {r.port} ({r.service or 'unknown'})",
                    "severity": sev,
                    "host": r.host,
                    "port": r.port,
                    "banner": r.banner or "",
                    "fix": f"Закройте порт {r.port} если сервис не используется снаружи.",
                })

                # Уязвимости порта тоже в общий список
                for vf in port_vulns:
                    result["findings"].append(vf)

        except Exception as e:
            logger.error("Port scanner fallback error: %s", e)
            result["findings"].append({
                "type": "scanner_error",
                "title": f"Ошибка сканирования портов: {e}",
                "severity": "INFO",
                "host": scan_target,
            })

    # 3. Web Scanner (HTTP-заголовки, TLS) — только для http/https хостов
    if _WEB_SCANNER_AVAILABLE:
        open_web_ports = sorted({
            entry["port"] for entry in result["network"]
            if entry["port"] in (80, 443, 8080, 8443)
        }) or [443 if not is_local else 80]  # fallback если сканер портов не нашёл открытых веб-портов

        for wp in open_web_ports:
            try:
                web_result = await run_web_assessment(domain, port=wp)

                raw_findings = web_result.get("findings", []) if isinstance(web_result, dict) else []
                enriched_web = [enrich_finding(f) for f in raw_findings if f]

                result["web"].extend(enriched_web)
                result["findings"].extend(enriched_web)

            # technologies/headers тоже полезны — можно сложить отдельно
                result.setdefault("web_technologies", {})[wp] = web_result.get("technologies", [])
                result.setdefault("web_headers", {})[wp] = web_result.get("headers", [])

            except Exception as e:
                logger.warning("Web scanner error on port %s: %s", wp, e)
                
				

    if enrich and result["findings"]:
        result["recommendations"] = generate_recommendations(result["findings"])
    else:
        result["recommendations"] = []

    return result
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
