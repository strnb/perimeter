"""Port Scanner — скан портов + сигнатуры уязвимостей (модуль Демьяна)."""

import logging
from typing import Optional

from .knowledge import enrich_finding

logger = logging.getLogger(__name__)

try:
    from core.modules.scanner.port_scanner import scan_ports, DEFAULT_PORTS
    from core.modules.scanner.vuln_signatures import match_vulnerabilities
    _SCANNER_AVAILABLE = True
except ImportError:
    _SCANNER_AVAILABLE = False
    logger.warning("Scanner module not available")


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
