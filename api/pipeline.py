"""Combined Pipeline — OSINT -> скан портов -> обогащение."""

import logging
from typing import Optional

from .knowledge import enrich_finding

logger = logging.getLogger(__name__)

try:
    from core.modules.scanner.pipeline import osint_and_scan
    _PIPELINE_AVAILABLE = True
except ImportError:
    _PIPELINE_AVAILABLE = False
    logger.warning("Combined Pipeline module not available")


async def run_combined_pipeline(
    domain: str,
    wordlist_path: str = None,
    ports: Optional[list[int]] = None,
    host_concurrency: int = 10,
    enrich: bool = True,
    scan: bool = False,
) -> dict:
    """
    Запускает сквозной сценарий: OSINT -> (по флагу scan) скан портов -> Обогащение.
    """
    if not _PIPELINE_AVAILABLE:
        return {"error": "Combined Pipeline module not available"}
    try:
        result = await osint_and_scan(
            domain=domain,
            wordlist_path=wordlist_path,
            ports=ports,
            host_concurrency=host_concurrency,
            enrich=enrich,
            scan=scan,
        )
        # Если требуется обогащение, прогоняем находки через базу знаний
        if enrich and "findings" in result:
            enriched_findings = []
            for vf in result["findings"]:
                finding_dict = {
                    "host": vf.host,
                    "port": vf.port,
                    "service": vf.service,
                    "banner": vf.banner,
                    "cve": vf.cve,
                    "severity": vf.severity,
                    "title": vf.title,
                    "recommendation": vf.recommendation,
                    "kb_id": vf.kb_id,
                }
                enriched_findings.append(enrich_finding(finding_dict))
            result["findings"] = enriched_findings
        return result
    except Exception as e:
        logger.error(f"run_combined_pipeline error: {e}")
        return {"error": str(e)}
