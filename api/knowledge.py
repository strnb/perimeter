"""База знаний (knowledge_base/vulnerabilities.json) — обогащение находок."""

import json
import logging

from .paths import KB_PATH

logger = logging.getLogger(__name__)

_knowledge_base: list[dict] = []

# type находки DLP -> id записи в базе знаний
TYPE_TO_KB = {
    "ssh_key":           "VULN-039",
    "aws_key":           "VULN-007",
    "aws_secret":        "VULN-007",
    "aws_credentials":   "VULN-007",
    "github":            "VULN-007",
    "gitlab":            "VULN-007",
    "openai":            "VULN-007",
    "stripe":            "VULN-007",
    "slack":             "VULN-007",
    "google":            "VULN-007",
    "sendgrid":          "VULN-007",
    "npm":               "VULN-007",
    "digitalocean":      "VULN-007",
    "telegram":          "VULN-007",
    "jwt":               "VULN-007",
    "generic_api_key":   "VULN-007",
    "password":          "VULN-006",
    "connection_string": "VULN-040",
    "password_hash":     "VULN-041",
    "secret_dump":       "VULN-042",
}


def _load_knowledge_base() -> list[dict]:
    """Читает базу с диска один раз и кеширует в памяти."""
    global _knowledge_base
    if _knowledge_base:
        return _knowledge_base
    if KB_PATH.exists():
        try:
            with open(KB_PATH, encoding="utf-8") as f:
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
