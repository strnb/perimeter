"""Проверки конфигурации домена по уже собранным DNS/HTTP-данным.

Здесь нет сети: функции получают записи и возвращают структуры отчёта и
находки. Так их можно проверять офлайн, без DNS и HTTP.
"""

import re

# Провайдеры, у которых занятое имя CNAME можно «перехватить», если оно
# освободилось. Значение — (название, маркеры ответа «здесь ничего нет»).
TAKEOVER_PROVIDERS = {
    "herokuapp.com": ("Heroku", ("no such app", "there is no app configured")),
    "github.io": ("GitHub Pages", ("there isn't a github pages site here",)),
    "s3.amazonaws.com": ("Amazon S3", ("nosuchbucket", "the specified bucket does not exist")),
    "azurewebsites.net": ("Azure", ("error 404 - web app not found",)),
    "cloudfront.net": ("CloudFront", ("the request could not be satisfied",)),
    "netlify.app": ("Netlify", ("not found - request id",)),
    "vercel.app": ("Vercel", ("deployment not found", "not_found")),
    "pages.dev": ("Cloudflare Pages", ("project not found",)),
    "web.app": ("Firebase", ("site not found",)),
    "firebaseapp.com": ("Firebase", ("site not found",)),
    "myshopify.com": ("Shopify", ("sorry, this shop is currently unavailable",)),
    "readthedocs.io": ("Read the Docs", ("project not found",)),
    "surge.sh": ("Surge", ("project not found",)),
    "bitbucket.io": ("Bitbucket", ("repository not found",)),
    "freshdesk.com": ("Freshdesk", ("account not found",)),
    "zendesk.com": ("Zendesk", ("this help center no longer exists",)),
    "ngrok.io": ("ngrok", ("tunnel not found",)),
    "digitaloceanspaces.com": ("DigitalOcean Spaces", ("nosuchbucket",)),
}

# Заголовки страниц, по которым узнаются панели управления
ADMIN_TITLE_MARKERS = (
    "jenkins", "grafana", "phpmyadmin", "gitlab", "kibana", "prometheus",
    "adminer", "jupyter", "sonarqube", "rabbitmq", "portainer", "kibana",
)


def _finding(kb_id, type_, severity, title, detail, fix):
    return {
        "kb_id": kb_id,
        "type": type_,
        "severity": severity,
        "title": title,
        "detail": detail,
        "fix": fix,
    }


# ---------------------------------------------------------------------------
# Почта: SPF / DMARC
# ---------------------------------------------------------------------------

def _spf_tokens(record):
    return record.split()


def analyze_spf(txt_records):
    """Возвращает (сводка, находки) по TXT-записям корня домена."""
    spf = [t for t in txt_records if t.strip().lower().startswith("v=spf1")]
    findings = []

    if not spf:
        findings.append(_finding(
            "VULN-043", "spf_missing", "high",
            "SPF не настроен",
            "В TXT-записях домена нет SPF. Получатели не могут проверить, "
            "какие серверы вправе отправлять письма от вашего имени.",
            "Добавить TXT-запись вида «v=spf1 include:_spf.<провайдер> -all».",
        ))
        return {"record": None, "policy": None, "lookups": 0}, findings

    if len(spf) > 1:
        findings.append(_finding(
            "VULN-043", "spf_multiple", "medium",
            "Несколько SPF-записей",
            f"Найдено {len(spf)} записей v=spf1. По стандарту должна быть одна; "
            "иначе проверка SPF у получателя даёт непредсказуемый результат.",
            "Объединить все механизмы в одну TXT-запись v=spf1.",
        ))

    record = spf[0]
    policy = None
    for token in _spf_tokens(record):
        if token.lstrip("+-~?").lower() == "all":
            policy = token.lower()
            break

    if policy in ("+all", "all"):
        findings.append(_finding(
            "VULN-043", "spf_allow_all", "critical",
            "SPF разрешает отправку писем всем",
            "Запись SPF заканчивается на +all: любой сервер может отправлять "
            "письма от имени домена, защита от подделки отсутствует.",
            "Заменить +all на -all и перечислить только доверенные серверы.",
        ))
    elif policy == "?all":
        findings.append(_finding(
            "VULN-043", "spf_neutral", "medium",
            "SPF в нейтральном режиме (?all)",
            "?all означает «неизвестно»: получатель не отклонит поддельное письмо.",
            "Заменить ?all на -all после проверки легитимных отправителей.",
        ))
    elif policy is None:
        findings.append(_finding(
            "VULN-043", "spf_no_all", "medium",
            "SPF без механизма all",
            "В записи SPF нет завершающего all — поведение зависит от политики получателя.",
            "Добавить -all в конец записи SPF.",
        ))

    lookups = sum(
        1 for token in _spf_tokens(record)
        if any(m in token.lower() for m in ("include:", "a:", "mx:", "ptr:", "exists:", "redirect="))
    )
    if lookups > 10:
        findings.append(_finding(
            "VULN-043", "spf_too_many_lookups", "medium",
            f"SPF требует {lookups} DNS-запросов",
            "Более 10 запросов — превышение лимита RFC 7208; часть получателей "
            "сочтёт SPF ошибочным (permerror).",
            "Сократить число include/redirect, объединить домены у одного провайдера.",
        ))

    return {"record": record, "policy": policy, "lookups": lookups}, findings


def analyze_dmarc(txt_records):
    """DMARC-запись берётся из _dmarc.<domain>, а не из корня."""
    records = [t for t in txt_records if t.strip().lower().startswith("v=dmarc1")]
    findings = []

    if not records:
        findings.append(_finding(
            "VULN-044", "dmarc_missing", "high",
            "DMARC не настроен",
            "Нет записи _dmarc. Получатели не знают, что делать с письмами, "
            "не прошедшими SPF/DKIM, и не присылают отчёты.",
            "Добавить TXT-запись _dmarc с «v=DMARC1; p=quarantine; rua=mailto:...».",
        ))
        return {"record": None, "policy": None}, findings

    record = records[0]
    match = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", record, re.I)
    policy = match.group(1).lower() if match else None

    if policy is None:
        findings.append(_finding(
            "VULN-044", "dmarc_no_policy", "medium",
            "DMARC без политики p=",
            "В записи DMARC не указана политика — она не защищает домен.",
            "Добавить p=quarantine (затем p=reject) в запись DMARC.",
        ))
    elif policy == "none":
        findings.append(_finding(
            "VULN-044", "dmarc_none", "medium",
            "DMARC в режиме мониторинга (p=none)",
            "p=none только собирает отчёты: поддельные письма всё равно доставляются.",
            "После сбора статистики перейти на p=quarantine, затем p=reject.",
        ))

    return {"record": record, "policy": policy}, findings


# ---------------------------------------------------------------------------
# DNSSEC / CAA / зона
# ---------------------------------------------------------------------------

def analyze_security(ds_records, caa_records, zone_transfer="not_checked"):
    findings = []

    if not ds_records:
        findings.append(_finding(
            "VULN-045", "dnssec_disabled", "medium",
            "DNSSEC не включён",
            "Нет DS-записи: ответы DNS можно подменить, и клиент этого не заметит.",
            "Включить DNSSEC у регистратора и подписать зону у DNS-провайдера.",
        ))

    if not caa_records:
        findings.append(_finding(
            "VULN-046", "caa_missing", "low",
            "CAA не настроен",
            "Любой удостоверяющий центр может выпустить сертификат на домен.",
            "Добавить CAA-запись, разрешающую выпуск только вашему CA.",
        ))

    if zone_transfer.startswith("VULNERABLE"):
        ns = zone_transfer.split(":", 1)[-1].strip()
        findings.append(_finding(
            "VULN-047", "dns_zone_transfer", "critical",
            "DNS-зона отдаётся по AXFR",
            f"Сервер {ns} передаёт всю зону целиком: видны все внутренние имена.",
            "Запретить AXFR на авторитативных серверах, разрешить только доверенным secondary.",
        ))

    return {
        "dnssec": bool(ds_records),
        "caa": bool(caa_records),
        "zone_transfer": zone_transfer,
    }, findings


# ---------------------------------------------------------------------------
# HTTP-инвентаризация и subdomain takeover
# ---------------------------------------------------------------------------

def takeover_provider(cname):
    """Провайдер, на который указывает CNAME, или None."""
    if not cname:
        return None
    name = cname.lower().rstrip(".")
    for suffix, (provider, _markers) in TAKEOVER_PROVIDERS.items():
        if name == suffix or name.endswith("." + suffix):
            return provider
    return None


def is_takeover_candidate(cname, status, body):
    """CNAME на известный сервис + ответ «такого приложения нет»."""
    if not cname:
        return False
    name = cname.lower().rstrip(".")
    for suffix, (_provider, markers) in TAKEOVER_PROVIDERS.items():
        if name == suffix or name.endswith("." + suffix):
            text = (body or "").lower()
            return any(marker in text for marker in markers)
    return False


def analyze_http(subdomains):
    """Находки по результатам HTTP-проб: панели и TLS."""
    findings = []

    for sub in subdomains:
        info = sub.get("http") or {}
        title = (info.get("title") or "").lower()
        if any(marker in title for marker in ADMIN_TITLE_MARKERS):
            findings.append(_finding(
                "VULN-050", "admin_panel_exposed", "medium",
                "Доступна панель управления",
                f"{sub['subdomain']} отдаёт страницу «{info.get('title')}». "
                "Панели управления не должны быть видны из интернета.",
                "Ограничить доступ по IP/VPN или закрыть панель авторизацией и MFA.",
            ))

        days = info.get("tls_days_left")
        if isinstance(days, int) and days < 14:
            findings.append(_finding(
                "VULN-049", "tls_expiring", "medium",
                "Сертификат TLS скоро истекает",
                f"{sub['subdomain']}: сертификат истекает через {days} дн.",
                "Настроить автопродление сертификата и проверить цепочку.",
            ))

        if sub.get("takeover"):
            provider = takeover_provider(sub.get("cname"))
            findings.append(_finding(
                "VULN-048", "subdomain_takeover", "high",
                "Кандидат на захват поддомена",
                f"{sub['subdomain']} — CNAME на {sub.get('cname')}"
                + (f" ({provider})" if provider else "")
                + ", но сервис отвечает, что приложения не существует. Имя можно занять.",
                "Удалить висячий CNAME или заново зарегистрировать имя у провайдера.",
            ))

    return findings
