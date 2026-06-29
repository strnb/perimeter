"""
vuln_signatures.py
Локальная offline-база сигнатур известных уязвимостей.
Не требует интернета/API — чистый regex и сверка по номеру порта
поверх того, что уже собрал port_scanner.py + banner.py.

Заточено под Metasploitable 2, но сигнатуры по версиям сервисов
сработают на любом реальном таргете с такими же версиями ПО.
"""
import re
from dataclasses import dataclass


@dataclass
class VulnFinding:
    host: str
    port: int
    service: str
    banner: str
    cve: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    recommendation: str
    kb_id: str = None  # связь с knowledge_base/vulnerabilities.json (VULN-XXX), если применимо


# --- Сигнатуры по содержимому баннера (regex применяется к "service banner") ---
BANNER_SIGNATURES = [
    (re.compile(r"vsftpd\s*2\.3\.4", re.I), "CRITICAL", "CVE-2011-2523",
     "vsFTPd 2.3.4 Backdoor",
     "Немедленно обновить vsftpd или удалить сервис. Бэкдор открывает root-шелл на порту 6200 "
     "при логине с именем, заканчивающимся на смайлик."),

    (re.compile(r"proftpd", re.I), "HIGH", "CVE-2010-4221",
     "ProFTPD — известные RCE/backdoor-уязвимости в ряде версий",
     "Проверить точную версию ProFTPD, обновить до актуальной, ограничить доступ файрволом."),

    (re.compile(r"openssh[_\s]4\.7", re.I), "MEDIUM", "Устаревшая версия",
     "OpenSSH 4.7 — устаревшая версия с известными слабостями",
     "Обновить OpenSSH до актуальной версии."),

    (re.compile(r"samba.*3\.0", re.I), "CRITICAL", "CVE-2007-2447",
     "Samba 3.0.x usermap_script — Remote Code Execution",
     "Обновить Samba, отключить опцию usermap_script в smb.conf."),

    (re.compile(r"distcc", re.I), "CRITICAL", "CVE-2004-2687",
     "distccd — Remote Code Execution",
     "Отключить distccd снаружи, никогда не выставлять порт 3632 в публичную сеть."),

    (re.compile(r"unreal", re.I), "CRITICAL", "CVE-2010-2075",
     "UnrealIRCd — Backdoor Command Execution",
     "Переустановить с чистого источника, обновить UnrealIRCd, заблокировать порт 6667/6697."),

    (re.compile(r"tomcat|coyote", re.I), "HIGH", "Default Credentials",
     "Apache Tomcat Manager — типичные дефолтные креды (tomcat:tomcat)",
     "Сменить дефолтные учетные данные Manager-приложения, ограничить доступ к /manager."),

    (re.compile(r"postgresql", re.I), "MEDIUM", "Weak/Default Credentials",
     "PostgreSQL — потенциально слабые учетные данные (postgres:postgres)",
     "Сменить пароль postgres, ограничить доступ по IP/файрволу."),

    (re.compile(r"vnc", re.I), "MEDIUM", "Exposed VNC Service",
     "VNC-сервис доступен по сети",
     "Ограничить доступ по IP/VPN и использовать сложный пароль."),
]

# --- Сигнатуры по номеру порта — для протоколов, которые не шлют банер сами ---
# (rlogin/rsh/ingreslock/X11/drb не присылают читаемый баннер на простой connect,
#  но сам факт открытого порта на Metasploitable УЖЕ является находкой)
PORT_SIGNATURES = {
    111: ("MEDIUM", "Exposed RPCBind", "rpcbind/portmapper доступен извне",
          "Ограничить доступ к rpcbind по IP/файрволу; он раскрывает RPC/NFS-сервисы и помогает дальнейшей атаке."),
    2049: ("HIGH", "Exposed NFS", "NFS доступен извне",
           "Ограничить NFS по IP, проверить /etc/exports, включить root_squash и запретить публичные экспорты."),
    1524: ("CRITICAL", "Known Backdoor", "Ingreslock — готовый root bind shell",
           "Закрыть порт немедленно: подключение netcat'ом сразу даёт root-шелл."),
    6200: ("CRITICAL", "CVE-2011-2523", "vsFTPd 2.3.4 — backdoor bind shell",
           "Немедленно закрыть порт 6200, остановить/обновить vsftpd 2.3.4 и проверить систему на компрометацию."),
    512: ("CRITICAL", "Trust-based Auth Bypass", "'rexec' — доступ часто без пароля через .rhosts",
          "Отключить r-сервисы, использовать SSH."),
    513: ("CRITICAL", "Trust-based Auth Bypass", "'rlogin' — доступ часто без пароля через .rhosts",
          "Отключить r-сервисы, использовать SSH."),
    514: ("CRITICAL", "Trust-based Auth Bypass", "'rsh' — доступ часто без пароля через .rhosts",
          "Отключить r-сервисы, использовать SSH."),
    6000: ("MEDIUM", "Open X11 Display", "Открытый X11-сервер",
           "Закрыть порт снаружи, включить X11-аутентификацию (xauth)."),
    8787: ("HIGH", "Insecure RMI Exposure", "Ruby DRb (drb) — удалённое выполнение кода через незащищённый RMI",
           "Закрыть порт снаружи, обновить/отключить сервис."),
    1099: ("HIGH", "CVE-2011-3556", "Java RMI Registry — RCE через десериализацию",
           "Закрыть порт 1099 снаружи, обновить JRE/RMI registry."),
    6667: ("MEDIUM", "Possible UnrealIRCd Backdoor", "Обнаружен IRC-сервис",
           "На Metasploitable 2 это исторически UnrealIRCd 3.2.8.1 с бэкдором (CVE-2010-2075). "
           "Баннер не всегда виден до NICK/USER — проверить версию вручную."),
    6697: ("MEDIUM", "Possible UnrealIRCd Backdoor", "Обнаружен IRC-сервис (SSL)",
           "См. порт 6667 — тот же сервис, проверить версию вручную."),
    139: ("HIGH", "Possible CVE-2007-2447", "Обнаружен SMB/NetBIOS (Samba)",
          "SMB не присылает версию на пассивный коннект — нужен активный Negotiate Protocol запрос. "
          "На Metasploitable 2 это исторически Samba 3.0.20 с usermap_script RCE. Проверить вручную: "
          "smbclient -L //<host>/ или enum4linux."),
    445: ("HIGH", "Possible CVE-2007-2447", "Обнаружен SMB/NetBIOS (Samba)",
          "См. порт 139 — тот же сервис."),
}

# --- Generic-правила 1:1 с контрактом knowledge_base/vulnerabilities.json (Миша) ---
# Фиксируем строго по тем же id/severity, что в VULN-001..VULN-005, чтобы при
# подключении enrich_finding() по kb_id не было рассинхрона с базой знаний.
KB_GENERIC_PORT_RULES = {
    21: ("VULN-003", "high", "FTP — передача данных и кредов в открытом виде",
         "Отключить FTP, заменить на SFTP/FTPS, запретить анонимный доступ."),
    23: ("VULN-004", "critical", "Telnet — все данные, включая пароли, в открытом виде",
         "Немедленно отключить Telnet, использовать SSH (apt remove telnetd)."),
    22: ("VULN-005", "medium", "SSH доступен без ограничений — риск brute-force",
         "Отключить вход по паролю, использовать ключи, поставить fail2ban."),
}

# Redis/Mongo по контракту Миши специфично "без аутентификации" —
# фиксируем находку только если check_redis/check_mongo подтвердили отсутствие пароля
# (узнаём по тексту banner, который уже формирует port_scanner.py)
KB_AUTH_GATED_RULES = {
    6379: ("VULN-001", "Redis без аутентификации — полный доступ к данным"),
    27017: ("VULN-002", "MongoDB без аутентификации — полный доступ к данным"),
}


def match_vulnerabilities(scan_results: list) -> list[VulnFinding]:
    """
    Принимает список объектов с атрибутами host/port/service/banner
    (то, что возвращает scan_ports()), сверяет с локальной базой сигнатур
    и возвращает найденные уязвимости с CVE/severity/рекомендацией.
    """
    findings = []
    seen = set()

    def add_finding(finding: VulnFinding) -> None:
        key = (finding.host, finding.port, finding.kb_id, finding.cve, finding.title)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for r in scan_results:
        text = f"{r.service or ''} {r.banner or ''}"

        for pattern, severity, cve, title, rec in BANNER_SIGNATURES:
            if pattern.search(text):
                add_finding(VulnFinding(
                    host=r.host, port=r.port, service=r.service,
                    banner=r.banner or "", cve=cve, severity=severity,
                    title=title, recommendation=rec,
                ))

        if r.port in PORT_SIGNATURES:
            severity, cve, title, rec = PORT_SIGNATURES[r.port]
            add_finding(VulnFinding(
                host=r.host, port=r.port, service=r.service,
                banner=r.banner or "", cve=cve, severity=severity,
                title=title, recommendation=rec,
            ))

        # Generic-правила, привязанные к VULN-003/004/005 (FTP/Telnet/SSH)
        if r.port in KB_GENERIC_PORT_RULES:
            kb_id, severity, title, rec = KB_GENERIC_PORT_RULES[r.port]
            add_finding(VulnFinding(
                host=r.host, port=r.port, service=r.service,
                banner=r.banner or "", cve="", severity=severity,
                title=title, recommendation=rec, kb_id=kb_id,
            ))

        # Redis/Mongo — только если реально подтверждено отсутствие авторизации
        if r.port in KB_AUTH_GATED_RULES and "VULNERABLE" in (r.banner or ""):
            kb_id, title = KB_AUTH_GATED_RULES[r.port]
            add_finding(VulnFinding(
                host=r.host, port=r.port, service=r.service,
                banner=r.banner or "", cve="", severity="critical",
                title=title, recommendation="См. fix в knowledge_base/vulnerabilities.json",
                kb_id=kb_id,
            ))

    return findings
