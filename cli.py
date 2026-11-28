"""
perimeter — терминальный комплекс аудита безопасности.
"""
import argparse
import asyncio
import dataclasses
import difflib
import getpass
import json
import os
import json
import sqlite3
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

import api
import database

BANNER = r"""
██████╗ ███████╗██████╗ ██╗███╗   ███╗███████╗████████╗███████╗██████╗
██╔══██╗██╔════╝██╔══██╗██║████╗ ████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ██████╔╝██║██╔████╔██║█████╗     ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══╝  ██╔══██╗██║██║╚██╔╝██║██╔══╝     ██║   ██╔══╝  ██╔══██╗
██║     ███████╗██║  ██║██║██║ ╚═╝ ██║███████╗   ██║   ███████╗██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
              Комплекс аудита безопасности · CLI
"""

DISCLAIMER = (
    "ВНИМАНИЕ: исключительно для легального аудита. Сканирование сторонних "
    "ресурсов без согласия владельцев незаконно (ст. 272-274 УК РФ). "
    "Вы используете инструмент на свой страх и риск."
)


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ports_arg(value):
    """Парсит '22,80,8000-8100' в список портов."""
    ports = []
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    if not ports or any(not 1 <= p <= 65535 for p in ports):
        raise argparse.ArgumentTypeError("порты должны быть в диапазоне 1-65535")
    return ports


def _jsonable(obj):
    # датаклассы (ScanResult и т.п.) -> dict, остальное -> str
    return dataclasses.asdict(obj) if dataclasses.is_dataclass(obj) else str(obj)


def _dump(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=_jsonable))


def _save_report_flag(args, findings):
    if getattr(args, "report", False):
        json_path, txt_path = api.save_report(findings)
        print(f"[+] Отчёты сохранены: {json_path}, {txt_path}")


# ---------------------------------------------------------------------------
# Команды
# ---------------------------------------------------------------------------

def cmd_dlp(args):
    stats = {}
    findings = api.scan_dlp(
        args.path,
        show_secrets=getattr(args, "show_secrets", False),
        stats=stats,
        git=getattr(args, "git", False),
        git_depth=getattr(args, "git_depth", 0),
    )
    if findings and "error" in findings[0]:
        print(f"[-] {findings[0]['error']}")
        return 1

    critical = high = medium = low = 0
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev == "CRITICAL":
            critical += 1
        elif sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        else:
            low += 1
        kind = f.get("type") or f.get("vuln_type", "?")
        loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
        match = f.get("raw_line") or f.get("match") or f.get("value") or ""
        if f.get("commit"):
            print(f"[{sev:8}] {kind:20} {loc}")
            origin = "сейчас в файле, но есть и в истории" if f.get("also_in_git") else "удалён из кода"
            print(f"           git {f['commit']} {f.get('date', '')} {f.get('subject', '')}")
            print(f"           {origin}; коммитов с этим секретом: {f.get('commits', 1)}")
        else:
            print(f"[{sev:8}] {kind:20} {loc}")
        if match:
            print(f"           {str(match).strip()[:120]}")
        if f.get("fix"):
            print(f"           fix: {f['fix']}")

    if not findings:
        print("[+] Угроз не обнаружено")
    database.save_dlp_result(_now(), args.path, critical, medium, low, high_count=high)
    print(f"\nИтого: критических {critical}, высоких {high}, средних {medium}, низких {low}")
    if stats:
        skipped = [
            f"{label} {stats[key]}"
            for key, label in (("skipped_binary", "бинарных"), ("skipped_big", "больших"),
                               ("skipped_unreadable", "нечитаемых"))
            if stats.get(key)
        ]
        note = f" (пропущено: {', '.join(skipped)})" if skipped else ""
        print(f"Проверено файлов: {stats.get('scanned', 0)}{note}")
        if stats.get("yara_failed"):
            print("[!] YARA-правила недоступны — работают только regex-детекторы.")
        if stats.get("git_commits") is not None and getattr(args, "git", False):
            print(f"История git: коммитов {stats.get('git_commits', 0)}, "
                  f"проверено добавленных строк {stats.get('git_lines', 0)}")
        if stats.get("git_error"):
            print(f"[!] История git не проверена: {stats['git_error']}")
    _save_report_flag(args, findings)
    return 0


def cmd_scan(args):
    findings = asyncio.run(api.scan_network(args.target, ports=args.ports))
    if findings and "error" in findings[0]:
        print(f"[-] {findings[0]['error']}")
        return 1
    if not findings:
        print("[-] Открытых портов не найдено")

    vuln_count = 0
    details = []
    report_findings = []  # плоский список для отчёта: host/port + сама уязвимость
    for f in findings:
        print(f"[+] {f['host']}:{f['port']}  {f['service']}  {f['banner']}")
        port_vulns = f.get("findings", [])
        vuln_count += len(port_vulns)
        for vuln in port_vulns:
            print(f"    ↳ [!] {vuln.get('title', 'Уязвимость')} — {vuln.get('severity', '?')}")
            report_findings.append({"host": f["host"], "port": f["port"],
                                    "service": f["service"], **vuln})
        rows = port_vulns or [{}]
        for vuln in rows:
            details.append({
                "host": f["host"],
                "port": f["port"], "service": f["service"], "banner": f["banner"],
                "vulnerability_title": vuln.get("title"), "severity": vuln.get("severity"),
            })

    database.save_network_result(_now(), args.target, len(findings), vuln_count, details)
    print(f"\nОткрытых портов: {len(findings)}, уязвимостей: {vuln_count}")
    _save_report_flag(args, report_findings)
    return 0


def _osint_value(value):
    if value in (None, "", [], {}):
        return "—"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "—"
    return str(value)


def _print_osint(result, previous_names):
    domain = result.get("domain", "?")
    cached = result.get("cached")
    duration = result.get("duration_sec")
    header = f"\nДомен: {domain}"
    if cached:
        header += f"  [из кэша, {result.get('cache_age_hours', '?')} ч назад]"
    elif duration is not None:
        header += f"  ({duration} с)"
    print(header)

    sources = result.get("sources") or {}
    if sources:
        print("Источники: " + " | ".join(f"{name} {status}" for name, status in sources.items()))

    whois = result.get("whois") or {}
    print("\nWHOIS")
    if whois.get("error"):
        print(f"  ошибка: {whois['error']}")
    else:
        print(f"  Регистратор : {_osint_value(whois.get('registrar'))}")
        if whois.get("registrant_org") not in (None, "", "unknown"):
            print(f"  Организация : {whois['registrant_org']}")
        created = whois.get("creation_date")
        age = whois.get("age_days")
        print(f"  Создан      : {_osint_value(created)}"
              + (f" ({age} дн.)" if isinstance(age, int) else ""))
        expires = whois.get("expires_in_days")
        expires_at = whois.get("expiration_date")
        note = ""
        if isinstance(expires, int):
            note = f" (через {expires} дн.)"
            if expires <= 30:
                note += "  [!]"
        print(f"  Истекает    : {_osint_value(expires_at)}{note}")
        if whois.get("status"):
            print(f"  Статус      : {_osint_value(whois['status'])}")
        print(f"  NS          : {_osint_value(whois.get('name_servers'))}")

    dns = result.get("dns") or {}
    if dns:
        print("\nDNS")
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA", "DS"):
            if dns.get(rtype):
                values = [str(item)[:110] for item in dns[rtype]]
                print(f"  {rtype:<5}: {', '.join(values)}")
        security = result.get("security") or {}
        dnssec = "да" if security.get("dnssec") else "нет [!]"
        print(f"  DNSSEC: {dnssec}")

    email = result.get("email") or {}
    if email:
        print("\nПОЧТА")
        spf = email.get("spf") or {}
        if spf.get("record"):
            print(f"  SPF  : {spf['record'][:110]}  (lookup: {spf.get('lookups', 0)})")
        else:
            print("  SPF  : нет [!]")
        dmarc = email.get("dmarc") or {}
        print(f"  DMARC: {dmarc.get('policy') or 'нет [!]'}")
        print(f"  DKIM : {_osint_value(email.get('dkim'))}")

    subdomains = result.get("subdomains") or []
    if subdomains:
        passive = sum(1 for sub in subdomains if sub.get("source") == "passive")
        print(f"\nПОДДОМЕНЫ ({len(subdomains)}; crt.sh/пассивные {passive}, wordlist {len(subdomains) - passive})")

        new_names = sorted(
            sub["subdomain"] for sub in subdomains
            if previous_names and sub["subdomain"] not in previous_names
        )
        if previous_names:
            if new_names:
                print(f"  новых с прошлого скана: {len(new_names)} — {', '.join(new_names[:10])}")
            else:
                print("  новых с прошлого скана: нет")

        for sub in sorted(subdomains, key=lambda item: item.get("subdomain") or ""):
            info = sub.get("http") or {}
            parts = [sub.get("subdomain", "?")]
            if info:
                parts.append(str(info.get("status", "-")))
                if info.get("server"):
                    parts.append(info["server"])
                if info.get("title"):
                    parts.append(f"«{info['title']}»")
                if info.get("tls_days_left") is not None:
                    parts.append(f"TLS {info['tls_days_left']} дн.")
            elif sub.get("cname"):
                parts.append(f"CNAME {sub['cname']}")
            if sub.get("takeover"):
                parts.append("[!] takeover-кандидат")
            print("  " + "  ".join(parts))
    else:
        print("\nПоддомены: не найдены")

    findings = result.get("findings") or []
    print(f"\nНАХОДКИ: {len(findings)}")
    for finding in findings:
        severity = str(finding.get("severity", "?")).upper()
        print(f"  [{severity:8}] {finding.get('title')}")
        if finding.get("detail"):
            print(f"             {finding['detail']}")
        if finding.get("fix"):
            print(f"             fix: {finding['fix']}")


def cmd_osint(args):
    sources = [item.strip() for item in args.sources.split(",") if item.strip()]
    unknown = set(sources) - {"crt", "wordlist", "hackertarget"}
    if unknown:
        print(f"[-] Неизвестные источники: {', '.join(sorted(unknown))}")
        print("    допустимо: crt, wordlist, hackertarget")
        return 2

    if args.wordlist and not os.path.isfile(args.wordlist):
        print(f"[-] Файл словаря не найден: {args.wordlist}")
        return 1

    result = asyncio.run(api.run_osint_report(
        args.domain,
        wordlist_path=args.wordlist,
        active=args.active,
        sources=sources,
        concurrency=args.concurrency,
        use_cache=not args.no_cache,
    ))
    if not result or "error" in result:
        print(f"[-] {result.get('error', 'пустой результат')}")
        return 1

    domain = result.get("domain", args.domain)
    previous_names = database.get_previous_osint_subdomains(domain)
    _print_osint(result, previous_names)

    whois = result.get("whois") or {}
    # Кэш не создаёт новую запись: иначе один и тот же отчёт копится в истории
    if not result.get("cached"):
        database.save_osint_result(
            result.get("scan_time") or _now(),
            domain,
            whois.get("registrar") or "Неизвестно",
            len(result.get("subdomains") or []),
            expires_at=whois.get("expiration_date"),
            findings_count=len(result.get("findings") or []),
            subdomains=result.get("subdomains") or [],
        )

    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(f"\n[+] JSON сохранён: {args.json}")
    if args.report:
        print(f"[+] Отчёт сохранён: {api.save_osint_report(result)}")
    return 0


def cmd_web(args):
    cookies = dict(c.split("=", 1) for c in args.cookie) if args.cookie else None
    findings = asyncio.run(api.scan_web(args.target, port=args.port, cookies=cookies))
    if findings and "error" in findings[0]:
        print(f"[-] {findings[0]['error']}")
        return 1
    _dump(findings)
    print(f"\nНаходок: {len(findings)}")
    _save_report_flag(args, findings)
    return 0


def _jsonable(obj):
    """JSON для --json: dataclass-результаты становятся объектами, не строками."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return str(obj)


def cmd_pipeline(args):
    result = asyncio.run(api.run_combined_pipeline(
        args.domain, ports=args.ports, host_concurrency=args.concurrency,
        scan=getattr(args, "scan", False)))
    if "error" in result:
        print(f"[-] {result['error']}")
        return 1

    osint = result.get("osint") or {}
    subdomains = osint.get("subdomains") or []
    print(f"\nДомен: {result.get('domain')}  ({len(subdomains)} поддоменов)")
    print(f"Находки OSINT: {len(osint.get('findings') or [])}")
    for finding in (osint.get("findings") or [])[:10]:
        print(f"  [{finding.get('severity', '?').upper():8}] {finding.get('title')}")

    if not getattr(args, "scan", False):
        print("\nПорты не сканировались. Добавьте --scan, если это ваша инфраструктура.")
    else:
        scan_results = result.get("scan_results") or {}
        total_ports = sum(1 for results in scan_results.values() for r in results if r.status == "open")
        print(f"\nПросканировано хостов: {len(scan_results)}, открытых портов: {total_ports}")
        for ip, results in scan_results.items():
            open_ports = [r for r in results if r.status == "open"]
            if open_ports:
                print(f"  {ip}: " + ", ".join(f"{r.port}/{r.service}" for r in open_ports))
        findings = result.get("findings") or []
        print(f"Находки по портам: {len(findings)}")
        for f in findings[:15]:
            print(f"  [{str(f.get('severity', '?')).upper():8}] {f.get('host')}:{f.get('port')} "
                  f"{f.get('title')}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2, default=_jsonable), encoding="utf-8")
        print(f"\n[+] JSON сохранён: {args.json}")
    return 0


def cmd_rev(args):
    # сквозной проброс в ctfkit: всё после 'rev' — его подкоманда и аргументы
    return api.run_revpwn(args.args)


def cmd_vault(args):
    if args.vault_cmd == "list":
        for name in api.vault_list():
            print(name)
        return 0

    password = getpass.getpass("Мастер-пароль: ")
    try:
        unlocked = api.vault_unlock(password)
    except RuntimeError as exc:
        # например, потерян .salt: это не «неверный пароль»
        print(f"[-] {exc}")
        return 1
    if not unlocked:
        print("[-] Неверный пароль")
        return 1
    try:
        if args.vault_cmd == "save":
            value = getpass.getpass("Секрет: ")
            if not api.vault_save(args.name, value):
                print("[-] Не удалось сохранить секрет")
                return 1
            print(f"[+] Секрет '{args.name}' сохранён")
        elif args.vault_cmd == "load":
            value = api.vault_load(args.name)
            if value is None:
                print(f"[-] Секрет '{args.name}' не найден")
                return 1
            print(value)
    finally:
        api.vault_lock()
    return 0


def cmd_report(args):
    from core.modules.report_generator_utils.report_generator import generate_pdf_report
    generate_pdf_report(args.output)
    print(f"[+] PDF-отчёт сохранён: {args.output}")
    return 0


def cmd_history(args):
    conn = sqlite3.connect(database.DB_PATH)
    cursor = conn.cursor()
    for table, title in (("dlp_results", "DLP"),
                         ("network_results", "NETWORK"),
                         ("osint_results", "OSINT")):
        cursor.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (args.limit,))
        rows = cursor.fetchall()
        cols = [d[0] for d in cursor.description]
        print(f"\n=== {title} ===")
        if not rows:
            print("  (пусто)")
        for row in rows:
            data = dict(zip(cols, row))
            if table == "osint_results":
                expiry = data.get("expires_at") or "?"
                print(f"  {data.get('scan_time')}  {data.get('target_domain')}  "
                      f"{data.get('registrar')}  поддоменов: {data.get('subdomains_count')}  "
                      f"находок: {data.get('findings_count', 0)}  истекает: {expiry}")
            elif table == "dlp_results":
                print(f"  {data.get('scan_time')}  {data.get('checked_path')}  "
                      f"крит: {data.get('critical_count')}  выс: {data.get('high_count', 0)}  "
                      f"средн: {data.get('medium_count')}  низк: {data.get('low_count')}")
            else:
                print(f"  {data.get('scan_time')}  {data.get('target')}  "
                      f"портов: {data.get('open_ports_count')}  "
                      f"уязвимостей: {data.get('vulnerabilities_count')}")
            if table == "network_results":
                cursor.execute(
                    "SELECT host, port, vulnerability_title, severity FROM network_details "
                    "WHERE result_id = ? AND vulnerability_title IS NOT NULL", (row[0],))
                for host, port, vuln_title, severity in cursor.fetchall():
                    print(f"    ↳ {host or '?'}:{port}: {vuln_title} ({severity})")
    conn.close()
    return 0


def cmd_clear(args):
    if not args.yes:
        answer = input("Удалить ВСЮ историю сканирований? [y/N] ")
        if answer.strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено")
            return 0
    database.clear_all_data()
    print("[+] История очищена")
    return 0


def cmd_completion(args):
    shell = args.shell or _detect_shell()
    if not shell:
        print("[?] Не удалось определить оболочку — укажите явно:")
        print("    perimeter completion bash|zsh|powershell")
        return 1
    print(SHELL_SCRIPTS[shell].rstrip())
    return 0


# ---------------------------------------------------------------------------
# Автодополнение: shell-скрипты и скрытая команда _complete
# ---------------------------------------------------------------------------

# Bash/zsh: Tab спрашивает кандидатов у `perimeter _complete ...`.
# -o default оставляет обычное дополнение файлов (dlp/scan/osint принимают пути).
COMPLETION_BASH = """\
_perimeter_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local args=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    COMPREPLY=($(compgen -W "$(perimeter _complete "${args[@]}" "$cur")" -- "$cur"))
}
complete -o default -F _perimeter_complete perimeter"""

COMPLETION_ZSH = """\
autoload -Uz bashcompinit && bashcompinit
""" + COMPLETION_BASH

# shortcut: Register-ArgumentCompleter -Native есть только в PowerShell 7+,
# на встроенной 5.1 Tab работать не будет — обновить PowerShell.
COMPLETION_POWERSHELL = """\
Register-ArgumentCompleter -Native -CommandName perimeter -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = @($commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.Value })
    perimeter _complete @words | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}"""

SHELL_SCRIPTS = {
    "bash": COMPLETION_BASH,
    "zsh": COMPLETION_ZSH,
    "powershell": COMPLETION_POWERSHELL,
}


def _detect_shell():
    """Оболочка по $SHELL (Linux/macOS/Git Bash) или PowerShell на Windows."""
    name = os.path.basename(os.environ.get("SHELL", "")).lower()
    if name in SHELL_SCRIPTS:
        return name
    return "powershell" if os.name == "nt" else ""


def _subcommands(parser) -> list[str]:
    """Имена подкоманд парсера — единственный источник правды для подсказок и Tab."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return list(action.choices)
    return []


def _subparser(parser, name: str):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices.get(name)
    return None


def _complete(words) -> list[str]:
    """
    Кандидаты для Tab. `words` — всё после 'perimeter', последнее слово — префикс.
    Пусто -> имена команд; после 'vault' -> save/load/list; иначе флаги подкоманды.
    """
    words = list(words)
    prefix = words.pop() if words else ""

    node = build_parser()
    for word in words:
        child = _subparser(node, word)
        if child is None:
            break  # это значение аргумента (путь, домен) — дальше предлагать нечего
        node = child

    candidates = _subcommands(node) + [
        o for a in node._actions for o in a.option_strings if o not in ("-h", "--help")
    ]
    return sorted({c for c in candidates if c.startswith(prefix)})


def _suggest_command(word: str) -> str:
    """Ближайшая по написанию команда: 'dpl' -> 'dlp', иначе пустая строка."""
    matches = difflib.get_close_matches(word, _subcommands(build_parser()), n=1, cutoff=0.5)
    return matches[0] if matches else ""


# ---------------------------------------------------------------------------
# Парсер
# ---------------------------------------------------------------------------

MAIN_EPILOG = """\
Группы:  секреты — dlp, vault | сеть — scan, osint, pipeline | веб — web
         ctf — rev | отчёты — report, history, clear | оболочка — completion

Примеры:
  perimeter dlp ~/project --report
  perimeter scan 192.168.1.10 --ports 22,80,8000-8100
  perimeter scan 10.0.0.0/24 --report
  perimeter osint example.com --active --report
  perimeter pipeline example.com --scan --concurrency 20
  perimeter web 192.168.1.10 --port 4280 --cookie session=abc
  perimeter rev triage ./chall
  perimeter vault save github_token
  perimeter history --limit 10

Подробнее о модуле:  perimeter <команда> -h"""


class _Parser(argparse.ArgumentParser):
    """Справка по-русски: заголовки секций и свой -h (у подкоманд тоже)."""

    def __init__(self, **kwargs):
        kwargs.setdefault("add_help", False)
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(**kwargs)
        self._positionals.title = "аргументы"
        self._optionals.title = "опции"
        self.add_argument("-h", "--help", action="help", help="показать эту справку и выйти")


def _add(sub, name, help_, description, epilog):
    """Подкоманда с многострочным описанием и примерами (переносы сохраняются)."""
    return sub.add_parser(name, help=help_, description=description, epilog=epilog)


def build_parser():
    parser = _Parser(
        prog="perimeter",
        description=BANNER + "\n" + DISCLAIMER,
        epilog=MAIN_EPILOG,
    )
    sub = parser.add_subparsers(dest="command", metavar="<команда>")

    p = _add(
        sub, "dlp", "DLP-скан папки на утечки секретов",
        "Ищет в файлах папки приватные ключи SSH, токены (AWS, GitHub, OpenAI,\n"
        "Telegram), JWT и пароли. Находки обогащаются описанием и рекомендацией\n"
        "из базы знаний. Итог пишется в историю (таблица dlp_results).\n"
        "--git добавляет проверку истории: секреты, удалённые из кода, но\n"
        "оставшиеся в прошлых коммитах (их видит каждый, у кого есть клон).",
        "Примеры:\n"
        "  perimeter dlp ~/project\n"
        "  perimeter dlp . --git --report\n"
        "  perimeter dlp . --git --git-depth 5000 --show-secrets",
    )
    p.add_argument("path", metavar="PATH", help="папка для сканирования")
    p.add_argument("--report", action="store_true", help="сохранить JSON/TXT отчёт в ./reports")
    p.add_argument("--show-secrets", action="store_true",
                   help="печатать и сохранять секреты полностью (по умолчанию маскируются)")
    p.add_argument("--git", action="store_true",
                   help="проверить историю git: секреты в прошлых коммитах")
    p.add_argument("--git-depth", metavar="N", type=int, default=1000,
                   help="сколько последних коммитов проверять (по умолчанию 1000)")
    p.set_defaults(func=cmd_dlp)

    p = _add(
        sub, "scan", "скан портов + сигнатуры уязвимостей",
        "Проверяет TCP-порты цели (IP, домен или CIDR-подсеть) и сопоставляет\n"
        "открытые сервисы с базой уязвимостей. Итог пишется в историю\n"
        "(таблица network_results).",
        "Примеры:\n"
        "  perimeter scan 192.168.1.10\n"
        "  perimeter scan example.com --ports 22,80,443\n"
        "  perimeter scan 10.0.0.0/24 --ports 8000-8100 --report",
    )
    p.add_argument("target", metavar="TARGET", help="IP, домен или CIDR-подсеть")
    p.add_argument("--ports", metavar="PORTS", type=_ports_arg,
                   help="напр. 22,80,8000-8100 (по умолчанию — топ портов)")
    p.add_argument("--report", action="store_true", help="сохранить JSON/TXT отчёт в ./reports")
    p.set_defaults(func=cmd_scan)

    p = _add(
        sub, "osint", "WHOIS + DNS + поддомены + проверки конфигурации",
        "Разведка домена: WHOIS, DNS (A/AAAA/MX/TXT/NS/SOA/CNAME/CAA/DS),\n"
        "поддомены из crt.sh (Certificate Transparency) и wordlist, проверки\n"
        "SPF/DMARC/DKIM/DNSSEC/CAA. По умолчанию — только пассивные источники.\n"
        "Свой словарь: --wordlist PATH или PERIMETER_WORDLIST=...\n"
        "Итог пишется в историю (таблицы osint_results, osint_subdomains).",
        "Примеры:\n"
        "  perimeter osint example.com\n"
        "  perimeter osint example.com --report --json out.json\n"
        "  perimeter osint example.com --active\n"
        "  perimeter osint example.com --sources crt,wordlist,hackertarget",
    )
    p.add_argument("domain", metavar="DOMAIN", help="домен для разведки")
    p.add_argument("--active", action="store_true",
                   help="активные проверки: AXFR, HTTP/TLS-проба, subdomain takeover")
    p.add_argument("--sources", metavar="LIST", default="crt,wordlist",
                   help="источники поддоменов: crt,wordlist,hackertarget (по умолчанию crt,wordlist)")
    p.add_argument("--concurrency", metavar="N", type=int, default=50,
                   help="параллельных DNS-запросов (по умолчанию 50)")
    p.add_argument("--wordlist", metavar="PATH",
                   help="свой список поддоменов (по умолчанию встроенный или SecLists)")
    p.add_argument("--no-cache", action="store_true", help="не использовать кэш (TTL 24 ч)")
    p.add_argument("--json", metavar="PATH", help="сохранить полный отчёт в JSON")
    p.add_argument("--report", action="store_true", help="сохранить JSON-отчёт в ./reports")
    p.set_defaults(func=cmd_osint)

    p = _add(
        sub, "web", "веб-проверки для учебного стенда DVWA",
        "Проверки XSS, CSRF, brute force, file upload и open redirect по путям\n"
        "DVWA (/vulnerabilities/...). На обычном приложении эти пути дадут 404:\n"
        "модуль предназначен для стенда DVWA, а не для аудита любого сайта.\n"
        "Cookie нужны, если приложение за авторизацией.",
        "Примеры:\n"
        "  perimeter web 192.168.1.10\n"
        "  perimeter web 192.168.1.10 --port 8080 --cookie PHPSESSID=abc",
    )
    p.add_argument("target", metavar="TARGET", help="IP или хост веб-приложения")
    p.add_argument("--port", metavar="PORT", type=int, default=4280,
                   help="порт веб-приложения (по умолчанию 4280)")
    p.add_argument("--cookie", action="append", metavar="K=V",
                   help="cookie сессии, можно несколько раз")
    p.add_argument("--report", action="store_true", help="сохранить JSON/TXT отчёт в ./reports")
    p.set_defaults(func=cmd_web)

    p = _add(
        sub, "pipeline", "OSINT домена и (по желанию) скан его хостов",
        "Сквозной сценарий: разведка домена, затем по флагу --scan — скан портов\n"
        "всех найденных хостов с обогащением находок из базы знаний.\n"
        "Без --scan порты не сканируются: IP за CDN принадлежат провайдеру, а не\n"
        "владельцу домена.",
        "Примеры:\n"
        "  perimeter pipeline example.com\n"
        "  perimeter pipeline example.com --scan --ports 22,80,443 --json out.json",
    )
    p.add_argument("domain", metavar="DOMAIN", help="домен для разведки")
    p.add_argument("--scan", action="store_true",
                   help="сканировать порты найденных хостов (только с разрешения владельца)")
    p.add_argument("--ports", metavar="PORTS", type=_ports_arg,
                   help="порты для скана (по умолчанию — топ портов)")
    p.add_argument("--concurrency", metavar="N", type=int, default=10,
                   help="сколько хостов сканировать одновременно (по умолчанию 10)")
    p.add_argument("--json", metavar="PATH", help="сохранить полный отчёт в JSON")
    p.set_defaults(func=cmd_pipeline)

    p = _add(
        sub, "rev", "CTF rev/pwn-помощник (ctfkit): триаж ELF, ROP, эксплойты",
        "Фасад над встроенным ctfkit (rev-pwn): триаж Linux ELF x86-64,\n"
        "генерация скелетов эксплойтов, ROP/GOT/libc/heap-хелперы.\n"
        "Всё после 'rev' уходит в ctfkit как есть. Базовый режим работает без\n"
        "зависимостей (readelf/objdump/nm), полная точность — с pwntools\n"
        "(pip install perimeter[revpwn]). Часть команд требует Linux-тулзы\n"
        "(gdb, patchelf, one_gadget).\n"
        "Без аргументов печатает справку ctfkit со списком подкоманд.",
        "Примеры:\n"
        "  perimeter rev                 # список подкоманд ctfkit\n"
        "  perimeter rev triage ./chall\n"
        "  perimeter rev pwn ./chall\n"
        "  perimeter rev rop ./chall",
    )
    p.add_argument("args", nargs=argparse.REMAINDER, metavar="...",
                   help="подкоманда ctfkit и её аргументы (напр. triage ./chall)")
    p.set_defaults(func=cmd_rev)

    p = _add(
        sub, "vault", "шифрованное хранилище секретов",
        "Шифрованное хранилище секретов на диске. Мастер-пароль вводится\n"
        "скрыто; список имён доступен без пароля.",
        "Примеры:\n"
        "  perimeter vault save github_token\n"
        "  perimeter vault load github_token\n"
        "  perimeter vault list",
    )
    vsub = p.add_subparsers(dest="vault_cmd", required=True, metavar="<действие>")
    v = _add(vsub, "save", "сохранить секрет",
             "Запрашивает мастер-пароль и значение секрета (оба скрыто).",
             "  perimeter vault save github_token")
    v.add_argument("name", metavar="NAME", help="имя секрета")
    v = _add(vsub, "load", "прочитать секрет",
             "Печатает значение секрета в stdout.",
             "  perimeter vault load github_token")
    v.add_argument("name", metavar="NAME", help="имя секрета")
    _add(vsub, "list", "список имён секретов",
         "Печатает имена сохранённых секретов. Пароль не нужен.",
         "  perimeter vault list")
    p.set_defaults(func=cmd_vault)

    p = _add(
        sub, "report", "PDF-отчёт по истории сканирований из БД",
        "Генерирует PDF-отчёт по всем записям истории сканирований.",
        "Примеры:\n"
        "  perimeter report\n"
        "  perimeter report -o ~/audit.pdf",
    )
    p.add_argument("-o", "--output", metavar="FILE", default="perimeter_report.pdf",
                   help="куда сохранить PDF (по умолчанию perimeter_report.pdf)")
    p.set_defaults(func=cmd_report)

    p = _add(
        sub, "history", "последние записи истории сканов",
        "Печатает последние записи из истории: DLP, сеть (с деталями по портам)\n"
        "и OSINT. Только чтение.",
        "Примеры:\n"
        "  perimeter history\n"
        "  perimeter history --limit 20",
    )
    p.add_argument("--limit", metavar="N", type=int, default=5,
                   help="сколько последних записей показывать (по умолчанию 5)")
    p.set_defaults(func=cmd_history)

    p = _add(
        sub, "clear", "очистить всю историю сканирований",
        "Удаляет все записи истории сканирований из локальной БД.\n"
        "Спрашивает подтверждение, если не указан --yes.",
        "Примеры:\n"
        "  perimeter clear\n"
        "  perimeter clear --yes",
    )
    p.add_argument("--yes", action="store_true", help="удалить без подтверждения")
    p.set_defaults(func=cmd_clear)

    p = _add(
        sub, "completion", "скрипт автодополнения (Tab) для shell",
        "Печатает скрипт автодополнения для Tab. Без аргумента оболочка\n"
        "определяется по $SHELL (на Windows — PowerShell).\n"
        "\n"
        "Установка:\n"
        "  bash        eval \"$(perimeter completion bash)\"        # в ~/.bashrc\n"
        "  zsh         eval \"$(perimeter completion zsh)\"         # в ~/.zshrc\n"
        "  PowerShell  perimeter completion powershell | Add-Content $PROFILE  # PS 7+",
        "Примеры:\n"
        "  perimeter completion bash\n"
        "  perimeter completion powershell > perimeter-completion.ps1",
    )
    p.add_argument("shell", nargs="?", choices=sorted(SHELL_SCRIPTS), metavar="SHELL",
                   help="bash | zsh | powershell (по умолчанию — по $SHELL)")
    p.set_defaults(func=cmd_completion)

    return parser



def main(argv=None):
    # кириллица/баннер не должны ронять вывод при редиректе в файл на Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    argv = list(sys.argv[1:] if argv is None else argv)

    # скрытая точка входа для shell-автодополнения (см. `perimeter completion`)
    if argv and argv[0] == "_complete":
        for candidate in _complete(argv[1:]):
            print(candidate)
        return 0

    parser = build_parser()
    if argv and not argv[0].startswith("-") and argv[0] not in _subcommands(parser):
        hint = _suggest_command(argv[0])
        print(f"[-] Неизвестная команда '{argv[0]}'." + (f" Возможно: {hint}." if hint else ""))
        print("    perimeter -h — модули и примеры · perimeter completion — автодополнение (Tab)")
        return 2

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    # Схему готовим перед выполнением, а не при импорте: -h должен работать
    # и на read-only дереве, где рядом с кодом нельзя создать базу.
    try:
        database.init_db()
    except Exception as ex:
        print(f"[!] История сканов недоступна: {ex}")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nПрервано")
        return 130
    except Exception as ex:
        print(f"[-] Ошибка: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
