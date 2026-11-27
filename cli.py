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
import sqlite3
import sys
from datetime import datetime

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
    findings = api.scan_dlp(args.path, show_secrets=getattr(args, "show_secrets", False), stats=stats)
    if findings and "error" in findings[0]:
        print(f"[-] {findings[0]['error']}")
        return 1

    critical = medium = low = 0
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in ("CRITICAL", "HIGH"):
            critical += 1
        elif sev == "MEDIUM":
            medium += 1
        else:
            low += 1
        kind = f.get("type") or f.get("vuln_type", "?")
        loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
        match = f.get("raw_line") or f.get("match") or f.get("value") or ""
        print(f"[{sev:8}] {kind:20} {loc}")
        if match:
            print(f"           {str(match).strip()[:120]}")
        if f.get("fix"):
            print(f"           fix: {f['fix']}")

    if not findings:
        print("[+] Угроз не обнаружено")
    database.save_dlp_result(_now(), args.path, critical, medium, low)
    print(f"\nИтого: критических {critical}, средних {medium}, низких {low}")
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


def cmd_osint(args):
    result = asyncio.run(api.run_osint_report(args.domain))
    if not result or "error" in result:
        print(f"[-] {result.get('error', 'пустой результат')}")
        return 1

    whois_data = result.get("whois", {})
    registrar = whois_data.get("registrar") or whois_data.get("registrar_name") or "Неизвестно"
    subdomains = result.get("subdomains", [])
    database.save_osint_result(result.get("scan_time") or _now(),
                               result.get("domain", args.domain), registrar, len(subdomains))

    print(f"Домен: {result.get('domain', args.domain)}")
    print(f"Время: {result.get('scan_time', '-')}")
    if whois_data:
        print("\nWHOIS:")
        for k, v in whois_data.items():
            print(f"  {k}: {v}")
    dns_data = result.get("dns", {})
    if dns_data:
        print("\nDNS:")
        for rtype, ips in dns_data.items():
            print(f"  {rtype}: {', '.join(ips) if isinstance(ips, list) else ips}")
    print(f"\nПоддомены ({len(subdomains)}):")
    for sub in subdomains:
        if isinstance(sub, dict):
            print(f"  {sub.get('subdomain')} -> {sub.get('ip')}")
        else:
            print(f"  {sub}")
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


def cmd_pipeline(args):
    result = asyncio.run(api.run_combined_pipeline(
        args.domain, ports=args.ports, host_concurrency=args.concurrency))
    if "error" in result:
        print(f"[-] {result['error']}")
        return 1
    _dump(result)
    return 0


def cmd_vault(args):
    if args.vault_cmd == "list":
        for name in api.vault_list():
            print(name)
        return 0

    password = getpass.getpass("Мастер-пароль: ")
    if not api.vault_unlock(password):
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
            print("  " + " | ".join(f"{c}={v}" for c, v in zip(cols, row)))
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
         отчёты — report, history, clear | оболочка — completion

Примеры:
  perimeter dlp ~/project --report
  perimeter scan 192.168.1.10 --ports 22,80,8000-8100
  perimeter scan 10.0.0.0/24 --report
  perimeter osint example.com
  perimeter pipeline example.com --concurrency 20
  perimeter web 192.168.1.10 --port 4280 --cookie session=abc
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
        "из базы знаний. Итог пишется в историю (таблица dlp_results).",
        "Примеры:\n"
        "  perimeter dlp ~/project\n"
        "  perimeter dlp C:\\project --report",
    )
    p.add_argument("path", metavar="PATH", help="папка для сканирования")
    p.add_argument("--report", action="store_true", help="сохранить JSON/TXT отчёт в ./reports")
    p.add_argument("--show-secrets", action="store_true",
                   help="печатать и сохранять секреты полностью (по умолчанию маскируются)")
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
        sub, "osint", "WHOIS + DNS + перебор поддоменов",
        "Собирает WHOIS и DNS-записи домена, затем перебирает поддомены по\n"
        "wordlist. Итог пишется в историю (таблица osint_results).",
        "Примеры:\n"
        "  perimeter osint example.com",
    )
    p.add_argument("domain", metavar="DOMAIN", help="домен для разведки")
    p.set_defaults(func=cmd_osint)

    p = _add(
        sub, "web", "аудит веб-уязвимостей (L7)",
        "Аудит веб-приложения: заголовки безопасности, чувствительные пути и\n"
        "прочие проверки L7. Cookie нужны, если приложение за авторизацией.",
        "Примеры:\n"
        "  perimeter web 192.168.1.10\n"
        "  perimeter web 192.168.1.10 --port 8080 --cookie session=abc",
    )
    p.add_argument("target", metavar="TARGET", help="IP или хост веб-приложения")
    p.add_argument("--port", metavar="PORT", type=int, default=4280,
                   help="порт веб-приложения (по умолчанию 4280)")
    p.add_argument("--cookie", action="append", metavar="K=V",
                   help="cookie сессии, можно несколько раз")
    p.add_argument("--report", action="store_true", help="сохранить JSON/TXT отчёт в ./reports")
    p.set_defaults(func=cmd_web)

    p = _add(
        sub, "pipeline", "OSINT -> скан портов всех найденных хостов -> обогащение",
        "Сквозной сценарий: разведка домена, скан портов каждого найденного\n"
        "хоста и обогащение находок из базы знаний. Печатает JSON.",
        "Примеры:\n"
        "  perimeter pipeline example.com\n"
        "  perimeter pipeline example.com --ports 22,80,443 --concurrency 20",
    )
    p.add_argument("domain", metavar="DOMAIN", help="домен для разведки")
    p.add_argument("--ports", metavar="PORTS", type=_ports_arg,
                   help="порты для скана (по умолчанию — топ портов)")
    p.add_argument("--concurrency", metavar="N", type=int, default=10,
                   help="сколько хостов сканировать одновременно (по умолчанию 10)")
    p.set_defaults(func=cmd_pipeline)

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
