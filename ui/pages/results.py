"""
ui/pages/results.py — Экран результатов аудита.

• Большой Score в центре
• Карточки: Secrets, Configs, Headers (web), TLS (web)
• При клике на карточку — разворачивается список находок
• Кнопка «Сохранить отчёт»
• Кнопка «← Назад»
"""

import logging
from datetime import datetime
from pathlib import Path

import flet as ft
import api

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Цвета severity
# ──────────────────────────────────────────────────────────────────────────────

def _sev_color(sev: str) -> str:
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "#ff1744"
    if s == "MEDIUM":
        return "#ff9100"
    if s == "LOW":
        return "#ffea00"
    return "#a7a2be"


def _sev_icon(sev: str):
    s = (sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return ft.Icons.DANGEROUS
    if s == "MEDIUM":
        return ft.Icons.WARNING_AMBER
    if s == "LOW":
        return ft.Icons.INFO_OUTLINE
    return ft.Icons.CIRCLE_OUTLINED


def _score_color(score: int) -> str:
    if score >= 71:
        return "#00e676"
    if score >= 41:
        return "#ff9100"
    return "#ff1744"


# ──────────────────────────────────────────────────────────────────────────────
# Карточка категории
# ──────────────────────────────────────────────────────────────────────────────

def _result_card(
    icon,
    label: str,
    count: int,
    color: str,
    findings: list,
    page: ft.Page,
) -> ft.Container:
    """
    Карточка с иконкой, числом и раскрывающимся списком находок.
    """
    expanded = [False]

    findings_column = ft.Column(
        controls=[],
        visible=False,
        spacing=4,
    )

    def _build_findings():
        findings_column.controls.clear()
        if not findings:
            findings_column.controls.append(
                ft.Text("  Находок нет", size=12, color="#393053",
                        italic=True)
            )
            return
        for f in findings[:30]:  # Лимит 30 строк в карточке
            sev = f.get("severity", "")
            title = (
                f.get("title")
                or f.get("type")
                or f.get("vuln_type")
                or "Неизвестно"
            )
            file_ref = f.get("file") or f.get("host") or ""
            line = f.get("line")
            line_str = f" : {line}" if line else ""
            fix = f.get("fix") or f.get("recommendation") or ""

            findings_column.controls.append(
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(_sev_icon(sev), color=_sev_color(sev), size=14),
                            ft.Text(
                                title,
                                size=12,
                                color="#ffffff",
                                weight=ft.FontWeight.W_500,
                                expand=True,
                            ),
                            ft.Text(sev, size=11, color=_sev_color(sev)),
                        ], spacing=6),
                        ft.Text(
                            f"{file_ref}{line_str}",
                            size=11,
                            color="#a7a2be",
                            font_family="Courier New",
                        ) if file_ref else ft.Container(height=0),
                        ft.Text(
                            f"→ {fix}",
                            size=11,
                            color="#a7a2be",
                            italic=True,
                            no_wrap=False,
                        ) if fix else ft.Container(height=0),
                    ], spacing=2),
                    padding=ft.Padding(left=8, top=6, right=8, bottom=6),
                    bgcolor="#0b0813",
                    border_radius=6,
                )
            )

    _build_findings()

    chevron = ft.Icon(ft.Icons.KEYBOARD_ARROW_DOWN, color="#a7a2be", size=18)

    def toggle(e):
        expanded[0] = not expanded[0]
        findings_column.visible = expanded[0]
        chevron.name = (
            ft.Icons.KEYBOARD_ARROW_UP
            if expanded[0]
            else ft.Icons.KEYBOARD_ARROW_DOWN
        )
        page.update()

    header = ft.Container(
        content=ft.Row([
            ft.Icon(icon, color=color, size=24),
            ft.Column([
                ft.Text(label, size=13, color="#a7a2be", weight=ft.FontWeight.W_500),
                ft.Text(
                    str(count) if count > 0 else "—",
                    size=28,
                    weight=ft.FontWeight.BOLD,
                    color=color,
                ),
            ], spacing=0),
            ft.Container(expand=True),
            ft.Text(
                "подробнее" if count > 0 else "",
                size=11,
                color="#393053",
            ),
            chevron if count > 0 else ft.Container(width=0),
        ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
        on_click=toggle if count > 0 else None,
        ink=count > 0,
        padding=ft.Padding(left=16, top=16, right=16, bottom=16),
    )

    return ft.Container(
        content=ft.Column([header, findings_column], spacing=0),
        bgcolor="#18122b",
        border_radius=14,
        border=ft.Border(
            top=ft.BorderSide(1, color if count > 0 else "#251b45"),
            bottom=ft.BorderSide(1, color if count > 0 else "#251b45"),
            left=ft.BorderSide(1, color if count > 0 else "#251b45"),
            right=ft.BorderSide(1, color if count > 0 else "#251b45"),
        ),
        clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Детальные панели (OSINT + Network) — стиль «консоли» как в старых страницах
# ──────────────────────────────────────────────────────────────────────────────

def _console_line(text: str, color: str = "#a7a2be") -> ft.Text:
    return ft.Text(text, font_family="Courier New", size=12, color=color, selectable=True)


def _build_osint_detail(osint: dict, domain: str) -> list:
    """Возвращает список Flet-контролов с детальным OSINT-выводом."""
    if not osint or "error" in osint:
        return []

    lines = []

    # WHOIS
    whois = osint.get("whois", {})
    if whois:
        lines.append(_console_line(" -> Данные WHOIS:", "#b388ff"))
        for k, v in whois.items():
            lines.append(_console_line(f"    | {k}: {v}"))

    # DNS
    dns = osint.get("dns", {})
    if dns:
        lines.append(_console_line(" -> DNS записи:", "#b388ff"))
        for rtype, vals in dns.items():
            v_str = ", ".join(vals) if isinstance(vals, list) else str(vals)
            lines.append(_console_line(f"    | {rtype}: {v_str}"))

    # Субдомены
    subdomains = osint.get("subdomains", [])
    lines.append(_console_line(f" -> Найдено поддоменов: {len(subdomains)}", "#b388ff"))
    for sub in subdomains[:50]:
        if isinstance(sub, dict):
            sub_name = sub.get("subdomain", "?")
            sub_ip   = sub.get("ip", "")
            lines.append(_console_line(
                f"    | {sub_name}" + (f" -> IP: {sub_ip}" if sub_ip else ""),
                "#ffeb3b",
            ))
        else:
            lines.append(_console_line(f"    | {sub}", "#ffeb3b"))
    if len(subdomains) > 50:
        lines.append(_console_line(f"    | ... ещё {len(subdomains) - 50} поддоменов", "#393053"))

    if not lines:
        return []

    return [
        ft.Container(height=8),
        ft.Text("Разведка (OSINT)", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
        ft.Container(height=6),
        ft.Container(
            content=ft.Container(
                content=ft.Column(
                    controls=[
                        _console_line(f"[+] Домен: {osint.get('domain', domain)}", "#00e676"),
                        _console_line(f" -> Время: {osint.get('scan_time', '—')}"),
                        *lines,
                    ],
                    spacing=3,
                    scroll=ft.ScrollMode.AUTO,
                ),
                height=300,
                padding=ft.Padding(left=14, top=12, right=14, bottom=12),
            ),
            bgcolor="#0b0813",
            border_radius=10,
            border=ft.Border(
                top=ft.BorderSide(1, "#251b45"),
                bottom=ft.BorderSide(1, "#251b45"),
                left=ft.BorderSide(1, "#251b45"),
                right=ft.BorderSide(1, "#251b45"),
            ),
        ),
    ]


def _build_network_detail(network: list) -> list:
    """Возвращает список Flet-контролов с детальным выводом портов и уязвимостей."""
    if not network:
        return []

    lines = []
    for f in network:
        port    = f.get("port", "?")
        service = f.get("service", "unknown")
        banner  = f.get("banner", "")
        vulns   = f.get("findings", [])

        lines.append(_console_line(
            f"[+] Порт {port} ({service})" + (f"  баннер: {banner}" if banner else ""),
            "#00e676",
        ))
        if vulns:
            for v in vulns:
                sev   = v.get("severity", "?")
                title = v.get("title", "Уязвимость")
                rec   = v.get("recommendation") or v.get("fix", "")
                sev_color = _sev_color(sev)
                lines.append(_console_line(f"    ↳ [!] {title} [{sev}]", sev_color))
                if rec:
                    lines.append(_console_line(f"        → {rec}", "#a7a2be"))
        else:
            lines.append(_console_line("    ↳ Известных уязвимостей не обнаружено", "#393053"))

    return [
        ft.Container(height=8),
        ft.Text("Детали сканирования портов", size=14, color="#a7a2be", weight=ft.FontWeight.W_500),
        ft.Container(height=6),
        ft.Container(
            content=ft.Container(
                content=ft.Column(
                    controls=lines,
                    spacing=3,
                    scroll=ft.ScrollMode.AUTO,
                ),
                height=300,
                padding=ft.Padding(left=14, top=12, right=14, bottom=12),
            ),
            bgcolor="#0b0813",
            border_radius=10,
            border=ft.Border(
                top=ft.BorderSide(1, "#251b45"),
                bottom=ft.BorderSide(1, "#251b45"),
                left=ft.BorderSide(1, "#251b45"),
                right=ft.BorderSide(1, "#251b45"),
            ),
        ),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Главная функция страницы
# ──────────────────────────────────────────────────────────────────────────────

def results_page(
    page: ft.Page,
    audit_result: dict,
    mode: str,       # "project" | "web"
    on_back,         # callable()
) -> ft.Column:

    score: int = audit_result.get("score", 0)
    target: str = audit_result.get("target", "")
    scan_time: str = audit_result.get("scan_time", "")

    # ── Разбираем находки по категориям ─────────────────────────────────────

    if mode == "project":
        dlp_findings: list = audit_result.get("dlp", [])
        git_data: dict = audit_result.get("git", {})

        # Secrets — всё из DLP
        secrets = [f for f in dlp_findings if "error" not in f]

        # Configs — находки типа config / env / docker / yaml
        CONFIG_TYPES = {"config", "env", "docker", "yaml", "toml", "ini", "cfg"}
        configs = [
            f for f in secrets
            if (f.get("type") or f.get("vuln_type") or "").lower() in CONFIG_TYPES
        ]

        headers_findings: list = []
        tls_findings: list = []
        ports_findings: list = []

        # Git-находки как доп. секреты
        git_findings = git_data.get("findings", []) if isinstance(git_data, dict) else []
        secrets = secrets + [
            {"type": "git_secret", "title": g.get("title", "Git issue"),
             "severity": g.get("severity", "MEDIUM"),
             "file": g.get("file", ""), "fix": g.get("fix", "")}
            for g in git_findings
        ]

    else:  # web
        all_findings: list = list(audit_result.get("findings", []))

        # Порты из network[], если pipeline вернул их отдельно (fallback-режим)
        network_data = audit_result.get("network", [])
        existing_port_keys = {
            (f.get("host"), f.get("port"))
            for f in all_findings
            if f.get("type") == "open_port"
        }
        if isinstance(network_data, list):
            for port_info in network_data:
                key = (port_info.get("host"), port_info.get("port"))
                if key not in existing_port_keys:
                    all_findings.append({
                        "type": "open_port",
                        "title": f"Открытый порт {port_info.get('port')} ({port_info.get('service', 'unknown')})",
                        "severity": "LOW",
                        "host": port_info.get("host", target),
                        "port": port_info.get("port"),
                        "banner": port_info.get("banner", ""),
                        "fix": (
                            f"Закройте порт {port_info.get('port')}, "
                            f"если сервис {port_info.get('service', 'unknown')} не нужен снаружи."
                        ),
                    })
                    existing_port_keys.add(key)

        # Фильтрация по категориям
        secrets = [
            f for f in all_findings
            if (f.get("type") or f.get("vuln_type") or "").lower()
            in {"ssh_key", "aws_key", "aws_secret", "github", "openai",
                "telegram", "jwt", "password", "secret"}
        ]
        configs = [
            f for f in all_findings
            if (f.get("type") or f.get("vuln_type") or "").lower()
            in {"config", "env", "docker", "yaml"}
        ]
        headers_findings = [
            f for f in all_findings
            if "header" in (f.get("type") or f.get("vuln_type") or "").lower()
        ]
        tls_findings = [
            f for f in all_findings
            if "tls" in (f.get("type") or f.get("vuln_type") or "").lower()
            or "ssl" in (f.get("type") or f.get("vuln_type") or "").lower()
            or "cert" in (f.get("type") or f.get("vuln_type") or "").lower()
        ]
        # Открытые порты — отдельная категория
        ports_findings = [
            f for f in all_findings
            if f.get("type") in ("open_port", "port")
            or f.get("type") == "vulnerability"
        ]

    def _card_color(items: list) -> str:
        if not items:
            return "#00e676"
        sevs = [(f.get("severity") or "").upper() for f in items]
        if any(s in ("CRITICAL", "HIGH") for s in sevs):
            return "#ff1744"
        if any(s == "MEDIUM" for s in sevs):
            return "#ff9100"
        return "#ffea00"

    # ── Score виджет ─────────────────────────────────────────────────────────
    score_color = _score_color(score)
    score_label = (
        "Высокий уровень защиты" if score >= 71
        else "Средний уровень защиты" if score >= 41
        else "Критические уязвимости"
    )

    score_widget = ft.Column([
        ft.Text(
            str(score),
            size=96,
            weight=ft.FontWeight.BOLD,
            color=score_color,
            text_align=ft.TextAlign.CENTER,
        ),
        ft.Text(
            score_label,
            size=14,
            color=score_color,
            text_align=ft.TextAlign.CENTER,
            weight=ft.FontWeight.W_500,
        ),
        ft.Text(
            "Индекс безопасности",
            size=12,
            color="#393053",
            text_align=ft.TextAlign.CENTER,
        ),
    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=4)

    # ── Итоговые строки ───────────────────────────────────────────────────────
    def _summary_row(icon, label: str, items: list) -> ft.Row:
        color = _card_color(items)
        count = len(items)
        val = f"{count} найдено" if count > 0 else "чисто"
        return ft.Row([
            ft.Icon(icon, color=color, size=18),
            ft.Text(label, size=13, color="#ffffff", width=100),
            ft.Text(val, size=13, color=color, weight=ft.FontWeight.W_500),
        ], spacing=10)

    summary_items = [
        _summary_row(ft.Icons.KEY, "Secrets", secrets),
        _summary_row(ft.Icons.SETTINGS, "Configs", configs),
    ]
    if mode == "web":
        summary_items += [
            _summary_row(ft.Icons.ROUTER, "Открытые порты", ports_findings),
            _summary_row(ft.Icons.HTTP, "Headers", headers_findings),
            _summary_row(ft.Icons.LOCK, "TLS", tls_findings),
        ]

    # ── Карточки ──────────────────────────────────────────────────────────────
    cards = [
        _result_card(
            icon=ft.Icons.KEY,
            label="Secrets",
            count=len(secrets),
            color=_card_color(secrets),
            findings=secrets,
            page=page,
        ),
        _result_card(
            icon=ft.Icons.SETTINGS,
            label="Configs",
            count=len(configs),
            color=_card_color(configs),
            findings=configs,
            page=page,
        ),
    ]
    if mode == "web":
        cards += [
            _result_card(
                icon=ft.Icons.ROUTER,
                label="Открытые порты",
                count=len(ports_findings),
                color=_card_color(ports_findings),
                findings=ports_findings,
                page=page,
            ),
            _result_card(
                icon=ft.Icons.HTTP,
                label="Headers",
                count=len(headers_findings),
                color=_card_color(headers_findings),
                findings=headers_findings,
                page=page,
            ),
            _result_card(
                icon=ft.Icons.LOCK,
                label="TLS / SSL",
                count=len(tls_findings),
                color=_card_color(tls_findings),
                findings=tls_findings,
                page=page,
            ),
        ]

    # ── Сохранение отчёта ─────────────────────────────────────────────────────
    save_status = ft.Text("", size=12, color="#a7a2be")

    def on_save(e):
        try:
            _ports = ports_findings if mode == "web" else []
            all_f = secrets + configs + _ports + headers_findings + tls_findings
            json_p, txt_p = api.save_report(all_f)
            save_status.value = f"✓ Отчёт сохранён: {txt_p}"
            save_status.color = "#00e676"
        except Exception as ex:
            save_status.value = f"Ошибка: {ex}"
            save_status.color = "#ff1744"
        page.update()

    # ── Шапка ────────────────────────────────────────────────────────────────
    mode_icon = ft.Icons.FOLDER if mode == "project" else ft.Icons.LANGUAGE
    mode_label = "Аудит проекта" if mode == "project" else "Аудит инфраструктуры"

    header_row = ft.Row([
        ft.IconButton(
            icon=ft.Icons.ARROW_BACK,
            icon_color="#a7a2be",
            tooltip="На главную",
            on_click=lambda e: on_back(),
        ),
        ft.Icon(mode_icon, color="#a7a2be", size=20),
        ft.Column([
            ft.Text(mode_label, size=18, weight=ft.FontWeight.BOLD, color="#ffffff"),
            ft.Text(
                target,
                size=11,
                color="#393053",
                overflow=ft.TextOverflow.ELLIPSIS,
                max_lines=1,
            ),
        ], spacing=2, expand=True),
        ft.Text(scan_time, size=11, color="#393053"),
    ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10)

    # ── Сборка ───────────────────────────────────────────────────────────────
    return ft.Column(
        controls=[
            ft.Container(
                content=ft.Column([
                    header_row,
                    ft.Divider(color="#251b45"),
                    ft.Container(height=10),

                    # Score по центру
                    score_widget,
                    ft.Container(height=16),

                    # Итоговые строки
                    ft.Container(
                        content=ft.Column(summary_items, spacing=10),
                        bgcolor="#18122b",
                        border_radius=12,
                        padding=16,
                        border=ft.Border(
                            top=ft.BorderSide(1, "#251b45"),
                            bottom=ft.BorderSide(1, "#251b45"),
                            left=ft.BorderSide(1, "#251b45"),
                            right=ft.BorderSide(1, "#251b45"),
                        ),
                    ),

                    ft.Container(height=20),
                    ft.Text(
                        "Результаты по категориям",
                        size=14,
                        color="#a7a2be",
                        weight=ft.FontWeight.W_500,
                    ),
                    ft.Container(height=8),

                    # Карточки в сетке 2×N
                    ft.Column(
                        controls=[
                            ft.Row(
                                controls=cards[i:i+2],
                                spacing=12,
                            )
                            for i in range(0, len(cards), 2)
                        ],
                        spacing=12,
                    ),

                    ft.Container(height=20),

                    # ── Детали OSINT (только web) ─────────────────────────
                    *(_build_osint_detail(audit_result.get("osint", {}), target) if mode == "web" else []),

                    # ── Детали портов (только web) ────────────────────────
                    *(_build_network_detail(audit_result.get("network", [])) if mode == "web" else []),

                    ft.Container(height=20),

                    # Кнопка сохранения
                    ft.Row([
                        ft.ElevatedButton(
                            content=ft.Row([
                                ft.Icon(ft.Icons.SAVE_ALT, color="#0b0813"),
                                ft.Text("Сохранить отчёт", color="#0b0813"),
                            ], spacing=8),
                            bgcolor="#b388ff",
                            on_click=on_save,
                        ),
                        save_status,
                    ], spacing=16, vertical_alignment=ft.CrossAxisAlignment.CENTER),

                    ft.Container(height=30),
                ], spacing=0),
                padding=ft.Padding(left=25, top=25, right=25, bottom=25),
            ),
        ],
        scroll=ft.ScrollMode.AUTO,
        expand=True,
    )
