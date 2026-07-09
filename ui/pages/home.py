"""
ui/pages/home.py — Главный экран «Периметра».

Два и только два сценария:
  • «Проверить проект» → FilePicker → run_project_audit / scan_dlp + scan_git
  • «Проверить сайт»   → TextField с доменом → run_combined_pipeline

История последних 5 запусков из БД.
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path

import flet as ft
import api
import database

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Вспомогательные стили
# ──────────────────────────────────────────────────────────────────────────────

_CARD = dict(
    bgcolor="#18122b",
    border_radius=16,
    border=ft.Border(
        top=ft.BorderSide(1, "#393053"),
        bottom=ft.BorderSide(1, "#393053"),
        left=ft.BorderSide(1, "#393053"),
        right=ft.BorderSide(1, "#393053"),
    ),
)


def _neon_button(label: str, icon, color: str, on_click) -> ft.Container:
    """Большая акцентная кнопка сценария."""
    return ft.Container(
        content=ft.Column(
            controls=[
                ft.Icon(icon, color=color, size=42), # Чуть увеличили иконку для баланса
                ft.Text(label, size=18, weight=ft.FontWeight.BOLD, color="#ffffff", text_align=ft.TextAlign.CENTER),
            ],
            alignment=ft.MainAxisAlignment.CENTER,       # Центрируем по вертикали
            horizontal_alignment=ft.CrossAxisAlignment.CENTER, # Центрируем по горизонтали
            spacing=15, # Красивый отступ между иконкой и текстом
        ),
        width=260,
        height=160, # Слегка увеличили высоту, чтобы тексту снизу было просторно
        bgcolor="#18122b",
        border_radius=18,
        border=ft.Border(
            top=ft.BorderSide(1.5, color),
            bottom=ft.BorderSide(1.5, color),
            left=ft.BorderSide(1.5, color),
            right=ft.BorderSide(1.5, color),
        ),
        on_click=on_click,
        ink=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Главная страница
# ──────────────────────────────────────────────────────────────────────────────

def home_page(
    page: ft.Page,
    on_project_result,   # callable(dict)
    on_web_result,       # callable(dict)
) -> ft.Column:

    # ── Статус / прогресс ────────────────────────────────────────────────────
    progress_ring = ft.ProgressRing(
        width=28, height=28, stroke_width=3,
        color="#b388ff", visible=False,
    )
    status_text = ft.Text("", size=13, color="#a7a2be")

    status_row = ft.Row(
        controls=[progress_ring, status_text],
        spacing=10,
        visible=False,
        alignment=ft.MainAxisAlignment.CENTER,
    )

    def set_status(msg: str, busy: bool = True):
        status_text.value = msg
        progress_ring.visible = busy
        status_row.visible = True
        page.update()

    def clear_status():
        status_row.visible = False
        page.update()

    # ── Диалог ввода пути к проекту ─────────────────────────────────────────
    selected_path_text = ft.Text("", size=12, color="#a7a2be", visible=False)

    project_path_field = ft.TextField(
        label="Путь к папке проекта",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        color="#ffffff",
        width=340,
        hint_text=r"C:\Users\user\myproject",
        hint_style=ft.TextStyle(color="#393053"),
    )

    project_dialog_open = [False]

    def close_project_dialog(e=None):
        project_dialog.open = False
        project_dialog_open[0] = False
        page.update()

    async def on_project_dialog_run(e):
        path = (project_path_field.value or "").strip()
        if not path:
            project_path_field.error_text = "Введите путь к директории"
            page.update()
            return
        project_path_field.error_text = None
        close_project_dialog()
        selected_path_text.value = f"📁 {path}"
        selected_path_text.visible = True
        page.update()
        await _run_project(path)

    project_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Проверить проект", color="#ffffff", weight=ft.FontWeight.BOLD),
        content=ft.Container(
            content=ft.Column([
                ft.Text("Введите путь к папке проекта для аудита:", color="#a7a2be", size=13),
                ft.Container(height=8),
                project_path_field,
            ], tight=True),
            width=380,
        ),
        bgcolor="#18122b",
        actions=[
            ft.TextButton("Отмена", style=ft.ButtonStyle(color="#a7a2be"), on_click=close_project_dialog),
            ft.ElevatedButton(
                "Запустить",
                bgcolor="#b388ff",
                color="#0b0813",
                on_click=on_project_dialog_run,
            ),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
    )
    page.overlay.append(project_dialog)

    # ── Диалог ввода домена (сайт) ───────────────────────────────────────────
    domain_field = ft.TextField(
        label="Домен или IP-адрес",
        label_style=ft.TextStyle(color="#a7a2be", size=13),
        border_color="#393053",
        focused_border_color="#b388ff",
        bgcolor="#130f22",
        color="#ffffff",
        width=340,
        hint_text="example.com",
        hint_style=ft.TextStyle(color="#393053"),
    )

    web_dialog_open = [False]

    def close_web_dialog(e=None):
        web_dialog.open = False
        web_dialog_open[0] = False
        page.update()
    
    def on_clear_history_click(e):
        def confirm_clear(ae):
            try:
                database.clear_all_data()
                _build_history()
                page.update()
            except Exception as ex:
                logger.error("Ошибка при очистке БД: %s", ex)
            confirm_dialog.open = False
            page.update()

        def cancel_clear(ae):
            confirm_dialog.open = False
            page.update()

        # Защитное диалоговое окно от случайных нажатий
        confirm_dialog = ft.AlertDialog(
            title=ft.Text("Очистить всю историю?", color="#ffffff"),
            content=ft.Text("Это действие безвозвратно удалит все сохраненные результаты аудитов.", color="#a7a2be", size=13),
            bgcolor="#18122b",
            actions=[
                ft.TextButton("Отмена", style=ft.ButtonStyle(color="#a7a2be"), on_click=cancel_clear),
                ft.ElevatedButton("Очистить", bgcolor="#ff1744", color="#ffffff", on_click=confirm_clear),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        page.overlay.append(confirm_dialog)
        confirm_dialog.open = True
        page.update()

    async def on_web_dialog_run(e):
        domain = (domain_field.value or "").strip()
        if not domain or "." not in domain:
            domain_field.error_text = "Введите корректный домен (например, google.com)"
            page.update()
            return
        domain_field.error_text = None
        close_web_dialog()
        await _run_web(domain)

    web_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Проверить сайт", color="#ffffff", weight=ft.FontWeight.BOLD),
        content=ft.Container(
            content=ft.Column([
                ft.Text("Введите домен или IP для аудита инфраструктуры:", color="#a7a2be", size=13),
                ft.Container(height=8),
                domain_field,
            ], tight=True),
            width=380,
        ),
        bgcolor="#18122b",
        actions=[
            ft.TextButton("Отмена", style=ft.ButtonStyle(color="#a7a2be"), on_click=close_web_dialog),
            ft.ElevatedButton(
                "Запустить",
                bgcolor="#b388ff",
                color="#0b0813",
                on_click=on_web_dialog_run,
            ),
        ],
        actions_alignment=ft.MainAxisAlignment.END,
    )
    page.overlay.append(web_dialog)

    # ── Кнопки сценариев ─────────────────────────────────────────────────────
    def on_project_click(e):
        project_path_field.value = ""
        project_path_field.error_text = None
        project_dialog.open = True
        page.update()

    def on_web_click(e):
        domain_field.value = ""
        domain_field.error_text = None
        web_dialog.open = True
        page.update()

    btn_project = _neon_button(
        "Проверить проект", ft.Icons.FOLDER_OPEN, "#b388ff", on_project_click
    )
    btn_web = _neon_button(
        "Проверить сайт", ft.Icons.LANGUAGE, "#00e5ff", on_web_click
    )

    # ── История запусков ─────────────────────────────────────────────────────
    history_column = ft.Column(controls=[], spacing=6)

    def _severity_color(score) -> str:
        if score is None:
            return "#a7a2be"
        if score >= 71:
            return "#00e676"
        if score >= 41:
            return "#ff9100"
        return "#ff1744"

    def _build_history():
        history_column.controls.clear()
        try:
            rows = database.get_recent_scans(limit=5)
        except Exception:
            rows = []

        if not rows:
            history_column.controls.append(
                ft.Text("История запусков пуста", size=13, color="#393053")
            )
            return

        for row in rows:
            # row: (id, scan_time, target, mode, score)
            scan_id, scan_time, target, mode, score = row
            icon = ft.Icons.FOLDER if mode == "project" else ft.Icons.LANGUAGE
            color = _severity_color(score)
            score_label = f"{score}/100" if score is not None else "—"

            history_column.controls.append(
                ft.Container(
                    content=ft.Row([
                        ft.Icon(icon, color="#a7a2be", size=16),
                        ft.Column([
                            ft.Text(target, size=13, color="#ffffff",
                                    overflow=ft.TextOverflow.ELLIPSIS, max_lines=1),
                            ft.Text(scan_time, size=11, color="#393053"),
                        ], spacing=0, expand=True),
                        ft.Text(score_label, size=14,
                                weight=ft.FontWeight.BOLD, color=color),
                    ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    padding=ft.Padding(left=14, top=10, right=14, bottom=10),
                    border_radius=10,
                    bgcolor="#130f22",
                    border=ft.Border(
                        top=ft.BorderSide(1, "#251b45"),
                        bottom=ft.BorderSide(1, "#251b45"),
                        left=ft.BorderSide(1, "#251b45"),
                        right=ft.BorderSide(1, "#251b45"),
                    ),
                )
            )

    _build_history()

    # ── Логика запусков ──────────────────────────────────────────────────────
    async def _run_project(path: str):
        btn_project.ink = False
        set_status("Сканируем файлы проекта...", busy=True)

        try:
            set_status("Анализируем секреты, конфиги и git-историю...", busy=True)
            raw = await api.run_project_audit(
                path=path,
                domain="",
                enrich=True,
            )

            result = {
                "mode": "project",
                "target": path,
                "dlp": raw.get("dlp", []) if isinstance(raw.get("dlp"), list) else [],
                "git": raw.get("git", {}) if isinstance(raw.get("git"), dict) else {},
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Считаем score
            score = _calc_project_score(result["dlp"])
            result["score"] = score

            # Сохраняем в историю
            try:
                database.save_scan_summary(
                    scan_time=result["scan_time"],
                    target=path,
                    mode="project",
                    score=score,
                )
            except Exception as db_ex:
                logger.warning("Не удалось сохранить историю: %s", db_ex)

            _build_history()
            clear_status()
            on_project_result(result)

        except Exception as ex:
            logger.error("Project audit error: %s", ex, exc_info=True)
            set_status(f"Ошибка: {ex}", busy=False)
            status_text.color = "#ff1744"
            page.update()

        btn_project.ink = True

    async def _run_web(domain: str):
        set_status(f"Запускаем OSINT для {domain}...", busy=True)

        try:
            set_status("Анализируем инфраструктуру...", busy=True)
            result = await api.run_combined_pipeline(domain)

            if "error" in result:
                raise RuntimeError(result["error"])

            result["mode"] = "web"
            result["target"] = domain
            result["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Score
            findings = result.get("findings", [])
            score = _calc_web_score(findings)
            result["score"] = score

            # Сохраняем в историю
            try:
                database.save_scan_summary(
                    scan_time=result["scan_time"],
                    target=domain,
                    mode="web",
                    score=score,
                )
            except Exception as db_ex:
                logger.warning("Не удалось сохранить историю: %s", db_ex)

            _build_history()
            clear_status()
            on_web_result(result)

        except Exception as ex:
            logger.error("Web pipeline error: %s", ex, exc_info=True)
            set_status(f"Ошибка: {ex}", busy=False)
            status_text.color = "#ff1744"
            page.update()

    # ── Расчёт Score ─────────────────────────────────────────────────────────
    def _calc_project_score(dlp_findings: list) -> int:
        score = 100
        for f in dlp_findings:
            if "error" in f:
                continue
            sev = (f.get("severity") or "").upper()
            if sev in ("CRITICAL", "HIGH"):
                score -= 10
            elif sev == "MEDIUM":
                score -= 4
            elif sev == "LOW":
                score -= 1
        return max(0, score)

    def _calc_web_score(findings: list) -> int:
        score = 100
        for f in findings:
            sev = (f.get("severity") or "").upper()
            if sev in ("CRITICAL", "HIGH"):
                score -= 10
            elif sev == "MEDIUM":
                score -= 4
            elif sev == "LOW":
                score -= 1
        return max(0, score)

    # ── Сборка страницы ──────────────────────────────────────────────────────
    return ft.Column(
        controls=[
            # Заголовок
            ft.Container(height=40),
            ft.Column([
                ft.Text(
                    "ПЕРИМЕТР",
                    size=42,
                    weight=ft.FontWeight.BOLD,
                    color="#ffffff",
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Text(
                    "Комплекс безопасности корпоративного уровня",
                    size=14,
                    color="#393053",
                    text_align=ft.TextAlign.CENTER,
                ),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),

            ft.Container(height=40),

            # Две кнопки
            ft.Row(
                controls=[btn_project, btn_web],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=30,
            ),

            ft.Container(height=16),

            # Подписи под кнопками
            ft.Row(
                controls=[
                    ft.Text("Секреты, конфиги, git-история", size=12,
                            color="#393053", text_align=ft.TextAlign.CENTER, width=260),
                    ft.Text("OSINT, порты, заголовки, TLS", size=12,
                            color="#393053", text_align=ft.TextAlign.CENTER, width=260),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=30,
            ),

            ft.Container(height=8),
            selected_path_text,
            status_row,

            ft.Container(height=30),
            ft.Divider(color="#251b45"),
            ft.Container(height=10),

            # История
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text("Последние проверки", size=14,
                                color="#a7a2be", weight=ft.FontWeight.W_500),
                        ft.IconButton(
                            icon=ft.Icons.DELETE_OUTLINE,
                            icon_color="#ff1744",
                            icon_size=18,
                            tooltip="Очистить всю историю",
                            on_click=on_clear_history_click
                        )
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    ft.Container(height=8),
                    history_column,
                ], spacing=0),
                padding=ft.Padding(left=60, top=0, right=60, bottom=0),
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        scroll=ft.ScrollMode.AUTO,
        expand=True,
    )
