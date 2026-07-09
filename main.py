import flet as ft
import asyncio
import database
from ui.pages.home import home_page
from ui.pages.results import results_page


async def main(page: ft.Page):
    page.title = "Периметр — Security Audit"
    page.bgcolor = "#0b0813"
    page.padding = 0

    database.init_db()

    # ──────────────────────────────────────────────
    # Роутер: единственный контейнер контента
    # ──────────────────────────────────────────────
    content_area = ft.Container(expand=True, bgcolor="#0b0813")

    def navigate_to_results(audit_result: dict, mode: str):
        """Переход на экран результатов."""
        content_area.content = results_page(
            page=page,
            audit_result=audit_result,
            mode=mode,
            on_back=navigate_home,
        )
        page.update()

    def navigate_home():
        """Возврат на главный экран."""
        content_area.content = home_page(
            page=page,
            on_project_result=lambda r: navigate_to_results(r, "project"),
            on_web_result=lambda r: navigate_to_results(r, "web"),
        )
        page.update()

    # Стартовый экран
    navigate_home()

    page.add(content_area)

    # ── Дисклеймер ──────────────────────────────
    def close_disclaimer(e):
        disclaimer_dialog.open = False
        page.update()

    disclaimer_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Icon(ft.Icons.GAVEL, color="#ff9100"),
            ft.Text("Уведомление об ответственности", size=18, weight=ft.FontWeight.BOLD, color="#ffffff"),
        ], spacing=10),
        content=ft.Container(
            content=ft.Text(
                "ВНИМАНИЕ: ИСКЛЮЧИТЕЛЬНО ДЛЯ ЛЕГАЛЬНОГО АУДИТА\n\n"
                "ПО «Периметр» разработано для тестирования на проникновение, "
                "легального сбора информации (OSINT) и предотвращения утечек данных (DLP). "
                "Сканирование сторонних ресурсов без согласия владельцев незаконно. "
                "Разработчики не несут ответственности за неправомерные действия "
                "(ст. 272–274 УК РФ).\n\nВы используете инструмент на свой страх и риск.",
                color="#a7a2be",
                size=13,
                text_align=ft.TextAlign.JUSTIFY,
            ),
            width=450,
        ),
        actions=[
            ft.TextButton(
                "Принимаю условия",
                style=ft.ButtonStyle(color="#00e676"),
                on_click=close_disclaimer,
            )
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        bgcolor="#18122b",
    )

    page.overlay.append(disclaimer_dialog)

    async def show_disclaimer():
        await asyncio.sleep(0.3)
        disclaimer_dialog.open = True
        page.update()

    page.run_task(show_disclaimer)


ft.app(target=main)
