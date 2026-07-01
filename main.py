import flet as ft
import asyncio
from ui.pages.dashboard import dashboard_page
from ui.pages.dlp import dlp_page
from ui.pages.network import network_page
from ui.pages.osint import osint_page
from ui.pages.reports import reports_page

async def main(page: ft.Page):
    page.title = "Комплекс Периметр"
    page.bgcolor = "#0b0813" 

    # -----------------------------------------------------------------------
    # ИНИЦИАЛИЗАЦИЯ ДИСКЛЕЙМЕРА
    # -----------------------------------------------------------------------
    def close_disclaimer(e):
        disclaimer_dialog.open = False
        page.update()

    disclaimer_dialog = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Icon(ft.Icons.GAVEL, color="#ff9100"),
            ft.Text("Уведомление об ответственности", size=18, weight=ft.FontWeight.BOLD)
        ], spacing=10),
        content=ft.Container(
            content=ft.Text(
                "ВНИМАНИЕ: ИСКЛЮЧИТЕЛЬНО ДЛЯ ЛЕГАЛЬНОГО АУДИТА\n\n"
                "ПО «Периметр» разработано исключительно для тестирования на проникновение, "
                "легального сбора информации (OSINT) и предотвращения утечек данных (DLP). "
                "Любое сканирование сторонних ресурсов без предварительного согласия их "
                "владельцев является незаконным. Разработчики не несут ответственности за "
                "неправомерные действия пользователей, повлекшие за собой нарушение работы сетей "
                "или модификацию данных (ст. 272-274 УК РФ).\n\n"
                "Вы используете данный инструмент на свой собственный страх и риск.",
                color="#a7a2be",
                size=13,
                text_align=ft.TextAlign.JUSTIFY
            ),
            width=450
        ),
        actions=[
            ft.TextButton("Принимаю условия", style=ft.ButtonStyle(color="#00e676"), on_click=close_disclaimer)
        ],
        actions_alignment=ft.MainAxisAlignment.END,
        bgcolor="#18122b"
    )

    # ВАЖНО: Сразу регистрируем диалог в overlay приложения, чтобы Flet знал о его существовании
    page.overlay.append(disclaimer_dialog)

    # Инициализируем страницы (теперь они не будут сбрасывать состояние)
    pages_store = {
        0: dashboard_page(page),
        1: dlp_page(page),
        2: network_page(page),
        3: osint_page(page),
        4: reports_page(page)
    }

    main_content = ft.Container(
        content=pages_store[0],  
        expand=True,
        padding=25,
        bgcolor="#0b0813"
    )

    async def route_change(e):
        idx = e.control.selected_index
        # Принудительно обновляем Dashboard при переходе на него, чтобы пересчитать индексы
        if idx == 0:
            pages_store[0] = dashboard_page(page)
        main_content.content = pages_store[idx]
        page.update()

    sidebar_rail = ft.NavigationRail(    
        destinations=[
            ft.NavigationRailDestination(icon=ft.Icons.DASHBOARD, label="Главная"),
            ft.NavigationRailDestination(icon=ft.Icons.LOCK_RESET, label="DLP"), 
            ft.NavigationRailDestination(icon=ft.Icons.TERMINAL, label="NETWORK"),
            ft.NavigationRailDestination(icon=ft.Icons.SEARCH, label="OSINT"),
            ft.NavigationRailDestination(icon=ft.Icons.ASSIGNMENT, label="REPORTS"),
        ],
        on_change=route_change,
        bgcolor="#130f22", 
    )

    sidebar = ft.Container(
        content=sidebar_rail,
        bgcolor="#130f22",
        padding=10,
        border_radius=12,
        border=ft.Border(
            top=ft.BorderSide(1, "#251b45"),
            bottom=ft.BorderSide(1, "#251b45"),
            left=ft.BorderSide(1, "#251b45"),
            right=ft.BorderSide(1, "#251b45")
        )
    )

    # Отрисовываем основную сетку интерфейса
    page.add(
        ft.Row(
            controls=[sidebar, main_content],
            expand=True,
            spacing=10
        )
    )

    # Функция таска: плавно и гарантированно открывает окно поверх готового UI
    async def show_disclaimer_task():
        await asyncio.sleep(0.3)  # Микропауза, пока собирается главное окно
        disclaimer_dialog.open = True
        page.update()

    # Запускаем таск
    page.run_task(show_disclaimer_task)

ft.app(target=main)