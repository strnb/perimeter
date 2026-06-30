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

    main_content = ft.Container(
        content=dashboard_page(page),
        expand=True,
        padding=25,
        bgcolor="#0b0813"
    )

    async def route_change(e):
        if e.control.selected_index == 0:
            main_content.content = dashboard_page(page)
        elif e.control.selected_index == 1:
            main_content.content = dlp_page(page)
        elif e.control.selected_index == 2:
            main_content.content = network_page(page)
        elif e.control.selected_index == 3:
            main_content.content = osint_page(page)
        elif e.control.selected_index == 4:
            main_content.content = reports_page(page)
        page.update() # ИСПРАВЛЕНО: просто update() вместо update_async()

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
        border=ft.Border.all(1, "#251b45")
    )

    # ИСПРАВЛЕНО: просто add() вместо add_async()
    page.add(
        ft.Row(
            controls=[sidebar, main_content],
            expand=True,
            spacing=10
        )
    )

ft.app(target=main)