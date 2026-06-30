import flet as ft
from ui.pages import dashboard_page, dlp_page, osint_page, reports_page, network_page

def main(page: ft.Page):
    page.title = "Комплекс Периметр"
    page.bgcolor = "#0b0813" 

    main_content = ft.Container(
        content=dashboard_page(page),
        expand=True,
        padding=25,
        bgcolor="#0b0813"
    )

    def route_change(e):
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
        border=ft.Border.all(1, "#251b45") 
    )

    page.add(
        ft.Row(
            controls=[
                sidebar,
                main_content,
            ],
            expand=True,
            spacing=10
        )
    )

ft.app(target=main)