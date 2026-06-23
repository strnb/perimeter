import flet as ft

def dashboard_page(page: ft.page):
    return ft.Column(
        controls=[
            ft.Text("Dashboard", style=ft.TextThemeStyle.HEADLINE_MEDIUM),

        ],
        expand = True
    )