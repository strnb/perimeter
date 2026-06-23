import flet as ft 

def reports_page(page: ft.page):
    return ft.Column(
        controls=[
            ft.Text("Reports", style=ft.TextThemeStyle.HEADLINE_MEDIUM),

        ],
        expand = True
    )