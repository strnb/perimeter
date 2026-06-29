import flet as ft

class ThreatCounter(ft.Row):
    def __init__(self, initial_data=None):
        if initial_data is None:
            initial_data = {"critical": 0, "medium": 0, "low": 0}

        # Твои рабочие поля для цифр
        self.crit_text = ft.Text(value=str(initial_data["critical"]), size=24, weight=ft.FontWeight.BOLD)
        self.med_text = ft.Text(value=str(initial_data["medium"]), size=24, weight=ft.FontWeight.BOLD)
        self.low_text = ft.Text(value=str(initial_data["low"]), size=24, weight=ft.FontWeight.BOLD)

        # Старый рабочий вызов super() без аргументов наружу
        super().__init__()

        # Твой старый рабочий способ наполнения controls, только исправили опечатку control -> controls
        self.controls = [
            self._create_badge("Критических", self.crit_text, ft.Colors.RED_ACCENT_700),
            self._create_badge("Средних", self.med_text, ft.Colors.ORANGE_ACCENT_400),
            self._create_badge("Низких", self.low_text, ft.Colors.YELLOW_ACCENT_400),
        ]
        self.spacing = 15
        self.alignment = ft.MainAxisAlignment.START
        self.vertical_alignment = ft.CrossAxisAlignment.CENTER

    def _create_badge(self, label, text_obj, color):
        return ft.Container(
            content=ft.Column(
                controls=[ # Здесь исправили control на controls
                    ft.Text(label, size=12, color=ft.Colors.GREY_400, weight=ft.FontWeight.W_500),
                    text_obj
                ],
                spacing=2
            ),
            bgcolor=ft.Colors.ON_SURFACE_VARIANT,
            padding=15,
            border_radius=8,
            width=140,
            border=ft.Border.all(1, color)
        )
    
    # Метод для Дамира с правильными именами переменных (med_text вместо mid_text)
    def refresh_counters(self, data):
        self.crit_text.value = str(data.get("critical", 0))
        self.med_text.value = str(data.get("medium", 0))
        self.low_text.value = str(data.get("low", 0))
        self.update()