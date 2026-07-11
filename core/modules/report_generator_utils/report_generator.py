import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
import json
from pathlib import Path
from datetime import datetime

from database import DB_PATH

def register_fonts():
    """Кроссплатформенная регистрация шрифта DejaVuSans с поддержкой кириллицы."""
    try:
        font_path = Path(__file__).parent.parent.parent / "assets" / "DejaVuSans.ttf"
        if not font_path.exists():
            font_path = Path("assets/DejaVuSans.ttf").resolve()
            
        pdfmetrics.registerFont(TTFont('DejaVuSans', str(font_path)))
    except Exception as e:
        print(f"[ERROR] Не удалось загрузить кастомный шрифт: {e}")
        pdfmetrics.registerFont(TTFont('DejaVuSans', 'Helvetica'))

def make_recommendation_box(text, style):
    """Создает красивую зеленую плашку для рекомендаций."""
    p = Paragraph(text, style)
    t = Table([[p]], colWidths=[460])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#e8f5e9')),
        ('BORDER', (0,0), (-1,-1), 1, colors.HexColor('#2e7d32')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    return t

def add_page_number(canvas, doc):
    """Функция для отрисовки колонтитулов и номеров страниц."""
    canvas.saveState()
    canvas.setFont('DejaVuSans', 8)
    canvas.setFillColor(colors.HexColor('#a7a2be'))
    
    # Верхний колонтитул
    canvas.drawString(54, 750, "Комплекс безопасности корпоративного уровня «ПЕРИМЕТР»")
    canvas.setStrokeColor(colors.HexColor('#251b45'))
    canvas.setLineWidth(0.5)
    canvas.line(54, 742, 558, 742)
    
    # Нижний колонтитул
    page_num = canvas.getPageNumber()
    canvas.drawRightString(558, 40, f"Страница {page_num}")
    canvas.drawString(54, 40, f"Отчёт сгенерирован: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    canvas.restoreState()

def generate_pdf_report(filename="Perimeter_Security_Report.pdf", scan_id=None):
    """
    Генерирует профессиональный PDF отчёт.
    Если передан scan_id — детализирует конкретную проверку из scan_results (JSON).
    """
    register_fonts()
    
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        rightMargin=54, leftMargin=54,
        topMargin=72, bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Стили с поддержкой кириллицы
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Title'],
        fontName='DejaVuSans',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#18122b'),
        alignment=1, # Center
        spaceAfter=20
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='DejaVuSans',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#251b45'),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='DejaVuSans',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#333333'),
        spaceAfter=8
    )
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=body_style,
        leftIndent=15,
        bulletIndent=5,
        spaceAfter=4
    )

    story = []
    
    # --- ТИТУЛЬНЫЙ БЛОК ---
    story.append(Spacer(1, 20))
    story.append(Paragraph("Поиск утечек данных и внешний аудит", title_style))
    story.append(Paragraph("<b>Система:</b> АО Комплекс «Периметр»<br/>"
                           f"<b>Дата выгрузки:</b> {datetime.now().strftime('%d.%m.%Y %H:%M')}<br/>", body_style))
    story.append(Spacer(1, 15))
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Извлекаем данные по конкретному сканированию, если передан ID
    current_findings = []
    scan_meta = {}
    if scan_id:
        cursor.execute("SELECT target, mode, scan_time, score FROM scan_summaries WHERE id=?", (scan_id,))
        summary_row = cursor.fetchone()
        if summary_row:
            scan_meta = {"target": summary_row[0], "mode": summary_row[1], "time": summary_row[2], "score": summary_row[3]}
            
            cursor.execute("SELECT result_json FROM scan_results WHERE summary_id=?", (scan_id,))
            result_row = cursor.fetchone()
            if result_row:
                try:
                    res_data = json.loads(result_row[0])
                    # Вытаскиваем находки (поддерживаем как проекты, так и web)
                    if scan_meta["mode"] == "project":
                        current_findings = res_data.get("dlp", [])
                        git_data = res_data.get("git", {})
                        if isinstance(git_data, dict) and "findings" in git_data:
                            current_findings.extend(git_data["findings"])
                    else:
                        current_findings = res_data.get("findings", [])
                        # Добавляем порты
                        for port_info in res_data.get("network", []):
                            current_findings.append({
                                "severity": port_info.get("severity", "LOW"),
                                "title": f"Открытый порт: {port_info.get('port')} ({port_info.get('service')})",
                                "fix": "Закройте порт брандмауэром, если он не используется."
                            })
                except Exception as e:
                    print(f"[ERROR] Ошибка парсинга JSON для PDF: {e}")

    # --- РАЗДЕЛ 1. ТЕКУЩИЙ ЗАПУСК ---
    if scan_meta:
        story.append(Paragraph(f"1. Результаты текущего аудита: {scan_meta['target']}", h1_style))
        story.append(Paragraph(f"<b>Режим проверки:</b> {scan_meta['mode'].upper()}<br/>"
                               f"<b>Время запуска:</b> {scan_meta['time']}<br/>"
                               f"<b>Индекс безопасности (Score):</b> {scan_meta['score']}/100", body_style))
        story.append(Spacer(1, 10))
        
        if current_findings:
            table_data = [[
                Paragraph("<b>Уязвимость / Находка</b>", body_style),
                Paragraph("<b>Уровень</b>", body_style),
                Paragraph("<b>Рекомендация по устранению</b>", body_style)
            ]]
            
            for f in current_findings:
                sev = str(f.get("severity", "INFO")).upper()
                # Красивое цветовое кодирование уровней угроз
                if sev in ("CRITICAL", "HIGH"):
                    sev_color = "<font color='#ff1744'><b>CRITICAL</b></font>"
                elif sev == "MEDIUM":
                    sev_color = "<font color='#ff9100'><b>MEDIUM</b></font>"
                elif sev == "LOW":
                    sev_color = "<font color='#ffea00'><b>LOW</b></font>"
                else:
                    sev_color = f"<font color='#a7a2be'><b>{sev}</b></font>"
                    
                title = f.get("title") or f.get("type") or "Утечка данных"
                fix = f.get("fix") or f.get("recommendation") or "Требуется ручной анализ."
                
                table_data.append([
                    Paragraph(title, body_style),
                    Paragraph(sev_color, body_style),
                    Paragraph(fix, body_style)
                ])
                
            t = Table(table_data, colWidths=[160, 80, 220])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#18122b')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,0), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#251b45')),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("Находок или критических уязвимостей в этой проверке не обнаружено.", body_style))
        story.append(Spacer(1, 15))

    # --- РАЗДЕЛ 2. СВОДНАЯ ИСТОРИЯ СКАНИРОВАНИЙ ---
    story.append(Paragraph("2. История последних проверок (scan_summaries)", h1_style))
    cursor.execute("SELECT id, scan_time, target, mode, score FROM scan_summaries ORDER BY id DESC LIMIT 10")
    history_rows = cursor.fetchall()
    
    if history_rows:
        hist_data = [[
            Paragraph("<b>ID</b>", body_style),
            Paragraph("<b>Дата / Время</b>", body_style),
            Paragraph("<b>Объект</b>", body_style),
            Paragraph("<b>Режим</b>", body_style),
            Paragraph("<b>Индекс</b>", body_style)
        ]]
        for row in history_rows:
            hist_data.append([
                Paragraph(str(row[0]), body_style),
                Paragraph(str(row[1]), body_style),
                Paragraph(str(row[2]), body_style),
                Paragraph(str(row[3]), body_style),
                Paragraph(f"<b>{row[4]}/100</b>", body_style)
            ])
        t_hist = Table(hist_data, colWidths=[30, 120, 160, 90, 60])
        t_hist.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#251b45')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#a7a2be')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_hist)
    else:
        story.append(Paragraph("История проверок в базе данных пуста.", body_style))
        
    story.append(Spacer(1, 15))
    
    # --- РАЗДЕЛ 3. ОБЩИЕ РЕКОМЕНДАЦИИ И ЗАКЛЮЧЕНИЕ ---
    story.append(Paragraph("3. Комплексный план действий", h1_style))
    story.append(Paragraph("<b>[Приоритет 1]</b> Изолировать или удалить приватные ключи, токены и пароли из открытого Git-репозитория.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 2]</b> Ограничить доступ к неиспользуемым внешним сетевым портам с помощью файрвола.", bullet_style))
    story.append(Paragraph("<b>[Приоритет 3]</b> Исправить конфигурационные файлы и добавить недостающие политики безопасности.", bullet_style))
    
    story.append(Spacer(1, 10))
    story.append(make_recommendation_box(
        "<b>Внимание:</b> Рекомендуется проводить автоматизированный аудит безопасности "
        "периметра не реже одного раза в неделю, а также после каждого крупного релиза системы.",
        body_style
    ))
    
    conn.close()
    
    # Собираем документ с верхними/нижними колонтитулами
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)