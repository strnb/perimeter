import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os

from database import DB_PATH

def register_fonts():
    """Регистрация шрифта для поддержки кириллицы."""
    try:
        pdfmetrics.registerFont(TTFont('Arial', 'C:\\Windows\\Fonts\\arial.ttf'))
    except:
        try:
            pdfmetrics.registerFont(TTFont('Arial', 'arial.ttf'))
        except:
            pass

def generate_pdf_report(target_pdf_path):
    register_fonts()
    
    doc = SimpleDocTemplate(target_pdf_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle', fontName='Arial', fontSize=22, leading=26, textColor=colors.HexColor("#130f22"), spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'H2Style', fontName='Arial', fontSize=14, leading=18, textColor=colors.HexColor("#251b45"), spaceBefore=12, spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyStyle', fontName='Arial', fontSize=10, leading=14, textColor=colors.HexColor("#333333")
    )

    # Шапка
    story.append(Paragraph("КОМПЛЕКС «ПЕРИМЕТР»", title_style))
    story.append(Paragraph("Сводный отчет по результатам аудита информационной безопасности", body_style))
    story.append(Spacer(1, 15))
    
    # Подключаемся к нашей единой БД
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # --- 1. СЕКЦИЯ OSINT 
    story.append(Paragraph("1. Результаты внешней разведки (OSINT)", h2_style))
    try:
        cursor.execute("SELECT scan_time, target_domain, registrar, subdomains_count FROM osint_results ORDER BY id DESC LIMIT 5")
        osint_data = cursor.fetchall()
    except sqlite3.OperationalError:
        osint_data = []

    if osint_data:
        table_data = [["Время", "Домен", "Регистратор", "Поддомены"]]
        for row in osint_data:
            table_data.append([str(row[0]), str(row[1]), str(row[2]), str(row[3])])
        
        t = Table(table_data, colWidths=[110, 140, 140, 70])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#130f22")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,-1), 'Arial'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Данные о внешнем сканировании отсутствуют (база пуста).", body_style))
        
    story.append(Spacer(1, 15))

    # --- 2. СЕКЦИЯ DLP ---
    story.append(Paragraph("2. Результаты анализа утечек данных (DLP)", h2_style))
    try:
        cursor.execute("SELECT scan_time, checked_path, critical_count, medium_count, low_count FROM dlp_results ORDER BY id DESC LIMIT 5")
        dlp_data = cursor.fetchall()
    except sqlite3.OperationalError:
        dlp_data = []
    
    if dlp_data:
        table_data = [["Время", "Путь", "Крит.", "Средн.", "Низк."]]
        for row in dlp_data:
            table_data.append([str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4])])
            
        t = Table(table_data, colWidths=[110, 210, 50, 50, 50])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#251b45")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('FONTNAME', (0,0), (-1,-1), 'Arial'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e0e0e0")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("Данные локального DLP-мониторинга отсутствуют (база пуста).", body_style))

    conn.close()
    
    # Сборка
    doc.build(story)