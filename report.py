from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor
from datetime import datetime

def create_pdf(content: str, report_type: str = None):  # Added report_type parameter with default
    filename = f"Cyber_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    # Customize title based on report_type
    if report_type == "urgent":
        title_text = "URGENT - Cyber Threat Intelligence Report"
        title_color = HexColor('#c0392b')  # Red for urgent
    elif report_type == "priority":
        title_text = "PRIORITY - Cyber Threat Intelligence Report"
        title_color = HexColor('#e67e22')  # Orange for priority
    else:
        title_text = "Cyber Threat Intelligence Report"
        title_color = HexColor('#1a1a1a')  # Default dark color
    
    title_style = ParagraphStyle(
        'Title', parent=styles['Heading1'],
        fontSize=26, textColor=title_color,
        spaceAfter=30, alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'Heading', parent=styles['Heading2'],
        fontSize=16, textColor=HexColor('#2c3e50'),
        spaceAfter=12, spaceBefore=18,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'Body', parent=styles['Normal'],
        fontSize=11, textColor=HexColor('#333333'),
        spaceAfter=10, leading=14
    )
    
    elements = []
    elements.append(Paragraph(title_text, title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", styles['Normal']))
    
    # Add urgency note if applicable
    if report_type == "urgent":
        urgent_style = ParagraphStyle(
            'UrgentNote', parent=styles['Normal'],
            fontSize=12, textColor=HexColor('#c0392b'),
            spaceAfter=15, alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        elements.append(Paragraph("⚠️ URGENT: Immediate Action Required ⚠️", urgent_style))
    elif report_type == "priority":
        priority_style = ParagraphStyle(
            'PriorityNote', parent=styles['Normal'],
            fontSize=12, textColor=HexColor('#e67e22'),
            spaceAfter=15, alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        elements.append(Paragraph("Priority: Action Recommended Within 24 Hours", priority_style))
    
    elements.append(Spacer(1, 30))
    
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 8))
            continue
        if line.startswith('###'):
            elements.append(Paragraph(line[3:].strip(), styles['Heading3']))
        elif line.startswith('##'):
            elements.append(Paragraph(line[2:].strip(), heading_style))
        elif line.startswith('#'):
            elements.append(Paragraph(line[1:].strip(), title_style))
        elif line.startswith('- ') or line.startswith('* '):
            elements.append(Paragraph(f"• {line[2:].strip()}", body_style))
        else:
            # Escape HTML characters for ReportLab
            safe_line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            elements.append(Paragraph(safe_line, body_style))
    
    doc.build(elements)
    
    urgency_indicator = f" ({report_type.upper()})" if report_type else ""
    print(f"[OK] PDF Report Created{urgency_indicator}: {filename}")
    return filename
