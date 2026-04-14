from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.colors import HexColor
from datetime import datetime

def create_pdf(content: str):
    filename = f"Cyber_Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        rightMargin=72, leftMargin=72,
        topMargin=72, bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'Title', parent=styles['Heading1'],
        fontSize=26, textColor=HexColor('#1a1a1a'),
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
    elements.append(Paragraph("Cyber Threat Intelligence Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M')}", styles['Normal']))
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
            elements.append(Paragraph(line, body_style))
    
    doc.build(elements)
    print(f"✅ PDF Report Created: {filename}")
    return filename