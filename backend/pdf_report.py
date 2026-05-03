from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from io import BytesIO
import datetime

class PDFGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.custom_styles = {
            "Title": ParagraphStyle(
                'Title',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor("#1A5276"),
                alignment=1,
                spaceAfter=20
            ),
            "Header": ParagraphStyle(
                'Header',
                parent=self.styles['Heading2'],
                fontSize=18,
                textColor=colors.HexColor("#2E86C1"),
                spaceBefore=15,
                spaceAfter=10
            ),
            "Critical": ParagraphStyle('Critical', textColor=colors.red, fontWeight='bold'),
            "High": ParagraphStyle('High', textColor=colors.orange, fontWeight='bold'),
            "Medium": ParagraphStyle('Medium', textColor=colors.goldenrod, fontWeight='bold'),
            "Low": ParagraphStyle('Low', textColor=colors.green, fontWeight='bold'),
        }

    def generate(self, data):
        """Generate PDF report from scan data."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []

        # Title
        elements.append(Paragraph("OpenMythos Security Report", self.custom_styles["Title"]))
        elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]))
        elements.append(Spacer(1, 20))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", self.custom_styles["Header"]))
        risk_score = data.get("risk_score", 0)
        risk_level = data.get("risk_level", "Unknown").upper()
        
        summary_text = f"<b>Risk Score:</b> {risk_score}/100<br/>"
        summary_text += f"<b>Risk Level:</b> {risk_level}<br/>"
        summary_text += f"<b>Total Findings:</b> {len(data.get('vulnerabilities', []))}"
        
        elements.append(Paragraph(summary_text, self.styles["Normal"]))
        elements.append(Spacer(1, 15))

        # Severity Table
        summary = data.get("summary", {})
        table_data = [
            ["Severity", "Count"],
            ["Critical", summary.get("critical", 0)],
            ["High", summary.get("high", 0)],
            ["Medium", summary.get("medium", 0)],
            ["Low", summary.get("low", 0)]
        ]
        t = Table(table_data, colWidths=[100, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#D5D8DC")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 30))

        # Findings Table
        elements.append(Paragraph("Detailed Findings", self.custom_styles["Header"]))
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            elements.append(Paragraph("No vulnerabilities detected.", self.styles["Normal"]))
        else:
            findings_data = [["Type", "Severity", "File/Line", "Verdict"]]
            for v in vulnerabilities:
                findings_data.append([
                    v.get("type", "Unknown"),
                    v.get("severity", "low").upper(),
                    f"{v.get('filename', 'Unknown')}:{v.get('line', 'N/A')}",
                    "Vulnerable"
                ])
            
            ft = Table(findings_data, colWidths=[150, 100, 150, 100])
            ft.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2E86C1")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ]))
            elements.append(ft)

            # Detailed Descriptions
            elements.append(PageBreak())
            elements.append(Paragraph("Technical Details", self.custom_styles["Header"]))
            for idx, v in enumerate(vulnerabilities):
                elements.append(Paragraph(f"{idx+1}. {v.get('type')}", self.styles["Heading3"]))
                elements.append(Paragraph(f"<b>Severity:</b> {v.get('severity').upper()}", self.styles["Normal"]))
                elements.append(Paragraph(f"<b>Location:</b> {v.get('filename')}:{v.get('line')}", self.styles["Normal"]))
                elements.append(Spacer(1, 5))
                elements.append(Paragraph(f"<b>Description:</b> {v.get('description')}", self.styles["Normal"]))
                if v.get("exploitation"):
                    elements.append(Spacer(1, 5))
                    elements.append(Paragraph(f"<b>Exploitation:</b> <i>{v.get('exploitation')}</i>", self.styles["Normal"]))
                if v.get("fix"):
                    elements.append(Spacer(1, 5))
                    elements.append(Paragraph(f"<b>Recommended Fix:</b> {v.get('fix')}", self.styles["Normal"]))
                
                elements.append(Spacer(1, 15))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
