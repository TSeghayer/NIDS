from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Spacer, SimpleDocTemplate, Table, TableStyle
from reportlab.lib.enums import TA_CENTER

class PDFGenerator:
    def __init__(self, filename):
        # Initialize PDFGenerator with a filename where the PDF document will be saved.
        self.filename = filename

    def generate_pdf(self, baseline_tp, anomaly_tp, baseline_max_band, baseline_min_band, anomaly_max_band, anomaly_min_band, new_ips=None):
        # Generates a PDF report detailing throughput analysis, band analysis, and new IP addresses detected.
        
        # Set up the document template and styles.
        doc = SimpleDocTemplate(self.filename, pagesize=letter)
        styles = getSampleStyleSheet()
        Story = []
        
        # Custom style for section titles, center-aligned.
        section_title_style = styles['Heading2']
        section_title_style.alignment = TA_CENTER
        
        # Report Header: Including title and creation time.
        Story.append(Paragraph("UWE Bristol", styles['Title']))
        Story.append(Paragraph("Taha Omar Seghayer", styles['Normal']))
        Story.append(Paragraph("NIDS Network Analysis Report", styles['Heading1']))
        created_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        Story.append(Paragraph(f"Report created on: {created_on}", styles['Normal']))
        Story.append(Spacer(1, 12))
        
        # Formatting the throughput and bandwidth values for presentation.
        # These are converted to floats and formatted to three decimal places.
        # Throughput Analysis Section.
        Story.append(Paragraph("Throughput", section_title_style))
        Story.append(Spacer(1, 12))
        Story.append(Paragraph(f"Baseline Throughput: {baseline_tp:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Throughput: {anomaly_tp:.3f} kbps", styles['Normal']))
        Story.append(Spacer(1, 12))
        
        # Bandwidth (Bands) Analysis Section.
        Story.append(Paragraph("Bands", section_title_style))
        Story.append(Spacer(1, 12))
        Story.append(Paragraph(f"Baseline Max Band: {baseline_max_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Baseline Min Band: {baseline_min_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Max Band: {anomaly_max_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Min Band: {anomaly_min_band:.3f} kbps", styles['Normal']))
        Story.append(Spacer(1, 12))
    
        # New IP Addresses Section: Lists newly detected IP addresses, if any.
        if new_ips:
            Story.append(Paragraph("New IP Addresses", section_title_style))
            for ip in new_ips:
                Story.append(Paragraph(ip, styles['Normal']))
            Story.append(Spacer(1, 12))
    
        # Client Information Section: Displays static client information.
        Story.append(Paragraph("Client Information", section_title_style))
        client_info = [['Name', 'CP-Lab Siemens'], ['Case Number', '000001']]
        client_table = Table(client_info)
        client_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('ALIGN', (0,0), (-1,-1), 'LEFT')]))
        Story.append(client_table)
        
        # Build and save the PDF document with the compiled content.
        doc.build(Story)
"""
The PDFGenerator class serves to create detailed PDF reports for network traffic analysis. 
It compiles various sections including throughput analysis, band analysis, and newly detected IP addresses into a structured document. 
This report aids in documenting and presenting the findings of the network analysis in a professional and accessible format.
"""