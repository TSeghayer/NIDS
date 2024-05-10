from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph, Spacer, SimpleDocTemplate, Table, TableStyle
from reportlab.lib.enums import TA_CENTER

class PDFGenerator:
    def __init__(self, filename):
        """
        Initializes the PDFGenerator class which is responsible for creating PDF documents.
        Parameters:
            filename (str): The name of the file where the PDF will be saved.
        """
        self.filename = filename

    def generate_pdf(self, baseline_tp, anomaly_tp, baseline_max_band, baseline_min_band, anomaly_max_band, anomaly_min_band, new_ips=None):
        """
        Generates a PDF report with detailed analyses including throughput, bandwidth, and new IP detections.
        Parameters:
            baseline_tp (float): Baseline throughput in kbps.
            anomaly_tp (float): Throughput observed during the anomaly in kbps.
            baseline_max_band (float): Maximum bandwidth during the baseline measurement in kbps.
            baseline_min_band (float): Minimum bandwidth during the baseline measurement in kbps.
            anomaly_max_band (float): Maximum bandwidth observed during the anomaly in kbps.
            anomaly_min_band (float): Minimum bandwidth observed during the anomaly in kbps.
            new_ips (list, optional): List of new IP addresses detected.
        """
        # Set up the document template using letter page size and the filename specified in the constructor.
        doc = SimpleDocTemplate(self.filename, pagesize=letter)
        styles = getSampleStyleSheet()  # Fetches a set of predefined styles for formatting the PDF.
        Story = []  # This list will hold the components of the PDF to be built.

        # Define a custom style for section titles to be center-aligned.
        section_title_style = styles['Heading2']
        section_title_style.alignment = TA_CENTER

        # Report Header: Includes the document title and metadata such as creation time.
        Story.append(Paragraph("UWE Bristol", styles['Title']))
        Story.append(Paragraph("Taha Omar Seghayer", styles['Normal']))
        Story.append(Paragraph("NIDS Network Analysis Report", styles['Heading1']))
        created_on = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        Story.append(Paragraph(f"Report created on: {created_on}", styles['Normal']))
        Story.append(Spacer(1, 12))  # Adds space for better layout.

        # Throughput Analysis Section: Presents throughput data formatted to three decimal places.
        Story.append(Paragraph("Throughput", section_title_style))
        Story.append(Spacer(1, 12))
        Story.append(Paragraph(f"Baseline Throughput: {baseline_tp:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Throughput: {anomaly_tp:.3f} kbps", styles['Normal']))
        Story.append(Spacer(1, 12))

        # Bandwidth Analysis Section: Details the max and min bandwidth used during baseline and anomaly periods.
        Story.append(Paragraph("Bands", section_title_style))
        Story.append(Spacer(1, 12))
        Story.append(Paragraph(f"Baseline Max Band: {baseline_max_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Baseline Min Band: {baseline_min_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Max Band: {anomaly_max_band:.3f} kbps", styles['Normal']))
        Story.append(Paragraph(f"Anomaly Min Band: {anomaly_min_band:.3f} kbps", styles['Normal']))
        Story.append(Spacer(1, 12))

        # New IP Addresses Section: Lists new IP addresses detected, if any are provided.
        if new_ips:
            Story.append(Paragraph("New IP Addresses", section_title_style))
            for ip in new_ips:
                Story.append(Paragraph(ip, styles['Normal']))
            Story.append(Spacer(1, 12))

        # Client Information Section: Demonstrates how static data can be displayed in table format.
        Story.append(Paragraph("Client Information", section_title_style))
        client_info = [['Name', 'CP-Lab Siemens'], ['Case Number', '000001']]
        client_table = Table(client_info)  # Creates a table with client info.
        client_table.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 1, colors.black),  # Adds grid lines to the table.
            ('BACKGROUND', (0,0), (-1,0), colors.grey),  # Sets the background color for the header row.
            ('ALIGN', (0,0), (-1,-1), 'LEFT')]))  # Aligns text to the left.
        Story.append(client_table)

        # Finalizing the document: This compiles all the components added to 'Story' and saves the PDF.
        doc.build(Story)

"""
The PDFGenerator class serves to create detailed PDF reports for network traffic analysis. 
It compiles various sections including throughput analysis, band analysis, and newly detected IP addresses into a structured document. 
This report aids in documenting and presenting the findings of the network analysis in a professional and accessible format.
"""