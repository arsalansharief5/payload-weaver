from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from datetime import datetime
from termcolor import colored
from textwrap import wrap
import os

def generate_report(crawl_data, target_url, perform_attack, vulnerabilities, scan_duration, 
                    start_time, high_count, medium_count, low_count, attack_type):
    """
    Generate a detailed PDF report based on the scan results with headings, margins, padding,
    and table styling.

    Parameters:
    - crawl_data (dict): The data returned from crawling the website.
    - target_url (str): The URL of the target website.
    - perform_attack (str): Whether an attack was performed.
    - vulnerabilities (list): List of detected vulnerabilities.
    - scan_duration (float): The total scan duration in seconds.
    - start_time (str): The start time of the scan.
    - high_count (int): Count of high severity vulnerabilities.
    - medium_count (int): Count of medium severity vulnerabilities.
    - low_count (int): Count of low severity vulnerabilities.
    - attack_type (str): The type of attack performed (e.g., XSS, SQL Injection, etc.).

    Returns:
    None
    """
    reports_dir = os.path.join("static", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    # Get current timestamp for unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.pdf"
    file_path = os.path.join(reports_dir, filename)
    
    doc = SimpleDocTemplate(file_path, pagesize=letter, leftMargin=72, rightMargin=72, topMargin=72, bottomMargin=72)

    # Styles for the report
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    heading_style = styles['Heading2']
    normal_style = styles['Normal']

    # Content to be added to the PDF
    content = []

    # Add a title to the PDF
    content.append(Paragraph("<b>Website Security Scan Report</b>", title_style))
    content.append(Paragraph(f"Generated on: {start_time}", normal_style))

    # Add crawling information (number of crawled URLs and the list of URLs)
    content.append(Paragraph("<b>Crawling Information</b>", heading_style))
    crawl_info_data = [
        ["Number of Crawled URLs", str(crawl_data["num_crawls"]), ""],
        ["Crawled URLs", "", ""]
    ]
    
    # Prepare the table for crawled URLs with one URL per row
    crawl_urls_data = [["Crawled URL"]]
    for url in crawl_data["crawled_urls"]:
        crawl_urls_data.append([Paragraph(url, normal_style)])

    # Create the table for crawled URLs with wrapped text
    crawl_urls_table = Table(crawl_urls_data, colWidths=[450])
    crawl_urls_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 0), (-1, -1), True),  # Ensures text wraps within the table
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    content.append(crawl_urls_table)

    # Add scan information
    content.append(Paragraph("<b>Scan Information</b>", heading_style))
    scan_info_data = [
        ["Target URL", target_url, ""],
        ["Attack Type", attack_type, ""],
        ["Scan Started At", start_time, ""],
        ["Scan Duration", f"{scan_duration} seconds", ""]
    ]
    scan_info_table = Table(scan_info_data, colWidths=[150, 250, 50])
    scan_info_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    content.append(scan_info_table)

    # Add vulnerabilities summary
    content.append(Paragraph("<b>Vulnerabilities Found</b>", heading_style))
    vulnerabilities_data = [
        ["High Severity", high_count, ""],
        ["Medium Severity", medium_count, ""],
        ["Low Severity", low_count, ""]
    ]
    vulnerabilities_table = Table(vulnerabilities_data, colWidths=[150, 100, 50])
    vulnerabilities_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    content.append(vulnerabilities_table)

    # Add vulnerability details table
    content.append(Paragraph("<b>Vulnerability Details</b>", heading_style))

    # Prepare the data for the vulnerability details table
    vulnerability_details_data = [
        ["URL", "Risk", "Description"]
    ]
    for vuln in vulnerabilities:
        vulnerability_details_data.append([vuln['url'], vuln['risk'], vuln['description']])

    # Define custom column widths
    col_widths = [150, 100, 250]  # URL, Risk, Description widths

    # Wrap the "URL" and "Description" fields to ensure they don't overflow
    wrapped_vulnerabilities_data = []
    for row in vulnerability_details_data:
        wrapped_row = [
            Paragraph(row[0], normal_style),  # URL
            Paragraph(row[1], normal_style),  # Risk
            Paragraph(row[2], normal_style),  # Description
        ]
        wrapped_vulnerabilities_data.append(wrapped_row)

    # Create the table for vulnerabilities with wrapped text
    vulnerability_table = Table(wrapped_vulnerabilities_data, colWidths=col_widths)
    vulnerability_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'LEFT'),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.red),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.blue),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 0), (-1, -1), True),  # Enables word wrapping
    ]))
    content.append(vulnerability_table)

    # Build the PDF document
    doc.build(content)


    print(f"PDF report generated: {file_path}")

    return file_path


def create_wrapped_cell(text, width=60):
    """Helper function to wrap text in table cells"""
    if not isinstance(text, str):
        text = str(text)
    wrapped_text = "\n".join(wrap(text, width))
    return Paragraph(wrapped_text, ParagraphStyle('Normal'))

def generate_combined_report(combined_results):
    """Generates a combined PDF report for multiple URLs with enhanced formatting"""
    report_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"security_scan_report_{report_time}.pdf"
    
    doc = SimpleDocTemplate(
        report_filename,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    heading2_style = styles['Heading2']
    normal_style = styles['Normal']
    
    vuln_style = ParagraphStyle(
        'VulnerabilityStyle',
        parent=styles['Normal'],
        spaceAfter=10,
        leftIndent=20
    )
    
    elements = []
    
    # Title and Executive Summary sections
    elements.append(Paragraph("Security Scan Combined Report", title_style))
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("Executive Summary", heading2_style))
    elements.append(Spacer(1, 10))
    
    summary_data = [
        ["Scan Start Time:", combined_results['scan_start_time']],
        ["Scan End Time:", combined_results['scan_end_time']],
        ["Total Scan Duration:", f"{round(combined_results['total_scan_duration'], 2)} seconds"],
        ["Total URLs Scanned:", str(len(combined_results['urls_scanned']))],
        ["High Severity Vulnerabilities:", str(combined_results['total_vulnerabilities']['High'])],
        ["Medium Severity Vulnerabilities:", str(combined_results['total_vulnerabilities']['Medium'])],
        ["Low Severity Vulnerabilities:", str(combined_results['total_vulnerabilities']['Low'])]
    ]
    
    wrapped_summary_data = [[create_wrapped_cell(cell) for cell in row] for row in summary_data]
    summary_table = Table(wrapped_summary_data, colWidths=[2*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("Detailed Scan Results", heading2_style))
    elements.append(Spacer(1, 20))
    
    for url_result in combined_results['detailed_results']:
        elements.append(Paragraph(f"Target URL: {url_result['url']}", heading2_style))
        elements.append(Spacer(1, 10))
        
        # URL Details Table
        url_details = [
            ["Scan Duration:", f"{url_result['scan_duration']} seconds"],
            ["URLs Crawled:", str(url_result['crawl_data']['num_crawls'])],
            ["Attack Performed:", str(url_result['attack_performed'])],
            ["Attack Type:", url_result['attack_type']],
            ["High Severity Findings:", str(url_result['vulnerability_counts']['High'])],
            ["Medium Severity Findings:", str(url_result['vulnerability_counts']['Medium'])],
            ["Low Severity Findings:", str(url_result['vulnerability_counts']['Low'])]
        ]
        
        wrapped_url_details = [[create_wrapped_cell(cell) for cell in row] for row in url_details]
        url_table = Table(wrapped_url_details, colWidths=[2*inch, 4*inch])
        url_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(url_table)
        elements.append(Spacer(1, 20))
        
        # Crawled URLs section - simplified to just show the list
        if 'crawled_urls' in url_result['crawl_data']:
            elements.append(Paragraph("Crawled URLs:", heading2_style))
            elements.append(Spacer(1, 10))
            
            crawled_urls_data = [["#", "URL"]]
            for idx, crawled_url in enumerate(url_result['crawl_data']['crawled_urls'], 1):
                crawled_urls_data.append([str(idx), crawled_url])
            
            wrapped_crawled_data = [[create_wrapped_cell(cell, width=40) for cell in row] for row in crawled_urls_data]
            crawled_table = Table(wrapped_crawled_data, colWidths=[0.5*inch, 5.5*inch])
            crawled_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(crawled_table)
            elements.append(Spacer(1, 20))
        
        # Vulnerabilities Details
        if url_result['vulnerabilities']:
            elements.append(Paragraph("Detected Vulnerabilities:", heading2_style))
            elements.append(Spacer(1, 10))
            
            for vuln in url_result['vulnerabilities']:
                if vuln['risk'] == 'High':
                    bg_color = colors.mistyrose
                elif vuln['risk'] == 'Medium':
                    bg_color = colors.lightgoldenrodyellow
                else:
                    bg_color = colors.lightgreen
                
                vuln_data = [
                    ["Name:", vuln['name']],
                    ["Risk Level:", vuln['risk']],
                    ["Description:", vuln['description']],
                    ["Solution:", vuln['solution']],
                    ["Affected URL:", vuln.get('affected_url', 'N/A')]
                ]
                
                wrapped_vuln_data = [[create_wrapped_cell(cell, width=50) for cell in row] for row in vuln_data]
                vuln_table = Table(wrapped_vuln_data, colWidths=[1.5*inch, 4.5*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('BACKGROUND', (0, 1), (1, 1), bg_color)
                ]))
                
                elements.append(vuln_table)
                elements.append(Spacer(1, 15))
        
        elements.append(PageBreak())
    
    # Build the PDF
    doc.build(elements)
    print(colored(f"\nCombined PDF report generated: {report_filename}", "green"))

    return report_filename