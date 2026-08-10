import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(output_dir="."):
    """
    Collects generated PNG files for a final PDF.
    """
    output_filename = os.path.join(output_dir, "pcap_analysis_report.pdf")

    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=22,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=6,
        alignment=0
    )
    
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#4a5568'),
        spaceAfter=15
    )
    
    section_title_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2d3748'),
        spaceBefore=10,
        spaceAfter=6
    )

    story = []

    story.append(Paragraph("Network Traffic Analysis Report", title_style))
    story.append(Paragraph("Automated PCAP Assessment", subtitle_style))
    story.append(Spacer(1, 10))

    charts = [
        ("top_talkers.png", "Top Communication Pairs", "Highlights the highest volume source-to-destination packet exchanges in the capture."),
        ("beacon_analysis.png", "Automated C2 Beaconing Detection", "Identifies time deltas indicating possible C2 activity."),
        ("top_destination_ports.png", "Destination Port Anomaly Distribution", "Highlights high destination port counts for further investigation."),
        ("top_domain_queries.png", "Top Requested DNS Domains", "Summarizes the most frequent domain name resolution requests."),
        ("rare_domain_queries.png", "Infrequent DNS Queries - Outliers", "Showcases tail-end distribution of rare domain lookups."),
        ("sni_domains.png", "Interesting TLS SNI Hostnames - Outliers", "Highlights encrypted destination hostnames extracted from TLS Client Hello handshakes."),
        ("interesting_uris.png", "Top Requested HTTP URIs", "Showcases most common plaintext web application paths requested."),
        ("rare_uris.png", "Infrequent HTTP Request URIs", "Identifies unique URIs for further analysis.")
    ]

    for filename, title, description in charts:
        if os.path.exists(filename):
            story.append(Paragraph(title, section_title_style))
            story.append(Paragraph(description, styles['Normal']))
            story.append(Spacer(1, 5))
            
            img = Image(filename, width=540, height=270)
            story.append(img)
            story.append(Spacer(1, 15))
            story.append(PageBreak())

    doc.build(story)
    print(f"[+] Successfully generated final PDF: {output_filename}")

if __name__ == "__main__":
    generate_pdf_report()